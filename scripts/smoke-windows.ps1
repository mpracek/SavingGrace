# Windows smoke test for SavingGrace (Phase 3: service + DNS enforcement).
# Designed for CI (windows-latest runs elevated). It CHANGES the machine's DNS and firewall,
# so it always cleans up in `finally`, even when an assertion fails.
param([string]$Exe = "target\release\savinggrace-agent.exe")
$ErrorActionPreference = "Stop"
$exe = (Resolve-Path $Exe).Path
$data = Join-Path $env:ProgramData "SavingGrace"
$verified = New-Object System.Collections.Generic.List[string]
$skipped = New-Object System.Collections.Generic.List[string]

function Assert($cond, $msg) { if (-not $cond) { throw "ASSERTION FAILED: $msg" } }

function Get-AgentStatus {
  for ($i = 0; $i -lt 20; $i++) {
    try { return (& $exe status | ConvertFrom-Json) } catch { Start-Sleep -Milliseconds 500 }
  }
  throw "agent did not answer over the named pipe"
}

function Test-Resolves($name, $server) {
  Clear-DnsClientCache
  try {
    if ($server) { $null = Resolve-DnsName $name -Server $server -Type A -DnsOnly -ErrorAction Stop }
    else         { $null = Resolve-DnsName $name -Type A -DnsOnly -ErrorAction Stop }
    return $true
  } catch { return $false }
}

function Test-TcpConnect($ip, $port, $ms = 3000) {
  $c = New-Object System.Net.Sockets.TcpClient
  try {
    $t = $c.ConnectAsync($ip, $port)
    return ($t.Wait($ms) -and $c.Connected)
  } catch { return $false } finally { $c.Dispose() }
}

function Get-BrowserDump($exePath, $url) {
  $profile = Join-Path $env:TEMP ("sg-profile-" + [guid]::NewGuid())
  try {
    $p = Start-Process -FilePath $exePath -ArgumentList @("--headless=new", "--disable-gpu", "--no-first-run", "--user-data-dir=$profile", "--virtual-time-budget=15000", "--dump-dom", $url) `
         -RedirectStandardOutput "$profile.out" -RedirectStandardError "$profile.err" -PassThru -Wait -WindowStyle Hidden
    return (Get-Content "$profile.out" -Raw -ErrorAction SilentlyContinue) + (Get-Content "$profile.err" -Raw -ErrorAction SilentlyContinue)
  } finally { Remove-Item $profile, "$profile.out", "$profile.err" -Recurse -Force -ErrorAction SilentlyContinue }
}

try {
  New-Item -ItemType Directory -Force -Path (Join-Path $data "rules") | Out-Null
  Copy-Item "data\adult-domains\domains.json" (Join-Path $data "rules\adult-domains.json") -Force

  # --- service -------------------------------------------------------------
  & $exe install
  if ($LASTEXITCODE -ne 0) { throw "install failed" }
  $svc = Get-CimInstance Win32_Service -Filter "Name='SavingGrace'"
  Assert ($svc.StartMode -eq "Auto") "StartMode is $($svc.StartMode), expected Auto"
  Assert ($svc.State -eq "Running") "service state is $($svc.State)"

  $s = Get-AgentStatus
  Assert $s.ok "status not ok"
  Write-Host ("agentState=$($s.result.agentState) networkFiltering=$($s.result.networkFiltering)")
  Write-Host ($s.result.enforcement | ConvertTo-Json -Compress)
  Assert ($s.result.agentState -eq "running") "agentState = $($s.result.agentState): $($s.result.degradedReasons -join ', ')"
  Assert ($s.result.networkFiltering -eq "enforced") "networkFiltering = $($s.result.networkFiltering)"
  $verified.Add("service auto-start + status over named pipe")

  $acl = (Get-Acl $data).Access | ForEach-Object { $_.IdentityReference.Value }
  Assert (-not ($acl -match "Users|Everyone")) "data directory ACL still grants access to: $($acl -join ', ')"
  $verified.Add("data directory ACL")

  # --- DNS redirection -----------------------------------------------------
  $dns = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses.Count -gt 0 -and $_.InterfaceAlias -notmatch "Loopback" }
  Assert ($dns.Count -gt 0) "no adapter has DNS servers"
  foreach ($d in $dns) { Assert (($d.ServerAddresses -join ",") -eq "127.0.0.1") "adapter $($d.InterfaceAlias) DNS = $($d.ServerAddresses -join ',')" }
  $verified.Add("all adapters point at 127.0.0.1")

  Assert (Test-Resolves "example.com" $null) "allowed domain example.com must resolve"
  Assert (-not (Test-Resolves "pornhub.com" $null)) "blocked domain pornhub.com must NOT resolve"
  Assert (-not (Test-Resolves "www.xvideos.com" $null)) "subdomain of blocked domain must NOT resolve"
  $verified.Add("system resolver: allowed resolves, blocked and subdomains do not")

  # --- bypass attempts -----------------------------------------------------
  Assert (-not (Test-Resolves "example.com" "8.8.8.8")) "direct DNS to 8.8.8.8 must be blocked by the firewall"
  Assert (-not (Test-Resolves "example.com" "1.1.1.1")) "direct DNS to 1.1.1.1 must be blocked by the firewall"
  Assert (-not (Test-TcpConnect "1.1.1.1" 443)) "DoH endpoint 1.1.1.1:443 must be blocked"
  Assert (-not (Test-TcpConnect "8.8.8.8" 853)) "DNS-over-TLS to 8.8.8.8:853 must be blocked"
  $verified.Add("alternative DNS, DoH endpoint and DoT blocked by WFP")

  # --- browser policies ----------------------------------------------------
  foreach ($p in @(
      @("HKLM:\SOFTWARE\Policies\Google\Chrome", "DnsOverHttpsMode", "off"),
      @("HKLM:\SOFTWARE\Policies\Microsoft\Edge", "DnsOverHttpsMode", "off"),
      @("HKLM:\SOFTWARE\Policies\BraveSoftware\Brave", "DnsOverHttpsMode", "off"),
      @("HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS", "Enabled", 0),
      @("HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS", "Locked", 1))) {
    $v = (Get-ItemProperty -Path $p[0] -Name $p[1] -ErrorAction Stop).($p[1])
    Assert ($v -eq $p[2]) "$($p[0])\$($p[1]) = $v, expected $($p[2])"
  }
  $verified.Add("browser DoH policies written for Chrome, Edge, Brave, Firefox")

  # --- real browsers (only those installed on the runner) -------------------
  $browsers = @{
    "Chrome" = @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe")
    "Edge"   = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe")
  }
  foreach ($name in $browsers.Keys) {
    $path = $browsers[$name] | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $path) { $skipped.Add("$name (not installed)"); continue }
    $ok = Get-BrowserDump $path "http://example.com/"
    Assert ($ok -match "Example Domain") "$name could not load the allowed page (control)"
    $bad = Get-BrowserDump $path "http://pornhub.com/"
    Assert ($bad -match "ERR_NAME_NOT_RESOLVED|This site can.t be reached|isn.t reachable") "$name did not report the blocked site as unreachable"
    $verified.Add("$name headless: allowed page loads, blocked page does not")
  }
  $skipped.Add("Firefox and Brave navigation (not automated; see docs/TESTING.md manual checklist)")

  # --- tamper resistance -----------------------------------------------------
  $adapter = Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1
  Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses "8.8.8.8"
  $fixed = $false
  for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Seconds 1
    $now = (Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).ServerAddresses -join ","
    if ($now -eq "127.0.0.1") { $fixed = $true; break }
  }
  Assert $fixed "watchdog did not restore DNS after it was changed to 8.8.8.8"
  Assert ((Get-AgentStatus).result.enforcement.tamperEvents -ge 1) "tamper event was not counted"
  $verified.Add("DNS tampering repaired by watchdog and counted")

  # --- crash recovery --------------------------------------------------------
  $pid1 = (Get-CimInstance Win32_Service -Filter "Name='SavingGrace'").ProcessId
  Stop-Process -Id $pid1 -Force
  $restarted = $false
  for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Seconds 1
    $now = Get-CimInstance Win32_Service -Filter "Name='SavingGrace'"
    if ($now.State -eq "Running" -and $now.ProcessId -ne $pid1 -and $now.ProcessId -ne 0) { $restarted = $true; break }
  }
  Assert $restarted "service was not restarted after the process was killed"
  $s = Get-AgentStatus
  Assert ($s.result.networkFiltering -eq "enforced") "not enforced again after restart: $($s.result.networkFiltering)"
  Assert (-not (Test-Resolves "pornhub.com" $null)) "blocked domain resolves after restart"
  $verified.Add("crash recovery: restart re-enforces without losing original DNS settings")

  # --- clean stop restores the machine ---------------------------------------
  & $exe uninstall
  if ($LASTEXITCODE -ne 0) { throw "uninstall failed" }
  Assert (-not (Get-Service -Name SavingGrace -ErrorAction SilentlyContinue)) "service still registered"
  $after = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses -contains "127.0.0.1" }
  Assert (-not $after) "an adapter still points at 127.0.0.1 after uninstall"
  Assert (Test-Resolves "example.com" "8.8.8.8") "direct DNS still blocked after uninstall (firewall filters left behind)"
  Assert (-not (Test-Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS" -PathType Container) -or -not (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS" -ErrorAction SilentlyContinue).Locked) "Firefox policy left behind"
  $verified.Add("uninstall restores DNS, removes filters and policies")

  Write-Host "`nVERIFIED:"; $verified | ForEach-Object { Write-Host "  + $_" }
  Write-Host "NOT AUTOMATED:"; $skipped | ForEach-Object { Write-Host "  - $_" }
  Write-Host "SMOKE TEST PASSED"
}
finally {
  # Never leave a CI machine (or a developer machine) with broken DNS.
  try { & $exe uninstall 2>$null } catch {}
  Get-NetAdapter | Where-Object Status -eq "Up" | ForEach-Object {
    $cur = (Get-DnsClientServerAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4).ServerAddresses
    if ($cur -contains "127.0.0.1") { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses }
  }
  Clear-DnsClientCache
}

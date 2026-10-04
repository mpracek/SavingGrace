# Windows smoke test for the SavingGrace service. Intended for CI (windows-latest runs elevated).
# Installs the service, verifies auto-start config, queries status over the named pipe,
# kills the process to prove the recovery action restarts it, then uninstalls.
param([string]$Exe = "target\release\savinggrace-agent.exe")
$ErrorActionPreference = "Stop"
$exe = (Resolve-Path $Exe).Path
$data = Join-Path $env:ProgramData "SavingGrace"

New-Item -ItemType Directory -Force -Path (Join-Path $data "rules") | Out-Null
Copy-Item "data\adult-domains\domains.json" (Join-Path $data "rules\adult-domains.json") -Force

& $exe install
if ($LASTEXITCODE -ne 0) { throw "install failed" }

$svc = Get-CimInstance Win32_Service -Filter "Name='SavingGrace'"
if ($svc.StartMode -ne "Auto") { throw "StartMode is $($svc.StartMode), expected Auto" }
if ($svc.State -ne "Running") { throw "service state is $($svc.State)" }

function Get-AgentStatus {
  for ($i = 0; $i -lt 20; $i++) {
    try { return (& $exe status | ConvertFrom-Json) } catch { Start-Sleep -Milliseconds 500 }
  }
  throw "agent did not answer over the named pipe"
}

$s = Get-AgentStatus
if (-not $s.ok) { throw "status not ok" }
if ($s.result.agentState -ne "running") { throw "agentState = $($s.result.agentState): $($s.result.degradedReasons -join ', ')" }
if ($s.result.networkFiltering -ne "not_implemented") { throw "unexpected networkFiltering value" }
Write-Host "status OK: version $($s.result.version), global list $($s.result.rules.globalList.count) domains"

# The data directory must be unreadable for ordinary users (protected DACL).
$acl = (Get-Acl $data).Access | ForEach-Object { $_.IdentityReference.Value }
if ($acl -match "Users|Everyone") { throw "data directory ACL still grants access to: $($acl -join ', ')" }

# Crash recovery: kill the service process, expect the SCM to restart it.
$pid1 = (Get-CimInstance Win32_Service -Filter "Name='SavingGrace'").ProcessId
Stop-Process -Id $pid1 -Force
$restarted = $false
for ($i = 0; $i -lt 30; $i++) {
  Start-Sleep -Seconds 1
  $now = Get-CimInstance Win32_Service -Filter "Name='SavingGrace'"
  if ($now.State -eq "Running" -and $now.ProcessId -ne $pid1 -and $now.ProcessId -ne 0) { $restarted = $true; break }
}
if (-not $restarted) { throw "service was not restarted after the process was killed" }
$null = Get-AgentStatus
Write-Host "recovery OK"

& $exe uninstall
if ($LASTEXITCODE -ne 0) { throw "uninstall failed" }
if (Get-Service -Name SavingGrace -ErrorAction SilentlyContinue) { throw "service still registered" }
Write-Host "SMOKE TEST PASSED"

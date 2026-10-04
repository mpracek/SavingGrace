use anyhow::{anyhow, bail, Context};
use savinggrace_agent::agent::{self, AgentOptions};
use savinggrace_agent::ipc::{self, IpcEndpoint, Request};
use savinggrace_agent::paths::DataDirs;
use std::path::PathBuf;

const USAGE: &str = "\
savinggrace-agent <command> [--data-dir <path>]

Commands:
  run         Run in the foreground (Ctrl+C to stop)
  status      Query a running agent over IPC and print its status as JSON
  version     Print the version
  install     (Windows, Administrator) register and start the Windows service
  uninstall   (Windows, Administrator) stop and remove the Windows service
  service     (internal) entry point used by the Service Control Manager

--data-dir is required on non-Windows hosts (development only).";

fn main() {
    if let Err(e) = real_main() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn parse_data_dir(args: &[String]) -> anyhow::Result<DataDirs> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--data-dir" {
            let p = it
                .next()
                .ok_or_else(|| anyhow!("--data-dir needs a value"))?;
            return Ok(DataDirs::new(PathBuf::from(p)));
        }
    }
    DataDirs::platform_default()
        .ok_or_else(|| anyhow!("no default data directory on this platform; pass --data-dir"))
}

fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}

fn real_main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("help");
    let rest = args.get(1..).unwrap_or(&[]);

    match command {
        "version" => println!("savinggrace-agent {}", savinggrace_agent::VERSION),
        "run" => {
            let dirs = parse_data_dir(rest)?;
            let _log = savinggrace_agent::logging::init(&dirs.logs_dir, true);
            runtime()?.block_on(async {
                let endpoint = IpcEndpoint::default_for(&dirs);
                let running = agent::start(AgentOptions { dirs, endpoint }).await?;
                tokio::signal::ctrl_c()
                    .await
                    .context("cannot listen for Ctrl+C")?;
                running.shutdown().await;
                anyhow::Ok(())
            })?;
        }
        "status" => {
            let dirs = parse_data_dir(rest)?;
            let endpoint = IpcEndpoint::default_for(&dirs);
            let resp = runtime()?
                .block_on(ipc::send_request(&endpoint, &Request::GetStatus))
                .with_context(|| format!("cannot reach the agent at {endpoint}"))?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
            if !resp.ok {
                bail!("agent returned an error");
            }
        }
        #[cfg(windows)]
        "service" => savinggrace_agent::service_windows::run_as_service()
            .map_err(|e| anyhow!("service dispatcher: {e}"))?,
        #[cfg(windows)]
        "install" => {
            savinggrace_agent::service_windows::install()?;
            println!("Service installed and started.");
        }
        #[cfg(windows)]
        "uninstall" => {
            savinggrace_agent::service_windows::uninstall()?;
            println!("Service removed.");
        }
        #[cfg(not(windows))]
        "service" | "install" | "uninstall" => bail!("'{command}' is only available on Windows"),
        _ => println!("{USAGE}"),
    }
    Ok(())
}

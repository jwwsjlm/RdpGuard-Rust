use std::process::ExitCode;

use anyhow::{Result, bail};
use rdpguard::{VERSION, elevation, monitor_runtime};

const HELP: &str = "RdpGuard Monitor - read-only RDP activity viewer\n\n\
Usage:\n  rdpguard-monitor\n  rdpguard-monitor --version\n  rdpguard-monitor --help\n\n\
Keys:\n  Tab/Shift+Tab  Switch page\n  1/2/3/4        10 minutes / 1 hour / 24 hours / 7 days\n  r              Refresh now\n  Up/Down         Scroll rows\n  q/Esc           Quit\n\n\
The monitor refreshes every 30 seconds and requests administrator access when needed.\n";

fn main() -> ExitCode {
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rdpguard-monitor: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn real_main() -> Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.as_slice() {
        [argument] if argument == "--version" => {
            println!("rdpguard-monitor {VERSION}");
            return Ok(());
        }
        [argument] if argument == "--help" => {
            print!("{HELP}");
            return Ok(());
        }
        [] => {}
        _ => bail!("unknown argument or invalid usage\n\n{HELP}"),
    }

    if !elevation::is_elevated()? {
        elevation::relaunch_elevated()?;
        return Ok(());
    }
    monitor_runtime::run_interactive_monitor()
}

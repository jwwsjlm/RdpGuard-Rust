use std::{error::Error, fmt, path::PathBuf, process::ExitCode};

use anyhow::{Context, Result};
use rdpguard::{
    VERSION,
    app::{AppPaths, execute_once},
    service,
};

const HELP: &str = "RdpGuard - temporary blocking for repeated RDP failures\n\n\
Usage:\n  rdpguard --service\n  rdpguard --once [path options]\n  rdpguard --dry-run [path options]\n  rdpguard --version\n\n\
Path options:\n  --config <file>  Configuration JSON\n  --state <file>   Persistent block state JSON\n  --log <file>     Operational log\n";

enum Mode {
    Service,
    Once { dry_run: bool, paths: AppPaths },
}

fn main() -> ExitCode {
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rdpguard: {error:#}");
            if error.downcast_ref::<UsageError>().is_some() {
                ExitCode::from(2)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn real_main() -> Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments == ["--help"] {
        print!("{HELP}");
        return Ok(());
    }
    if arguments == ["--version"] {
        println!("rdpguard {VERSION}");
        return Ok(());
    }
    let mode = parse_mode(&arguments).inspect_err(|_error| {
        eprintln!("unknown argument or invalid usage\n\n{HELP}");
    })?;
    match mode {
        Mode::Service => service::run_dispatcher().context("service dispatcher failed"),
        Mode::Once { dry_run, paths } => {
            let outcome = execute_once(&paths, dry_run)?;
            println!(
                "failures={} blocked={} unblocked={}",
                outcome.report.failures, outcome.report.blocked, outcome.report.unblocked
            );
            for change in outcome.planned_changes {
                println!("dry-run: {change:?}");
            }
            Ok(())
        }
    }
}

#[derive(Debug)]
struct UsageError(String);

impl fmt::Display for UsageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for UsageError {}

fn parse_mode(arguments: &[String]) -> std::result::Result<Mode, UsageError> {
    let Some(first) = arguments.first() else {
        return Err(UsageError("missing mode".into()));
    };
    if first == "--service" && arguments.len() == 1 {
        return Ok(Mode::Service);
    }
    let dry_run = match first.as_str() {
        "--once" => false,
        "--dry-run" => true,
        _ => return Err(UsageError(format!("unknown argument: {first}"))),
    };
    let mut paths = AppPaths::default();
    let mut index = 1;
    while index < arguments.len() {
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| UsageError("path option requires a value".into()))?;
        match arguments[index].as_str() {
            "--config" => paths.config = PathBuf::from(value),
            "--state" => paths.state = PathBuf::from(value),
            "--log" => paths.log = PathBuf::from(value),
            other => return Err(UsageError(format!("unknown argument: {other}"))),
        }
        index += 2;
    }
    Ok(Mode::Once { dry_run, paths })
}

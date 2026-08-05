use std::{error::Error, fmt, path::PathBuf, process::ExitCode};

use anyhow::{Context, Result};
use rdpguard::{
    VERSION,
    app::{AppPaths, execute_once},
    doctor,
    language::Language,
    service,
    sessions::active_public_rdp_session_sources,
};

const HELP: &str = "RdpGuard - temporary blocking for repeated RDP failures\n\n\
Usage:\n  rdpguard --service\n  rdpguard --once [path options]\n  rdpguard --dry-run [path options]\n  rdpguard doctor [--json] [--language zh-CN|en-US] [path options]\n  rdpguard session-sources --json\n  rdpguard --version\n\n\
Path options:\n  --config <file>  Configuration JSON\n  --state <file>   Persistent block state JSON\n  --log <file>     Operational log\n";

enum Mode {
    Service,
    Once {
        dry_run: bool,
        paths: AppPaths,
    },
    Doctor {
        json: bool,
        language: Language,
        paths: AppPaths,
    },
    SessionSources,
}

fn main() -> ExitCode {
    match real_main() {
        Ok(code) => ExitCode::from(code),
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

fn real_main() -> Result<u8> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments == ["--help"] {
        print!("{HELP}");
        return Ok(0);
    }
    if arguments == ["--version"] {
        println!("rdpguard {VERSION}");
        return Ok(0);
    }
    let mode = parse_mode(&arguments).inspect_err(|_error| {
        eprintln!("unknown argument or invalid usage\n\n{HELP}");
    })?;
    match mode {
        Mode::Service => {
            service::run_dispatcher().context("service dispatcher failed")?;
            Ok(0)
        }
        Mode::Once { dry_run, paths } => {
            let outcome = execute_once(&paths, dry_run)?;
            println!(
                "failures={} blocked={} unblocked={}",
                outcome.report.failures, outcome.report.blocked, outcome.report.unblocked
            );
            for change in outcome.planned_changes {
                println!("dry-run: {change:?}");
            }
            Ok(0)
        }
        Mode::Doctor {
            json,
            language,
            paths,
        } => {
            let report = doctor::run(&paths, language);
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", report.render_text(language));
            }
            Ok(report.exit_code())
        }
        Mode::SessionSources => {
            let addresses: Vec<_> = active_public_rdp_session_sources()?
                .into_iter()
                .map(|address| address.to_string())
                .collect();
            println!("{}", serde_json::to_string(&addresses)?);
            Ok(0)
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
    if first == "doctor" {
        let mut json = false;
        let mut language = Language::detect();
        let mut paths = AppPaths::default();
        let mut index = 1;
        while index < arguments.len() {
            match arguments[index].as_str() {
                "--json" => {
                    json = true;
                    index += 1;
                }
                "--language" | "--config" | "--state" | "--log" => {
                    let option = arguments[index].as_str();
                    let value = arguments
                        .get(index + 1)
                        .ok_or_else(|| UsageError(format!("{option} requires a value")))?;
                    match option {
                        "--language" => {
                            language = Language::parse_cli(value)
                                .map_err(|error| UsageError(error.to_string()))?
                        }
                        "--config" => paths.config = PathBuf::from(value),
                        "--state" => paths.state = PathBuf::from(value),
                        "--log" => paths.log = PathBuf::from(value),
                        _ => unreachable!(),
                    }
                    index += 2;
                }
                other => return Err(UsageError(format!("unknown doctor argument: {other}"))),
            }
        }
        return Ok(Mode::Doctor {
            json,
            language,
            paths,
        });
    }
    if arguments == ["session-sources", "--json"] {
        return Ok(Mode::SessionSources);
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

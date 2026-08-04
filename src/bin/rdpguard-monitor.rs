use std::process::ExitCode;

use anyhow::{Result, bail};
use rdpguard::{VERSION, elevation, language::Language, monitor_runtime};

fn help(language: Language) -> &'static str {
    match language {
        Language::Chinese => {
            "RdpGuard 历史日志监控器（只读）\n\n\
用法：\n  rdpguard-monitor [--language zh-CN|en-US]\n  rdpguard-monitor --version\n  rdpguard-monitor --help\n\n\
按键：\n  Tab/Shift+Tab  切换历史页面\n  1/2/3/4        10 分钟 / 1 小时 / 24 小时 / 7 天\n  r              手动刷新\n  l              中文 / English\n  Up/Down         滚动\n  q/Esc           退出\n\n\
程序只在启动、切换时间范围或按 r 时读取日志。\n"
        }
        Language::English => {
            "RdpGuard Monitor - read-only RDP history viewer\n\n\
Usage:\n  rdpguard-monitor [--language zh-CN|en-US]\n  rdpguard-monitor --version\n  rdpguard-monitor --help\n\n\
Keys:\n  Tab/Shift+Tab  Switch history page\n  1/2/3/4        10 minutes / 1 hour / 24 hours / 7 days\n  r              Refresh now\n  l              English / 中文\n  Up/Down         Scroll rows\n  q/Esc           Quit\n\n\
Logs are read only at startup, after changing range, or after pressing r.\n"
        }
    }
}

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
    let mut language = None;
    let mut show_help = false;
    let mut show_version = false;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--language" => {
                index += 1;
                let value = arguments
                    .get(index)
                    .ok_or_else(|| anyhow::anyhow!("--language requires zh-CN or en-US"))?;
                if language.is_some() {
                    bail!("--language may only be provided once");
                }
                language = Some(Language::parse_cli(value)?);
            }
            "--help" if !show_help && !show_version => show_help = true,
            "--version" if !show_help && !show_version => show_version = true,
            argument => bail!("unknown argument or invalid usage: {argument}"),
        }
        index += 1;
    }
    let language = language.unwrap_or_else(Language::detect);
    if show_version {
        println!("rdpguard-monitor {VERSION}");
        return Ok(());
    }
    if show_help {
        print!("{}", help(language));
        return Ok(());
    }

    if !elevation::is_elevated()? {
        elevation::relaunch_elevated(language)?;
        return Ok(());
    }
    monitor_runtime::run_interactive_monitor(language)
}

use serde::Serialize;
use windows_service::{
    service::ServiceAccess,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

use crate::{
    VERSION,
    app::AppPaths,
    config::Config,
    engine::managed_rule,
    events::{query_recent_auth_events, query_recent_failures},
    firewall::{Firewall, WindowsFirewall, detect_rdp_port, firewall_policy_status},
    language::Language,
    sessions::active_public_rdp_session_sources,
    state::load_state,
};

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticStatus {
    Healthy,
    Warning,
    Error,
}

#[derive(Debug, Serialize)]
pub struct DiagnosticCheck {
    pub name: &'static str,
    pub status: DiagnosticStatus,
    pub code: Option<&'static str>,
    pub message: String,
    pub remediation: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DoctorReport {
    pub version: &'static str,
    pub architecture: &'static str,
    pub healthy: bool,
    pub checks: Vec<DiagnosticCheck>,
}

impl DoctorReport {
    pub fn exit_code(&self) -> u8 {
        if self.healthy { 0 } else { 1 }
    }

    pub fn render_text(&self, language: Language) -> String {
        let mut output = match language {
            Language::Chinese => format!(
                "RdpGuard 诊断  版本 {}  架构 {}\n\n",
                self.version, self.architecture
            ),
            Language::English => format!(
                "RdpGuard diagnostics  version {}  architecture {}\n\n",
                self.version, self.architecture
            ),
        };
        for check in &self.checks {
            let marker = match check.status {
                DiagnosticStatus::Healthy => "OK",
                DiagnosticStatus::Warning => "WARN",
                DiagnosticStatus::Error => "ERROR",
            };
            let code = check.code.map_or(String::new(), |code| format!(" {code}"));
            output.push_str(&format!(
                "[{marker}{code}] {}: {}\n",
                check.name, check.message
            ));
            if let Some(remediation) = &check.remediation {
                output.push_str(&format!("  -> {remediation}\n"));
            }
        }
        output.push_str(match (language, self.healthy) {
            (Language::Chinese, true) => "\n结果：健康\n",
            (Language::Chinese, false) => "\n结果：存在需要处理的项目\n",
            (Language::English, true) => "\nResult: healthy\n",
            (Language::English, false) => "\nResult: attention required\n",
        });
        output
    }
}

fn check_service(name: &'static str, display: &'static str, language: Language) -> DiagnosticCheck {
    let result = (|| -> anyhow::Result<String> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let service = manager.open_service(name, ServiceAccess::QUERY_STATUS)?;
        Ok(format!("{:?}", service.query_status()?.current_state))
    })();
    match result {
        Ok(state) if state == "Running" => healthy(display, state),
        Ok(state) => warning(
            display,
            "SVC001",
            state,
            choose(language, "请启动该服务。", "Start this service."),
        ),
        Err(error) => error_check(
            display,
            "SVC001",
            format!("{error:#}"),
            choose(
                language,
                "请以管理员身份运行诊断，并确认服务已安装。",
                "Run diagnostics as administrator and confirm the service is installed.",
            ),
        ),
    }
}

pub fn run(paths: &AppPaths, language: Language) -> DoctorReport {
    let mut checks = vec![
        healthy(
            "binary",
            format!("RdpGuard {VERSION} ({})", std::env::consts::ARCH),
        ),
        check_service("RdpGuard", "RdpGuard service", language),
        check_service("MpsSvc", "Windows Firewall service", language),
    ];

    let config = match Config::load(&paths.config) {
        Ok(config) => {
            checks.push(healthy(
                "configuration",
                format!(
                    "schema v{}; scope={:?}",
                    config.schema_version, config.block_scope
                ),
            ));
            Some(config)
        }
        Err(error) => {
            checks.push(error_check(
                "configuration",
                "CFG001",
                format!("{error:#}"),
                choose(
                    language,
                    "请修复 C:\\ProgramData\\RdpGuard\\config.json，或重新运行安装配置。",
                    "Repair C:\\ProgramData\\RdpGuard\\config.json or rerun installation/configuration.",
                ),
            ));
            None
        }
    };

    let rdp_port = config
        .as_ref()
        .and_then(|config| config.rdp_port)
        .map(Ok)
        .unwrap_or_else(detect_rdp_port);
    let active_port = rdp_port.as_ref().ok().copied().filter(|port| *port > 0);
    match &rdp_port {
        Ok(port) if *port > 0 => checks.push(healthy("RDP port", port.to_string())),
        Ok(_) | Err(_) => checks.push(error_check(
            "RDP port",
            "CFG002",
            rdp_port
                .as_ref()
                .err()
                .map_or_else(|| "invalid port 0".into(), |error| format!("{error:#}")),
            choose(
                language,
                "检查 RDP-Tcp 的 PortNumber 注册表值，或设置 rdp_port。",
                "Check the RDP-Tcp PortNumber registry value or set rdp_port.",
            ),
        )),
    }
    if active_port.is_some() {
        match active_public_rdp_session_sources() {
            Ok(public) => {
                checks.push(healthy(
                    "active authenticated RDP session sources",
                    if public.is_empty() {
                        "no authenticated active public RDP session sources".to_owned()
                    } else {
                        public
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    },
                ));
            }
            Err(error) => checks.push(warning(
                "active authenticated RDP session sources",
                "CONN002",
                format!("{error:#}"),
                choose(
                    language,
                    "请以管理员身份运行诊断。此项失败不会影响封禁。",
                    "Run diagnostics as administrator. This does not affect blocking.",
                ),
            )),
        }
    }

    let state = match load_state(&paths.state) {
        Ok(state) => {
            checks.push(healthy(
                "state",
                format!("{} active blocks", state.blocks.len()),
            ));
            Some(state)
        }
        Err(error) => {
            checks.push(error_check(
                "state",
                "STATE001",
                format!("{error:#}"),
                choose(
                    language,
                    "服务会隔离损坏状态并从防火墙元数据恢复；请检查磁盘和 ACL。",
                    "The service will quarantine corrupt state and recover firewall metadata; check disk health and ACLs.",
                ),
            ));
            None
        }
    };

    let rules = match WindowsFirewall::new().and_then(|mut firewall| firewall.managed_rules()) {
        Ok(Some(rules)) => {
            checks.push(healthy(
                "firewall rules",
                format!("{} managed addresses", rules.len()),
            ));
            Some(rules)
        }
        Ok(None) => None,
        Err(error) => {
            checks.push(error_check(
                "firewall rules",
                "FW001",
                format!("{error:#}"),
                choose(
                    language,
                    "请确认 Windows Defender 防火墙服务正在运行且本地规则未被组策略禁用。",
                    "Confirm Windows Defender Firewall is running and local rules are not disabled by policy.",
                ),
            ));
            None
        }
    };

    match firewall_policy_status() {
        Ok(policy) if policy.disabled_profiles != 0 => checks.push(error_check(
            "firewall policy",
            "FW005",
            format!(
                "active_profiles=0x{:X}; disabled_profiles=0x{:X}",
                policy.active_profiles, policy.disabled_profiles
            ),
            choose(
                language,
                "请为所有活动网络配置启用 Windows Defender 防火墙。",
                "Enable Windows Defender Firewall for every active network profile.",
            ),
        )),
        Ok(policy) if policy.local_rules_allowed() => checks.push(healthy(
            "firewall policy",
            format!("active_profiles=0x{:X}; local rules allowed", policy.active_profiles),
        )),
        Ok(policy) => checks.push(warning(
            "firewall policy",
            "FW004",
            format!(
                "active_profiles=0x{:X}; local_modify_state={}",
                policy.active_profiles, policy.local_modify_state.0
            ),
            choose(
                language,
                "本地防火墙规则可能被组策略覆盖；请联系域管理员允许本地规则合并。",
                "Local firewall rules may be overridden by Group Policy; ask the domain administrator to allow local rule merging.",
            ),
        )),
        Err(error) => checks.push(error_check(
            "firewall policy",
            "FW001",
            format!("{error:#}"),
            choose(
                language,
                "请确认 Windows Defender 防火墙服务可用，并以管理员身份运行诊断。",
                "Confirm Windows Defender Firewall is available and run diagnostics as administrator.",
            ),
        )),
    }

    if let (Some(state), Some(rules)) = (&state, &rules) {
        let actual: std::collections::HashMap<_, _> =
            rules.iter().map(|rule| (rule.ip, rule)).collect();
        let mut effective_config = config.clone().unwrap_or_default();
        if effective_config.rdp_port.is_none() {
            effective_config.rdp_port = active_port;
        }
        let missing = state
            .blocks
            .iter()
            .filter(|(ip, record)| {
                actual.get(ip).copied()
                    != Some(&managed_rule(**ip, record, state, &effective_config))
            })
            .count();
        let orphaned = actual
            .keys()
            .filter(|ip| !state.blocks.contains_key(ip))
            .count();
        if missing == 0 && orphaned == 0 {
            checks.push(healthy("reconciliation", "state and firewall match"));
        } else {
            checks.push(warning(
                "reconciliation",
                "FW003",
                format!("missing_or_mismatched={missing}, orphaned={orphaned}"),
                choose(
                    language,
                    "保持服务运行；下一轮检查会自动修复。",
                    "Keep the service running; the next check will repair this automatically.",
                ),
            ));
        }
        if let Some(config) = &config
            && state.blocks.len() >= config.max_active_blocks
        {
            checks.push(warning(
                "rule capacity",
                "FW002",
                format!("{} / {}", state.blocks.len(), config.max_active_blocks),
                choose(
                    language,
                    "检查攻击流量和白名单，不建议盲目提高上限。",
                    "Review attack traffic and the whitelist before increasing the limit.",
                ),
            ));
        }
    }

    match query_recent_failures(1) {
        Ok(events) => checks.push(healthy(
            "RdpCoreTS log",
            format!("readable; {} recent events", events.len()),
        )),
        Err(error) => checks.push(error_check(
            "RdpCoreTS log",
            "EVT001",
            format!("{error:#}"),
            choose(
                language,
                "启用 Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational 日志。",
                "Enable the Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational log.",
            ),
        )),
    }
    match query_recent_auth_events(1) {
        Ok(events) => checks.push(healthy(
            "Security log",
            format!("readable; {} recent events", events.events.len()),
        )),
        Err(error) => checks.push(warning(
            "Security log",
            "EVT002",
            format!("{error:#}"),
            choose(
                language,
                "请以管理员身份运行；该权限只影响历史登录展示，不影响封禁。",
                "Run as administrator; this only affects login history display, not blocking.",
            ),
        )),
    }

    let healthy = checks
        .iter()
        .all(|check| check.status == DiagnosticStatus::Healthy);
    DoctorReport {
        version: VERSION,
        architecture: std::env::consts::ARCH,
        healthy,
        checks,
    }
}

fn healthy(name: &'static str, message: impl Into<String>) -> DiagnosticCheck {
    DiagnosticCheck {
        name,
        status: DiagnosticStatus::Healthy,
        code: None,
        message: message.into(),
        remediation: None,
    }
}

fn warning(
    name: &'static str,
    code: &'static str,
    message: impl Into<String>,
    remediation: impl Into<String>,
) -> DiagnosticCheck {
    DiagnosticCheck {
        name,
        status: DiagnosticStatus::Warning,
        code: Some(code),
        message: message.into(),
        remediation: Some(remediation.into()),
    }
}

fn error_check(
    name: &'static str,
    code: &'static str,
    message: impl Into<String>,
    remediation: impl Into<String>,
) -> DiagnosticCheck {
    DiagnosticCheck {
        name,
        status: DiagnosticStatus::Error,
        code: Some(code),
        message: message.into(),
        remediation: Some(remediation.into()),
    }
}

fn choose(language: Language, chinese: &str, english: &str) -> String {
    match language {
        Language::Chinese => chinese,
        Language::English => english,
    }
    .to_owned()
}

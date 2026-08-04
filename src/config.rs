use std::{fmt, fs, net::IpAddr, path::Path, str::FromStr};

use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::policy::normalize_ip;

pub const CONFIG_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BlockScope {
    #[default]
    AllInbound,
    RdpOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhitelistEntry(IpNet);

impl WhitelistEntry {
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0.contains(&normalize_ip(ip))
    }
}

impl fmt::Display for WhitelistEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for WhitelistEntry {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let network = if value.contains('/') {
            value.parse::<IpNet>().context("invalid whitelist CIDR")?
        } else {
            let ip = normalize_ip(value.parse::<IpAddr>().context("invalid whitelist IP")?);
            IpNet::new(ip, if ip.is_ipv4() { 32 } else { 128 })?
        };
        Ok(Self(network.trunc()))
    }
}

impl Serialize for WhitelistEntry {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for WhitelistEntry {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Config {
    pub schema_version: u32,
    pub check_interval_seconds: u64,
    pub window_minutes: u64,
    pub failure_threshold: usize,
    pub block_minutes: u64,
    pub max_log_size_mb: u64,
    pub log_retention_files: usize,
    pub whitelist: Vec<WhitelistEntry>,
    pub block_scope: BlockScope,
    pub rdp_port: Option<u16>,
    pub repeat_block_multiplier: u32,
    pub max_block_minutes: u64,
    pub repeat_reset_days: u64,
    pub max_active_blocks: usize,
    pub heartbeat_minutes: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            check_interval_seconds: 60,
            window_minutes: 10,
            failure_threshold: 5,
            block_minutes: 360,
            max_log_size_mb: 10,
            log_retention_files: 5,
            whitelist: Vec::new(),
            block_scope: BlockScope::AllInbound,
            rdp_port: None,
            repeat_block_multiplier: 2,
            max_block_minutes: 10_080,
            repeat_reset_days: 30,
            max_active_blocks: 5_000,
            heartbeat_minutes: 60,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != CONFIG_SCHEMA_VERSION {
            bail!("CFG001: unsupported schema_version {}", self.schema_version);
        }
        if !(10..=3_600).contains(&self.check_interval_seconds) {
            bail!("check_interval_seconds must be between 10 and 3600");
        }
        if !(1..=1_440).contains(&self.window_minutes) {
            bail!("window_minutes must be between 1 and 1440");
        }
        if !(1..=10_000).contains(&self.failure_threshold) {
            bail!("failure_threshold must be between 1 and 10000");
        }
        if !(1..=525_600).contains(&self.block_minutes) {
            bail!("block_minutes must be between 1 and 525600");
        }
        if !(1..=1_024).contains(&self.max_log_size_mb) {
            bail!("max_log_size_mb must be between 1 and 1024");
        }
        if !(1..=100).contains(&self.log_retention_files) {
            bail!("log_retention_files must be between 1 and 100");
        }
        if self.rdp_port == Some(0) {
            bail!("rdp_port must be between 1 and 65535");
        }
        if !(1..=16).contains(&self.repeat_block_multiplier) {
            bail!("repeat_block_multiplier must be between 1 and 16");
        }
        if self.max_block_minutes < self.block_minutes || self.max_block_minutes > 525_600 {
            bail!("max_block_minutes must be between block_minutes and 525600");
        }
        if !(1..=3650).contains(&self.repeat_reset_days) {
            bail!("repeat_reset_days must be between 1 and 3650");
        }
        if !(1..=100_000).contains(&self.max_active_blocks) {
            bail!("max_active_blocks must be between 1 and 100000");
        }
        if !(1..=1440).contains(&self.heartbeat_minutes) {
            bail!("heartbeat_minutes must be between 1 and 1440");
        }
        Ok(())
    }

    pub fn is_whitelisted(&self, ip: IpAddr) -> bool {
        self.whitelist.iter().any(|entry| entry.contains(ip))
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        let raw: serde_json::Value = serde_json::from_str(&text)
            .with_context(|| format!("failed to parse config {}", path.display()))?;
        let has_max_block = raw.get("max_block_minutes").is_some();
        let mut config: Self = serde_json::from_value(raw)
            .with_context(|| format!("failed to parse config {}", path.display()))?;
        if config.schema_version == 1 {
            config.schema_version = CONFIG_SCHEMA_VERSION;
        }
        if !has_max_block {
            config.max_block_minutes = config.max_block_minutes.max(config.block_minutes);
        }
        config
            .validate()
            .context("CFG001: invalid RdpGuard configuration")?;
        Ok(config)
    }
}

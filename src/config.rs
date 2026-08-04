use std::{fs, net::IpAddr, path::Path};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Config {
    pub check_interval_seconds: u64,
    pub window_minutes: u64,
    pub failure_threshold: usize,
    pub block_minutes: u64,
    pub whitelist: Vec<IpAddr>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            check_interval_seconds: 60,
            window_minutes: 10,
            failure_threshold: 5,
            block_minutes: 360,
            whitelist: Vec::new(),
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
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
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        let config: Self = serde_json::from_str(&text)
            .with_context(|| format!("failed to parse config {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }
}

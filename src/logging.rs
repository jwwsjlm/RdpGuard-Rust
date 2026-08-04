use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use anyhow::{Context, Result};
use chrono::Utc;

pub fn append(path: &Path, message: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create log directory {}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open log {}", path.display()))?;
    writeln!(file, "{} {message}", Utc::now().to_rfc3339())
        .with_context(|| format!("failed to write log {}", path.display()))
}

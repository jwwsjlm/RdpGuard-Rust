use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use chrono::Utc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationPolicy {
    pub max_bytes: u64,
    pub retained_files: usize,
}

impl RotationPolicy {
    pub fn from_megabytes(max_size_mb: u64, retained_files: usize) -> Self {
        Self {
            max_bytes: max_size_mb.saturating_mul(1024 * 1024),
            retained_files,
        }
    }
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self::from_megabytes(10, 5)
    }
}

pub fn append(path: &Path, message: &str) -> Result<()> {
    append_with_policy(path, message, RotationPolicy::default())
}

pub fn append_with_policy(path: &Path, message: &str, policy: RotationPolicy) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create log directory {}", parent.display()))?;
    }
    let line = format!("{} {message}\n", Utc::now().to_rfc3339());
    rotate_if_needed(path, line.len() as u64, policy)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open log {}", path.display()))?;
    file.write_all(line.as_bytes())
        .with_context(|| format!("failed to write log {}", path.display()))
}

fn rotate_if_needed(path: &Path, incoming_bytes: u64, policy: RotationPolicy) -> Result<()> {
    let current_size = match fs::metadata(path) {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect log {}", path.display()));
        }
    };
    if current_size.saturating_add(incoming_bytes) <= policy.max_bytes {
        return Ok(());
    }

    if policy.retained_files == 0 {
        fs::remove_file(path).with_context(|| format!("failed to reset log {}", path.display()))?;
        return Ok(());
    }

    let oldest = archive_path(path, policy.retained_files);
    if oldest.exists() {
        fs::remove_file(&oldest)
            .with_context(|| format!("failed to remove old log {}", oldest.display()))?;
    }
    for index in (1..policy.retained_files).rev() {
        let source = archive_path(path, index);
        if source.exists() {
            let destination = archive_path(path, index + 1);
            fs::rename(&source, &destination).with_context(|| {
                format!(
                    "failed to rotate log {} to {}",
                    source.display(),
                    destination.display()
                )
            })?;
        }
    }
    let first_archive = archive_path(path, 1);
    fs::rename(path, &first_archive).with_context(|| {
        format!(
            "failed to rotate log {} to {}",
            path.display(),
            first_archive.display()
        )
    })
}

fn archive_path(path: &Path, index: usize) -> PathBuf {
    let mut value = OsString::from(path.as_os_str());
    value.push(format!(".{index}"));
    PathBuf::from(value)
}

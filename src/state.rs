use std::{
    collections::HashMap,
    ffi::OsStr,
    fs::{self, File},
    io::Write,
    net::IpAddr,
    os::windows::ffi::OsStrExt,
    path::Path,
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use windows_sys::Win32::Storage::FileSystem::{
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockRecord {
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub failures: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepeatRecord {
    pub count: u32,
    pub last_blocked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct State {
    pub blocks: HashMap<IpAddr, BlockRecord>,
    pub repeat_history: HashMap<IpAddr, RepeatRecord>,
}

#[derive(Debug)]
pub struct RecoveredState {
    pub state: State,
    pub quarantined_path: Option<std::path::PathBuf>,
    pub recovery_pending: bool,
}

pub fn load_state(path: &Path) -> Result<State> {
    if !path.exists() {
        return Ok(State::default());
    }
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read state {}", path.display()))?;
    let mut state: State = serde_json::from_str(&text)
        .with_context(|| format!("failed to parse state {}", path.display()))?;
    let mut blocks = HashMap::new();
    for (ip, record) in state.blocks.drain() {
        let ip = normalize_ip(ip);
        blocks
            .entry(ip)
            .and_modify(|current: &mut BlockRecord| {
                if record.expires_at > current.expires_at {
                    *current = record.clone();
                }
            })
            .or_insert(record);
    }
    let mut repeat_history = HashMap::new();
    for (ip, record) in state.repeat_history.drain() {
        let ip = normalize_ip(ip);
        repeat_history
            .entry(ip)
            .and_modify(|current: &mut RepeatRecord| {
                if record.last_blocked_at > current.last_blocked_at {
                    *current = record.clone();
                }
            })
            .or_insert(record);
    }
    state.blocks = blocks;
    state.repeat_history = repeat_history;
    Ok(state)
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

pub fn load_state_resilient(path: &Path) -> Result<RecoveredState> {
    let marker = recovery_marker_path(path)?;
    if !path.exists() && marker.exists() {
        return Ok(RecoveredState {
            state: State::default(),
            quarantined_path: None,
            recovery_pending: true,
        });
    }
    match load_state(path) {
        Ok(state) => {
            let _ = fs::remove_file(&marker);
            Ok(RecoveredState {
                state,
                quarantined_path: None,
                recovery_pending: false,
            })
        }
        Err(error) => {
            let timestamp = Utc::now().format("%Y%m%dT%H%M%S%.3fZ");
            let filename = path
                .file_name()
                .and_then(OsStr::to_str)
                .context("invalid state filename")?;
            let quarantine = path.with_file_name(format!("{filename}.corrupt-{timestamp}"));
            fs::write(&marker, b"pending").with_context(|| {
                format!(
                    "STATE001: failed to create recovery marker {}",
                    marker.display()
                )
            })?;
            if let Err(rename_error) = fs::rename(path, &quarantine) {
                let _ = fs::remove_file(&marker);
                return Err(rename_error).with_context(|| {
                    format!(
                        "STATE001: failed to quarantine corrupt state {}: {error:#}",
                        path.display()
                    )
                });
            }
            Ok(RecoveredState {
                state: State::default(),
                quarantined_path: Some(quarantine),
                recovery_pending: true,
            })
        }
    }
}

fn recovery_marker_path(path: &Path) -> Result<std::path::PathBuf> {
    let filename = path
        .file_name()
        .and_then(OsStr::to_str)
        .context("invalid state filename")?;
    Ok(path.with_file_name(format!("{filename}.recovery-pending")))
}

pub fn save_state_atomic(path: &Path, state: &State) -> Result<()> {
    let parent = path.parent().context("state path has no parent")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create state directory {}", parent.display()))?;
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .context("invalid state filename")?;
    let temporary = path.with_file_name(format!("{name}.tmp"));
    let bytes = serde_json::to_vec_pretty(state).context("failed to serialize state")?;

    let mut file = File::create(&temporary)
        .with_context(|| format!("failed to create temporary state {}", temporary.display()))?;
    file.write_all(&bytes)
        .context("failed to write temporary state")?;
    file.sync_all().context("failed to flush temporary state")?;
    drop(file);

    let old_wide: Vec<u16> = temporary.as_os_str().encode_wide().chain(Some(0)).collect();
    let new_wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let result = unsafe {
        MoveFileExW(
            old_wide.as_ptr(),
            new_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        let error = std::io::Error::last_os_error();
        let _ = fs::remove_file(&temporary);
        return Err(error).context("failed to atomically replace state file");
    }
    if let Ok(marker) = recovery_marker_path(path) {
        let _ = fs::remove_file(marker);
    }
    Ok(())
}

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

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub blocks: HashMap<IpAddr, BlockRecord>,
}

pub fn load_state(path: &Path) -> Result<State> {
    if !path.exists() {
        return Ok(State::default());
    }
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read state {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("failed to parse state {}", path.display()))
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
    Ok(())
}

use std::{
    ffi::{OsStr, c_void},
    mem::size_of,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    ptr,
};

use anyhow::{Context, Result, bail};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0},
    Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
    System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW},
    System::Threading::{
        GetCurrentProcess, GetExitCodeProcess, INFINITE, OpenProcessToken, WaitForSingleObject,
    },
    UI::{
        Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW},
        WindowsAndMessaging::SW_SHOWNORMAL,
    },
};

use crate::language::Language;

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

pub fn is_elevated() -> Result<bool> {
    let mut raw_token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) } == 0 {
        return Err(std::io::Error::last_os_error()).context("failed to inspect process elevation");
    }
    let token = OwnedHandle(raw_token);
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast::<c_void>(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error()).context("failed to read process elevation");
    }
    Ok(elevation.TokenIsElevated != 0)
}

pub fn relaunch_elevated(language: Language) -> Result<()> {
    let executable = std::env::current_exe().context("failed to locate monitor executable")?;
    if !is_trusted_monitor_location(&executable)? {
        bail!(
            "ELEV001: refusing to elevate a monitor from an unprotected location; run it from C:\\ProgramData\\RdpGuard or start an administrator PowerShell"
        );
    }
    let executable: Vec<u16> = executable
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let operation: Vec<u16> = "runas".encode_utf16().chain(Some(0)).collect();
    let parameters: Vec<u16> = format!("--language {}", language.cli_value())
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut execute_info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: operation.as_ptr(),
        lpFile: executable.as_ptr(),
        lpParameters: parameters.as_ptr(),
        nShow: SW_SHOWNORMAL,
        ..Default::default()
    };
    if unsafe { ShellExecuteExW(&mut execute_info) } == 0 {
        return Err(std::io::Error::last_os_error())
            .context("administrator elevation was cancelled or failed");
    }
    if execute_info.hProcess.is_null() {
        bail!("administrator elevation returned no process handle");
    }
    let process = OwnedHandle(execute_info.hProcess);
    if unsafe { WaitForSingleObject(process.0, INFINITE) } != WAIT_OBJECT_0 {
        return Err(std::io::Error::last_os_error()).context("failed to wait for elevated monitor");
    }
    let mut exit_code = 0u32;
    if unsafe { GetExitCodeProcess(process.0, &mut exit_code) } == 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to read elevated monitor exit code");
    }
    if exit_code != 0 {
        bail!("elevated monitor failed with exit code {exit_code}");
    }
    Ok(())
}

pub fn is_trusted_monitor_location_for(executable: &Path, program_data: &Path) -> bool {
    let expected = program_data.join("RdpGuard").join("rdpguard-monitor.exe");
    executable
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected.to_string_lossy())
}

fn is_trusted_monitor_location(executable: &Path) -> Result<bool> {
    let program_data = program_data_path()?;
    let executable = executable
        .canonicalize()
        .context("ELEV001: failed to resolve monitor executable path")?;
    let program_data = program_data
        .canonicalize()
        .context("ELEV001: failed to resolve ProgramData path")?;
    Ok(is_trusted_monitor_location_for(&executable, &program_data))
}

fn program_data_path() -> Result<PathBuf> {
    let subkey: Vec<u16> =
        OsStr::new(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")
            .encode_wide()
            .chain(Some(0))
            .collect();
    let value: Vec<u16> = OsStr::new("Common AppData")
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut bytes = 0u32;
    let first = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut bytes,
        )
    };
    if first != 0 || bytes < 2 {
        return Err(std::io::Error::from_raw_os_error(first as i32))
            .context("ELEV001: failed to locate ProgramData in the registry");
    }
    let mut buffer = vec![0u16; bytes.div_ceil(2) as usize];
    let second = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if second != 0 {
        return Err(std::io::Error::from_raw_os_error(second as i32))
            .context("ELEV001: failed to read ProgramData from the registry");
    }
    let length = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    Ok(PathBuf::from(
        String::from_utf16(&buffer[..length])
            .context("ELEV001: ProgramData registry value is not valid UTF-16")?,
    ))
}

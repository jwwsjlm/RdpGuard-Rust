use std::{ffi::c_void, mem::size_of, os::windows::ffi::OsStrExt, ptr};

use anyhow::{Context, Result, bail};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0},
    Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
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

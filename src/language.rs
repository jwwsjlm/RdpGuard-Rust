use anyhow::{Result, bail};
use windows_sys::Win32::Globalization::GetUserDefaultLocaleName;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Chinese,
    English,
}

impl Language {
    pub fn from_locale_name(value: &str) -> Self {
        if value.to_ascii_lowercase().starts_with("zh") {
            Self::Chinese
        } else {
            Self::English
        }
    }

    pub fn detect() -> Self {
        let mut buffer = [0u16; 85];
        let length = unsafe { GetUserDefaultLocaleName(buffer.as_mut_ptr(), buffer.len() as i32) };
        if length <= 1 {
            return Self::English;
        }
        String::from_utf16(&buffer[..length as usize - 1])
            .map(|locale| Self::from_locale_name(&locale))
            .unwrap_or(Self::English)
    }

    pub fn parse_cli(value: &str) -> Result<Self> {
        match value {
            "zh-CN" => Ok(Self::Chinese),
            "en-US" => Ok(Self::English),
            _ => bail!("language must be zh-CN or en-US"),
        }
    }

    pub const fn cli_value(self) -> &'static str {
        match self {
            Self::Chinese => "zh-CN",
            Self::English => "en-US",
        }
    }

    pub const fn toggle(self) -> Self {
        match self {
            Self::Chinese => Self::English,
            Self::English => Self::Chinese,
        }
    }
}

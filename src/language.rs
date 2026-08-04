use anyhow::{Result, bail};
use windows_sys::Win32::Globalization::GetUserDefaultUILanguage;

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
        const PRIMARY_LANGUAGE_MASK: u16 = 0x03ff;
        const CHINESE_PRIMARY_LANGUAGE: u16 = 0x0004;
        let language_id = unsafe { GetUserDefaultUILanguage() };
        if language_id & PRIMARY_LANGUAGE_MASK == CHINESE_PRIMARY_LANGUAGE {
            Self::Chinese
        } else {
            Self::English
        }
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

use std::net::IpAddr;

use anyhow::{Context, Result};
use windows::{
    Win32::{
        Foundation::VARIANT_TRUE,
        NetworkManagement::WindowsFirewall::{
            INetFwPolicy2, INetFwRule, INetFwRules, NET_FW_ACTION_BLOCK, NET_FW_IP_PROTOCOL_ANY,
            NET_FW_PROFILE2_ALL, NET_FW_RULE_DIR_IN, NetFwPolicy2, NetFwRule,
        },
        System::Com::{
            CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
            CoUninitialize,
        },
    },
    core::BSTR,
};

pub trait Firewall {
    fn block(&mut self, ip: IpAddr) -> Result<()>;
    fn unblock(&mut self, ip: IpAddr) -> Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallChange {
    Block(IpAddr),
    Unblock(IpAddr),
}

#[derive(Debug, Default)]
pub struct DryRunFirewall {
    pub changes: Vec<FirewallChange>,
}

impl Firewall for DryRunFirewall {
    fn block(&mut self, ip: IpAddr) -> Result<()> {
        self.changes.push(FirewallChange::Block(ip));
        Ok(())
    }

    fn unblock(&mut self, ip: IpAddr) -> Result<()> {
        self.changes.push(FirewallChange::Unblock(ip));
        Ok(())
    }
}

pub fn rule_name(ip: IpAddr) -> String {
    format!("RdpGuard AutoBlock {ip}")
}

struct ComApartment;

impl ComApartment {
    fn initialize() -> Result<Self> {
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED).ok() }
            .context("failed to initialize COM")?;
        Ok(Self)
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

pub struct WindowsFirewall {
    rules: INetFwRules,
    _apartment: ComApartment,
}

impl WindowsFirewall {
    pub fn new() -> Result<Self> {
        let apartment = ComApartment::initialize()?;
        let policy: INetFwPolicy2 =
            unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }
                .context("failed to open Windows Firewall policy")?;
        let rules = unsafe { policy.Rules() }.context("failed to enumerate firewall rules")?;
        Ok(Self {
            rules,
            _apartment: apartment,
        })
    }

    fn remove_exact(&self, ip: IpAddr) -> Result<()> {
        let name = BSTR::from(rule_name(ip));
        match unsafe { self.rules.Remove(&name) } {
            Ok(()) => Ok(()),
            Err(error) if matches!(error.code().0 as u32, 0x80070002 | 0x80070490) => Ok(()),
            Err(error) => Err(error).context("failed to remove firewall rule"),
        }
    }
}

impl Firewall for WindowsFirewall {
    fn block(&mut self, ip: IpAddr) -> Result<()> {
        self.remove_exact(ip)?;
        let rule: INetFwRule = unsafe { CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER) }
            .context("failed to create firewall rule")?;
        let name = BSTR::from(rule_name(ip));
        let address = BSTR::from(ip.to_string());
        let description =
            BSTR::from("Automatically blocked by RdpGuard after repeated RDP failures");
        let group = BSTR::from("RdpGuard AutoBlock");

        unsafe {
            rule.SetName(&name)?;
            rule.SetDescription(&description)?;
            rule.SetGrouping(&group)?;
            rule.SetRemoteAddresses(&address)?;
            rule.SetDirection(NET_FW_RULE_DIR_IN)?;
            rule.SetAction(NET_FW_ACTION_BLOCK)?;
            rule.SetProtocol(NET_FW_IP_PROTOCOL_ANY.0)?;
            rule.SetProfiles(NET_FW_PROFILE2_ALL.0)?;
            rule.SetEnabled(VARIANT_TRUE)?;
            self.rules.Add(&rule)?;
        }
        Ok(())
    }

    fn unblock(&mut self, ip: IpAddr) -> Result<()> {
        self.remove_exact(ip)
    }
}

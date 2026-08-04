use std::{collections::HashMap, ffi::OsStr, net::IpAddr, os::windows::ffi::OsStrExt};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use windows::{
    Win32::{
        Foundation::VARIANT_TRUE,
        NetworkManagement::WindowsFirewall::{
            INetFwPolicy2, INetFwRule, INetFwRules, NET_FW_ACTION_BLOCK, NET_FW_IP_PROTOCOL_ANY,
            NET_FW_IP_PROTOCOL_TCP, NET_FW_IP_PROTOCOL_UDP, NET_FW_MODIFY_STATE,
            NET_FW_MODIFY_STATE_OK, NET_FW_PROFILE2_ALL, NET_FW_PROFILE2_DOMAIN,
            NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC, NET_FW_RULE_DIR_IN, NetFwPolicy2,
            NetFwRule,
        },
        System::Com::{
            CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
            CoUninitialize, IDispatch,
        },
        System::Ole::IEnumVARIANT,
        System::Variant::{VARIANT, VT_DISPATCH},
    },
    core::{BSTR, Interface},
};
use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RegGetValueW};

use crate::config::BlockScope;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedRule {
    pub ip: IpAddr,
    pub scope: BlockScope,
    pub port: Option<u16>,
    pub expires_at: DateTime<Utc>,
    pub failures: usize,
    pub repeat_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirewallPolicyStatus {
    pub active_profiles: i32,
    pub disabled_profiles: i32,
    pub local_modify_state: NET_FW_MODIFY_STATE,
}

impl FirewallPolicyStatus {
    pub fn local_rules_allowed(self) -> bool {
        self.local_modify_state == NET_FW_MODIFY_STATE_OK
    }
}

pub fn format_rule_metadata(rule: &ManagedRule) -> String {
    let scope = match rule.scope {
        BlockScope::AllInbound => "all_inbound",
        BlockScope::RdpOnly => "rdp_only",
    };
    format!(
        "RdpGuard:v2|ip={}|expires={}|failures={}|repeat={}|scope={}|port={}",
        rule.ip,
        rule.expires_at.to_rfc3339(),
        rule.failures,
        rule.repeat_count,
        scope,
        rule.port
            .map_or_else(|| "0".to_owned(), |port| port.to_string())
    )
}

pub fn parse_rule_metadata(value: &str) -> Option<ManagedRule> {
    let fields = value.strip_prefix("RdpGuard:v2|")?;
    let mut values = std::collections::HashMap::new();
    for field in fields.split('|') {
        let (name, value) = field.split_once('=')?;
        values.insert(name, value);
    }
    let scope = match *values.get("scope")? {
        "all_inbound" => BlockScope::AllInbound,
        "rdp_only" => BlockScope::RdpOnly,
        _ => return None,
    };
    let port = match values.get("port")?.parse::<u16>().ok()? {
        0 => None,
        port => Some(port),
    };
    Some(ManagedRule {
        ip: values.get("ip")?.parse().ok()?,
        expires_at: DateTime::parse_from_rfc3339(values.get("expires")?)
            .ok()?
            .with_timezone(&Utc),
        failures: values.get("failures")?.parse().ok()?,
        repeat_count: values.get("repeat")?.parse().ok()?,
        scope,
        port,
    })
}

pub trait Firewall {
    fn block(&mut self, ip: IpAddr) -> Result<()>;
    fn unblock(&mut self, ip: IpAddr) -> Result<()>;

    fn managed_rules(&mut self) -> Result<Option<Vec<ManagedRule>>> {
        Ok(None)
    }

    fn apply_rule(&mut self, rule: &ManagedRule) -> Result<()> {
        self.block(rule.ip)
    }
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

const RULE_PREFIX: &str = "RdpGuard AutoBlock ";

pub fn detect_rdp_port() -> Result<u16> {
    let subkey: Vec<u16> =
        OsStr::new(r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp")
            .encode_wide()
            .chain(Some(0))
            .collect();
    let value: Vec<u16> = OsStr::new("PortNumber")
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut port = 0u32;
    let mut size = std::mem::size_of::<u32>() as u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            (&mut port as *mut u32).cast(),
            &mut size,
        )
    };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32))
            .context("CFG002: failed to read the RDP port from the registry");
    }
    let port = u16::try_from(port).context("CFG002: registry RDP port is outside 1..65535")?;
    if port == 0 {
        anyhow::bail!("CFG002: registry RDP port is zero");
    }
    Ok(port)
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

pub fn firewall_policy_status() -> Result<FirewallPolicyStatus> {
    let _apartment = ComApartment::initialize().context("FW001: failed to initialize COM")?;
    let policy: INetFwPolicy2 =
        unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }
            .context("FW001: failed to open Windows Firewall policy")?;
    let active_profiles = unsafe { policy.CurrentProfileTypes() }
        .context("FW001: failed to read active firewall profiles")?;
    let mut disabled_profiles = 0;
    for profile in [
        NET_FW_PROFILE2_DOMAIN,
        NET_FW_PROFILE2_PRIVATE,
        NET_FW_PROFILE2_PUBLIC,
    ] {
        if active_profiles & profile.0 != 0
            && unsafe { policy.get_FirewallEnabled(profile) }
                .context("FW001: failed to read firewall profile state")?
                .0
                == 0
        {
            disabled_profiles |= profile.0;
        }
    }
    Ok(FirewallPolicyStatus {
        active_profiles,
        disabled_profiles,
        local_modify_state: unsafe { policy.LocalPolicyModifyState() }
            .context("FW001: failed to read local firewall policy state")?,
    })
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

    fn remove_name(&self, name: &str) -> Result<()> {
        let name = BSTR::from(name);
        match unsafe { self.rules.Remove(&name) } {
            Ok(()) => Ok(()),
            Err(error) if matches!(error.code().0 as u32, 0x80070002 | 0x80070490) => Ok(()),
            Err(error) => Err(error).context("failed to remove firewall rule"),
        }
    }

    fn remove_exact(&self, ip: IpAddr) -> Result<()> {
        for name in [
            rule_name(ip),
            format!("{} TCP", rule_name(ip)),
            format!("{} UDP", rule_name(ip)),
        ] {
            self.remove_name(&name)?;
        }
        Ok(())
    }

    fn add_rule(
        &self,
        name: &str,
        ip: IpAddr,
        description: &str,
        protocol: i32,
        local_port: Option<u16>,
    ) -> Result<()> {
        let rule: INetFwRule = unsafe { CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER) }
            .context("FW001: failed to create firewall rule")?;
        let name = BSTR::from(name);
        let address = BSTR::from(ip.to_string());
        let description = BSTR::from(description);
        let group = BSTR::from("RdpGuard AutoBlock");
        unsafe {
            rule.SetName(&name)?;
            rule.SetDescription(&description)?;
            rule.SetGrouping(&group)?;
            rule.SetRemoteAddresses(&address)?;
            rule.SetDirection(NET_FW_RULE_DIR_IN)?;
            rule.SetAction(NET_FW_ACTION_BLOCK)?;
            rule.SetProtocol(protocol)?;
            if let Some(port) = local_port {
                rule.SetLocalPorts(&BSTR::from(port.to_string()))?;
            }
            rule.SetProfiles(NET_FW_PROFILE2_ALL.0)?;
            rule.SetEnabled(VARIANT_TRUE)?;
            self.rules.Add(&rule)?;
        }
        Ok(())
    }

    fn enumerate_managed_rules(&self) -> Result<Vec<ManagedRule>> {
        let unknown = unsafe { self.rules._NewEnum() }
            .context("FW001: failed to create firewall rule enumerator")?;
        let enumerator: IEnumVARIANT = unknown
            .cast()
            .context("FW001: firewall rule enumerator has an unexpected type")?;
        let mut found: HashMap<IpAddr, (ManagedRule, bool, bool, bool)> = HashMap::new();
        loop {
            let mut variants = [VARIANT::default()];
            let mut fetched = 0u32;
            let result = unsafe { enumerator.Next(&mut variants, &mut fetched) };
            if fetched == 0 {
                break;
            }
            result
                .ok()
                .context("FW001: failed while enumerating firewall rules")?;
            let inner = unsafe { &*variants[0].Anonymous.Anonymous };
            if inner.vt != VT_DISPATCH {
                continue;
            }
            let dispatch: IDispatch = unsafe { (*inner.Anonymous.pdispVal).clone() }
                .context("FW001: firewall rule enumeration returned an empty dispatch")?;
            let rule: INetFwRule = dispatch
                .cast()
                .context("FW001: enumerated firewall item was not a rule")?;
            let name = unsafe { rule.Name() }?.to_string();
            if !name.starts_with(RULE_PREFIX) {
                continue;
            }
            let description = unsafe { rule.Description() }
                .map(|value| value.to_string())
                .unwrap_or_default();
            let metadata = parse_rule_metadata(&description).or_else(|| {
                let candidate = name
                    .strip_prefix(RULE_PREFIX)?
                    .trim_end_matches(" TCP")
                    .trim_end_matches(" UDP");
                let ip = candidate.parse().ok()?;
                Some(ManagedRule {
                    ip,
                    scope: BlockScope::AllInbound,
                    port: None,
                    // Legacy rules have no trustworthy expiration metadata. A valid
                    // state file will cause them to be replaced; corrupt-state recovery
                    // deliberately treats them as expired so they cannot become permanent.
                    expires_at: DateTime::<Utc>::UNIX_EPOCH,
                    failures: 0,
                    repeat_count: 1,
                })
            });
            let Some(metadata) = metadata else { continue };
            let protocol = unsafe { rule.Protocol() }.unwrap_or(NET_FW_IP_PROTOCOL_ANY.0);
            let port_matches = metadata.port.is_none_or(|expected| {
                unsafe { rule.LocalPorts() }
                    .ok()
                    .and_then(|value| value.to_string().parse::<u16>().ok())
                    == Some(expected)
            });
            let base_valid = unsafe { rule.Direction() }.ok() == Some(NET_FW_RULE_DIR_IN)
                && unsafe { rule.Action() }.ok() == Some(NET_FW_ACTION_BLOCK)
                && unsafe { rule.Enabled() }.is_ok_and(|enabled| enabled.0 != 0)
                && unsafe { rule.Profiles() }.ok() == Some(NET_FW_PROFILE2_ALL.0)
                && unsafe { rule.RemoteAddresses() }.is_ok_and(|value| {
                    value.to_string().parse::<IpAddr>().ok() == Some(metadata.ip)
                });
            let entry = found
                .entry(metadata.ip)
                .or_insert((metadata.clone(), false, false, false));
            entry.0 = metadata;
            entry.1 |= base_valid && port_matches && protocol == NET_FW_IP_PROTOCOL_TCP.0;
            entry.2 |= base_valid && port_matches && protocol == NET_FW_IP_PROTOCOL_UDP.0;
            entry.3 |= base_valid && protocol == NET_FW_IP_PROTOCOL_ANY.0;
        }
        Ok(found
            .into_values()
            .map(|(mut rule, tcp, udp, all_valid)| {
                if rule.scope == BlockScope::RdpOnly && !(tcp && udp) {
                    rule.port = None;
                } else if rule.scope == BlockScope::AllInbound && !all_valid {
                    rule.port = Some(1);
                }
                rule
            })
            .collect())
    }
}

impl Firewall for WindowsFirewall {
    fn block(&mut self, ip: IpAddr) -> Result<()> {
        self.remove_exact(ip)?;
        self.add_rule(
            &rule_name(ip),
            ip,
            "Automatically blocked by RdpGuard after repeated RDP failures",
            NET_FW_IP_PROTOCOL_ANY.0,
            None,
        )
    }

    fn unblock(&mut self, ip: IpAddr) -> Result<()> {
        self.remove_exact(ip)
    }

    fn managed_rules(&mut self) -> Result<Option<Vec<ManagedRule>>> {
        self.enumerate_managed_rules().map(Some)
    }

    fn apply_rule(&mut self, rule: &ManagedRule) -> Result<()> {
        self.remove_exact(rule.ip)?;
        let description = format_rule_metadata(rule);
        match rule.scope {
            BlockScope::AllInbound => self.add_rule(
                &rule_name(rule.ip),
                rule.ip,
                &description,
                NET_FW_IP_PROTOCOL_ANY.0,
                None,
            ),
            BlockScope::RdpOnly => {
                let port = rule
                    .port
                    .context("CFG002: rdp_only rule requires an RDP port")?;
                self.add_rule(
                    &format!("{} TCP", rule_name(rule.ip)),
                    rule.ip,
                    &description,
                    NET_FW_IP_PROTOCOL_TCP.0,
                    Some(port),
                )?;
                if let Err(error) = self.add_rule(
                    &format!("{} UDP", rule_name(rule.ip)),
                    rule.ip,
                    &description,
                    NET_FW_IP_PROTOCOL_UDP.0,
                    Some(port),
                ) {
                    let _ = self.remove_exact(rule.ip);
                    return Err(error)
                        .context("FW001: failed to create UDP half of RDP-only block");
                }
                Ok(())
            }
        }
    }
}

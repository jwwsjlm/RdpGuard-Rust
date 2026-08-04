use std::{collections::HashMap, net::IpAddr};

use chrono::{DateTime, Duration, Utc};

use crate::config::Config;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Block {
        ip: IpAddr,
        failures: usize,
        expires_at: DateTime<Utc>,
    },
    Unblock {
        ip: IpAddr,
    },
}

pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

pub fn is_public_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && !ip.is_unspecified()
                && !ip.is_broadcast()
                && !ip.is_documentation()
        }
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_public_unicast(IpAddr::V4(mapped));
            }
            !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_unique_local()
                && !ip.is_unicast_link_local()
        }
    }
}

pub fn failure_counts<I>(ips: I) -> HashMap<IpAddr, usize>
where
    I: IntoIterator<Item = IpAddr>,
{
    let mut counts = HashMap::new();
    for ip in ips {
        *counts.entry(normalize_ip(ip)).or_insert(0) += 1;
    }
    counts
}

pub fn next_repeat_count(
    now: DateTime<Utc>,
    previous: Option<(u32, DateTime<Utc>)>,
    config: &Config,
) -> u32 {
    match previous {
        Some((count, last))
            if now.signed_duration_since(last)
                <= Duration::days(config.repeat_reset_days as i64) =>
        {
            count.saturating_add(1)
        }
        _ => 1,
    }
}

pub fn block_duration(config: &Config, repeat_count: u32) -> Duration {
    let exponent = repeat_count.saturating_sub(1).min(31);
    let multiplier = u64::from(config.repeat_block_multiplier).saturating_pow(exponent);
    let minutes = config
        .block_minutes
        .saturating_mul(multiplier)
        .min(config.max_block_minutes);
    Duration::minutes(minutes.min(i64::MAX as u64) as i64)
}

pub fn plan_actions(
    now: DateTime<Utc>,
    counts: &HashMap<IpAddr, usize>,
    active: &HashMap<IpAddr, DateTime<Utc>>,
    config: &Config,
) -> Vec<Action> {
    let mut actions = Vec::new();
    let mut active_ips: Vec<_> = active.iter().collect();
    active_ips.sort_by_key(|(ip, _)| **ip);

    for (&ip, &expires_at) in active_ips {
        if expires_at <= now {
            actions.push(Action::Unblock { ip });
        }
    }

    let mut counted_ips: Vec<_> = counts.iter().collect();
    counted_ips.sort_by_key(|(ip, _)| **ip);
    for (&ip, &failures) in counted_ips {
        if failures < config.failure_threshold
            || !is_public_unicast(ip)
            || config.is_whitelisted(ip)
            || active.contains_key(&ip)
        {
            continue;
        }
        actions.push(Action::Block {
            ip,
            failures,
            expires_at: now + Duration::minutes(config.block_minutes as i64),
        });
    }

    actions
}

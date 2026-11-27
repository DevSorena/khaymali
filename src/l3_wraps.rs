//! Layer-3 GRE Carrier Wraps, Path MTU Keeper, `/30` Pair Allocator & Carrier Advisor.
//!
//! Ported from Khaymali's `carrier6.go`, `carrier.go`, `gre_mtu.go`, `gre_pair.go`, and
//! `carrieradvisor.go`.

use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Mutex;

pub const MTU_DIRECT_GRE: u16 = 1380;
pub const MTU_WSS_WRAP: u16 = 1360;
pub const MTU_MIN_SAFE: u16 = 1280;
pub const DEFAULT_MTU_FILE: &str = "/var/lib/khaymali/gre_mtu";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GreWrapKind {
    Direct { local_v4: Ipv4Addr, remote_v4: Ipv4Addr },
    Wss { remote_host: String, port: u16, sni: String },
    SixToFour { local_v4: Ipv4Addr, remote_v4: Ipv4Addr },
    FourInSix { local_v6: Ipv6Addr, remote_v6: Ipv6Addr },
}

impl GreWrapKind {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Direct { .. } => "direct",
            Self::Wss { .. } => "wss",
            Self::SixToFour { .. } => "6to4",
            Self::FourInSix { .. } => "4in6",
        }
    }

    pub fn recommended_mtu(&self) -> u16 {
        match self {
            Self::Wss { .. } => MTU_WSS_WRAP,
            Self::Direct { .. } | Self::SixToFour { .. } | Self::FourInSix { .. } => MTU_DIRECT_GRE,
        }
    }

    pub fn six_to_four_inner_v6(local_v4: Ipv4Addr, remote_v4: Ipv4Addr) -> (&'static str, &'static str) {
        if local_v4 <= remote_v4 {
            ("fd64:6873:0:1::1", "fd64:6873:0:1::2")
        } else {
            ("fd64:6873:0:1::2", "fd64:6873:0:1::1")
        }
    }

    pub fn render_apply_commands(
        &self,
        if_name: &str,
        inner_local: Ipv4Addr,
        inner_remote: Ipv4Addr,
        mtu: u16,
    ) -> Result<Vec<Vec<String>>> {
        crate::l3::validate_if_name(if_name)?;
        let mtu = mtu.clamp(MTU_MIN_SAFE, 1420);
        let mss = mtu.saturating_sub(40);
        let sit_if = format!("kh6-{}", &if_name[..if_name.len().min(10)]);
        let mut cmds: Vec<Vec<String>> = Vec::new();

        cmds.push(vec!["ip".into(), "link".into(), "del".into(), if_name.into()]);
        cmds.push(vec!["ip".into(), "link".into(), "del".into(), sit_if.clone()]);

        match self {
            Self::Direct { local_v4, remote_v4 } => {
                cmds.push(vec![
                    "ip".into(), "tunnel".into(), "add".into(), if_name.into(),
                    "mode".into(), "gre".into(),
                    "local".into(), local_v4.to_string(),
                    "remote".into(), remote_v4.to_string(),
                    "ttl".into(), "255".into(),
                ]);
                cmds.push(vec![
                    "iptables".into(), "-I".into(), "INPUT".into(), "-p".into(), "47".into(),
                    "-s".into(), remote_v4.to_string(), "-j".into(), "ACCEPT".into(),
                ]);
            }
            Self::SixToFour { local_v4, remote_v4 } => {
                let (v6_loc, v6_rem) = Self::six_to_four_inner_v6(*local_v4, *remote_v4);
                cmds.push(vec![
                    "ip".into(), "tunnel".into(), "add".into(), sit_if.clone(),
                    "mode".into(), "sit".into(),
                    "local".into(), local_v4.to_string(),
                    "remote".into(), remote_v4.to_string(),
                    "ttl".into(), "255".into(),
                ]);
                cmds.push(vec![
                    "ip".into(), "addr".into(), "add".into(),
                    format!("{v6_loc}/64"), "dev".into(), sit_if.clone(),
                ]);
                cmds.push(vec!["ip".into(), "link".into(), "set".into(), sit_if.clone(), "up".into()]);
                cmds.push(vec![
                    "ip".into(), "-6".into(), "tunnel".into(), "add".into(), if_name.into(),
                    "mode".into(), "ip6gre".into(),
                    "local".into(), v6_loc.into(),
                    "remote".into(), v6_rem.into(),
                    "dev".into(), sit_if,
                ]);
                cmds.push(vec![
                    "iptables".into(), "-I".into(), "INPUT".into(), "-p".into(), "41".into(),
                    "-s".into(), remote_v4.to_string(), "-j".into(), "ACCEPT".into(),
                ]);
            }
            Self::FourInSix { local_v6, remote_v6 } => {
                cmds.push(vec![
                    "ip".into(), "-6".into(), "tunnel".into(), "add".into(), if_name.into(),
                    "mode".into(), "ip6gre".into(),
                    "local".into(), local_v6.to_string(),
                    "remote".into(), remote_v6.to_string(),
                ]);
                cmds.push(vec![
                    "ip6tables".into(), "-I".into(), "INPUT".into(), "-p".into(), "47".into(),
                    "-s".into(), remote_v6.to_string(), "-j".into(), "ACCEPT".into(),
                ]);
            }
            Self::Wss { .. } => {
                cmds.push(vec![
                    "ip".into(), "tuntap".into(), "add".into(), "dev".into(),
                    if_name.into(), "mode".into(), "tun".into(),
                ]);
            }
        }

        cmds.push(vec![
            "ip".into(), "addr".into(), "replace".into(),
            format!("{inner_local}/30"), "dev".into(), if_name.into(),
        ]);
        cmds.push(vec![
            "ip".into(), "link".into(), "set".into(), if_name.into(),
            "mtu".into(), mtu.to_string(), "up".into(),
        ]);
        cmds.push(vec![
            "ip".into(), "route".into(), "replace".into(),
            format!("{inner_remote}/32"), "dev".into(), if_name.into(),
            "src".into(), inner_local.to_string(),
        ]);
        cmds.push(vec![
            "iptables".into(), "-t".into(), "mangle".into(), "-A".into(), "FORWARD".into(),
            "-o".into(), if_name.into(), "-p".into(), "tcp".into(),
            "--tcp-flags".into(), "SYN,RST".into(), "SYN".into(),
            "-j".into(), "TCPMSS".into(), "--set-mss".into(), mss.to_string(),
        ]);
        Ok(cmds)
    }

    pub fn apply(
        &self,
        if_name: &str,
        inner_local: Ipv4Addr,
        inner_remote: Ipv4Addr,
        mtu: u16,
    ) -> Result<()> {
        let cmds = self.render_apply_commands(if_name, inner_local, inner_remote, mtu)?;
        for (idx, argv) in cmds.iter().enumerate() {
            let status = Command::new(&argv[0])
                .args(&argv[1..])
                .status()
                .with_context(|| format!("failed to run {}", argv.join(" ")))?;
            if idx >= 2 && !status.success() {
                bail!("command failed: {}", argv.join(" "));
            }
        }
        Ok(())
    }
}

pub struct PathMtuKeeper {
    current: AtomicU16,
    state_file: String,
}

impl PathMtuKeeper {
    pub fn new(state_file: impl Into<String>, initial: u16) -> Self {
        let state_file = state_file.into();
        let loaded = std::fs::read_to_string(&state_file)
            .ok()
            .and_then(|s| s.trim().parse::<u16>().ok())
            .filter(|&v| (MTU_MIN_SAFE..=1420).contains(&v))
            .unwrap_or(initial.clamp(MTU_MIN_SAFE, 1420));
        Self { current: AtomicU16::new(loaded), state_file }
    }

    pub fn current(&self) -> u16 {
        self.current.load(Ordering::Relaxed)
    }

    pub fn set(&self, mtu: u16) -> Result<u16> {
        let clamped = mtu.clamp(MTU_MIN_SAFE, 1420);
        self.current.store(clamped, Ordering::Relaxed);
        if let Some(p) = std::path::Path::new(&self.state_file).parent() {
            let _ = std::fs::create_dir_all(p);
        }
        std::fs::write(&self.state_file, format!("{clamped}\n"))?;
        Ok(clamped)
    }

    pub fn step_down(&self) -> u16 {
        let next = match self.current() {
            1361..=u16::MAX => 1360,
            1341..=1360 => 1340,
            1301..=1340 => 1300,
            _ => MTU_MIN_SAFE,
        };
        let _ = self.set(next);
        next
    }

    pub fn mss_clamp_value(&self) -> u16 {
        self.current().saturating_sub(40)
    }
}

pub struct GrePairAllocator;

impl GrePairAllocator {
    pub fn cidr_contains(net: Ipv4Addr, prefix: u8, ip: Ipv4Addr) -> bool {
        let mask = if prefix == 0 {
            0u32
        } else if prefix >= 32 {
            u32::MAX
        } else {
            !0u32 << (32 - prefix)
        };
        (u32::from(net) & mask) == (u32::from(ip) & mask)
    }

    pub fn allocate_free(used_cidrs: &[(Ipv4Addr, u8)]) -> Result<(Ipv4Addr, Ipv4Addr)> {
        for third in 10u8..=250u8 {
            for base in (0u8..=252u8).step_by(4) {
                let a = Ipv4Addr::new(10, 11, third, base + 1);
                let b = Ipv4Addr::new(10, 11, third, base + 2);
                let clash = used_cidrs.iter().any(|&(net, pfx)| {
                    Self::cidr_contains(net, pfx, a) || Self::cidr_contains(net, pfx, b)
                });
                if !clash {
                    return Ok((a, b));
                }
            }
        }
        bail!("no free /30 GRE inner IPv4 pair available")
    }
}

pub const ADV_MIN_SAMPLES: u32 = 20;
pub const ADV_BAD_RATIO: f64 = 0.80;
pub const ADV_MAX_SAMPLES: u32 = 2880;

#[derive(Clone, Copy, Debug, Default)]
pub struct CarrierStat {
    pub up: u32,
    pub degraded: u32,
    pub down: u32,
    pub last_seen_unix: u64,
}

impl CarrierStat {
    pub fn total(&self) -> u32 {
        self.up + self.degraded + self.down
    }
    pub fn ratio(&self) -> f64 {
        let t = self.total();
        if t == 0 {
            0.0
        } else {
            (self.up + self.degraded) as f64 / t as f64
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CarrierAdvice {
    pub level: &'static str,
    pub message: String,
    pub suggest: Option<String>,
}

pub struct CarrierAdvisor {
    stats: Mutex<HashMap<String, CarrierStat>>,
}

impl CarrierAdvisor {
    pub fn new() -> Self {
        Self { stats: Mutex::new(HashMap::new()) }
    }

    pub fn record(&self, carrier: &str, state: &str, now_unix: u64) {
        if carrier.is_empty() {
            return;
        }
        let mut g = self.stats.lock().unwrap();
        let s = g.entry(carrier.to_string()).or_default();
        match state {
            "healthy" | "up" => s.up += 1,
            "degraded" => s.degraded += 1,
            _ => s.down += 1,
        }
        if s.total() > ADV_MAX_SAMPLES {
            s.up /= 2;
            s.degraded /= 2;
            s.down /= 2;
        }
        s.last_seen_unix = now_unix;
    }

    pub fn snapshot(&self) -> HashMap<String, CarrierStat> {
        self.stats.lock().unwrap().clone()
    }

    pub fn advise(&self, active: &str, candidates: &[String]) -> CarrierAdvice {
        let snap = self.snapshot();
        Self::advise_from_stats(active, candidates, &snap)
    }

    pub fn advise_from_stats(
        active: &str,
        candidates: &[String],
        stats: &HashMap<String, CarrierStat>,
    ) -> CarrierAdvice {
        let cur = stats.get(active).copied().unwrap_or_default();
        if cur.total() < ADV_MIN_SAMPLES {
            return CarrierAdvice {
                level: "info",
                message: format!(
                    "Collecting data for carrier '{active}' ({}/{ADV_MIN_SAMPLES} samples).",
                    cur.total()
                ),
                suggest: None,
            };
        }
        if cur.ratio() >= ADV_BAD_RATIO {
            return CarrierAdvice {
                level: "ok",
                message: format!(
                    "Carrier '{active}' is stable ({:.0}% up).",
                    cur.ratio() * 100.0
                ),
                suggest: None,
            };
        }
        let mut alts: Vec<(String, f64, bool)> = candidates
            .iter()
            .filter(|c| c.as_str() != active)
            .map(|c| match stats.get(c) {
                Some(st) if st.total() >= ADV_MIN_SAMPLES => (c.clone(), st.ratio(), true),
                _ => (c.clone(), 0.0, false),
            })
            .collect();
        alts.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| b.1.total_cmp(&a.1)));
        CarrierAdvice {
            level: "warn",
            message: format!(
                "Carrier '{active}' was down in {:.0}% of recent samples.",
                (1.0 - cur.ratio()) * 100.0
            ),
            suggest: alts.first().map(|a| a.0.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn six_to_four_and_four_in_six_render_valid_commands() {
        let wrap64 = GreWrapKind::SixToFour {
            local_v4: Ipv4Addr::new(198, 51, 100, 1),
            remote_v4: Ipv4Addr::new(203, 0, 113, 2),
        };
        let cmds = wrap64
            .render_apply_commands("gre-t1", Ipv4Addr::new(10, 11, 10, 1), Ipv4Addr::new(10, 11, 10, 2), 1380)
            .unwrap();
        let flat = cmds.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
        assert!(flat.contains("mode sit") && flat.contains("mode ip6gre") && flat.contains("-p 41") && flat.contains("--set-mss 1340"));

        let wrap46 = GreWrapKind::FourInSix {
            local_v6: "2001:db8::1".parse().unwrap(),
            remote_v6: "2001:db8::2".parse().unwrap(),
        };
        let cmds46 = wrap46
            .render_apply_commands("gre-t2", Ipv4Addr::new(10, 11, 10, 5), Ipv4Addr::new(10, 11, 10, 6), 1380)
            .unwrap();
        let flat46 = cmds46.iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\n");
        assert!(flat46.contains("ip6tables -I INPUT -p 47"));
    }

    #[test]
    fn allocator_and_advisor_work() {
        let (a, b) = GrePairAllocator::allocate_free(&[(Ipv4Addr::new(10, 11, 10, 0), 24)]).unwrap();
        assert_eq!((a, b), (Ipv4Addr::new(10, 11, 11, 1), Ipv4Addr::new(10, 11, 11, 2)));

        let adv = CarrierAdvisor::new();
        for i in 0..25 {
            adv.record("direct", if i < 10 { "healthy" } else { "down" }, 1000 + i);
            adv.record("wss", "healthy", 1000 + i);
        }
        let res = adv.advise("direct", &["direct".into(), "wss".into(), "6to4".into()]);
        assert_eq!(res.level, "warn");
        assert_eq!(res.suggest.as_deref(), Some("wss"));
    }
}

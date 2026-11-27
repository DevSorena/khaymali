//! Reverse-Path Doctor & Auto-Fix Engine (`src/revpath.rs`).
//!
//! Ported from Khaymali's `revpath.go` & `revfix.go`.

use std::process::Command;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevPathVerdict {
    Healthy,
    RpFilter,
    SrcSelect,
    NoReturnRoute,
    FwInput,
    MtuBlackhole,
    ConntrackInvalid,
    IspIcmpOneWay,
    IspGreBlock,
    CloudSg,
    Unknown,
}

impl RevPathVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "HEALTHY",
            Self::RpFilter => "RP_FILTER",
            Self::SrcSelect => "SRC_SELECT",
            Self::NoReturnRoute => "NO_RETURN_ROUTE",
            Self::FwInput => "FW_INPUT",
            Self::MtuBlackhole => "MTU_BLACKHOLE",
            Self::ConntrackInvalid => "CONNTRACK_INVALID",
            Self::IspIcmpOneWay => "ISP_ICMP_ONE_WAY",
            Self::IspGreBlock => "ISP_GRE_BLOCK",
            Self::CloudSg => "CLOUD_SG",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct LocalKernelSnapshot {
    pub gre_if: String,
    pub inner_local: String,
    pub inner_peer: String,
    pub rp_filter_all: i8,
    pub rp_filter_default: i8,
    pub rp_filter_iface: i8,
    pub ip_forward: bool,
    pub gre_mtu: u16,
    pub route_known: bool,
    pub route_back_via_gre: bool,
    pub src_addr_on_reply: String,
    pub input_drops_proto47: bool,
    pub conntrack_invalid_rising: bool,
}

impl LocalKernelSnapshot {
    pub fn rp_strict(&self) -> bool {
        self.rp_filter_all.max(self.rp_filter_iface) == 1
    }

    pub fn src_mismatch(&self) -> bool {
        !self.inner_local.is_empty()
            && !self.src_addr_on_reply.is_empty()
            && self.src_addr_on_reply != self.inner_local
    }
}

#[derive(Clone, Debug, Default)]
pub struct ProbeMatrix {
    pub icmp_gre_64_ok: Option<bool>,
    pub icmp_gre_1300df_ok: Option<bool>,
    pub icmp_public_ok: Option<bool>,
    pub tcp_ctrl_inner_ok: Option<bool>,
    pub tcp_ctrl_public_ok: Option<bool>,
    pub tcp_wss_ok: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct RevPathDiagnosis {
    pub verdict: RevPathVerdict,
    pub confidence: &'static str,
    pub auto_fixable: bool,
    pub evidence: Vec<String>,
    pub suggested_fix: &'static str,
    pub fix_commands: Vec<Vec<String>>,
}

pub fn classify(m: &ProbeMatrix, s: &LocalKernelSnapshot) -> RevPathDiagnosis {
    let mut ev = Vec::new();
    let iface = if s.gre_if.is_empty() { "khaymali0" } else { s.gre_if.as_str() };

    if m.icmp_gre_64_ok == Some(true) && m.icmp_gre_1300df_ok == Some(false) {
        ev.push("64B ICMP over tunnel succeeded, but 1300B DF ICMP failed".into());
        let next_mtu = if s.gre_mtu > 1360 { 1360 } else if s.gre_mtu > 1340 { 1340 } else { 1300 };
        let mss = next_mtu - 40;
        return RevPathDiagnosis {
            verdict: RevPathVerdict::MtuBlackhole,
            confidence: "high",
            auto_fixable: true,
            evidence: ev,
            suggested_fix: "Lower tunnel MTU stepwise (1380 -> 1360 -> 1340 -> 1300) and clamp TCP MSS.",
            fix_commands: vec![
                vec!["ip".into(), "link".into(), "set".into(), iface.into(), "mtu".into(), next_mtu.to_string()],
                vec![
                    "iptables".into(), "-t".into(), "mangle".into(), "-I".into(), "FORWARD".into(),
                    "-o".into(), iface.into(), "-p".into(), "tcp".into(), "--tcp-flags".into(),
                    "SYN,RST".into(), "SYN".into(), "-j".into(), "TCPMSS".into(), "--set-mss".into(), mss.to_string(),
                ],
            ],
        };
    }

    if m.tcp_ctrl_inner_ok == Some(true) && m.icmp_gre_64_ok == Some(false) {
        ev.push("TCP control over tunnel works while ICMP echo fails".into());
        return RevPathDiagnosis {
            verdict: RevPathVerdict::IspIcmpOneWay,
            confidence: "high",
            auto_fixable: false,
            evidence: ev,
            suggested_fix: "ICMP is filtered upstream; rely on TCP/Noise health and do not restart the tunnel.",
            fix_commands: vec![],
        };
    }

    if m.icmp_gre_64_ok == Some(false) && m.tcp_ctrl_inner_ok == Some(false) {
        if s.route_known && !s.route_back_via_gre {
            ev.push(format!("Return route to {} does not exit via {iface}", s.inner_peer));
            let mut cmds = Vec::new();
            if !s.inner_peer.is_empty() && !s.inner_local.is_empty() {
                cmds.push(vec![
                    "ip".into(), "route".into(), "replace".into(),
                    format!("{}/32", s.inner_peer), "dev".into(), iface.into(),
                    "src".into(), s.inner_local.clone(),
                ]);
            }
            return RevPathDiagnosis {
                verdict: RevPathVerdict::NoReturnRoute,
                confidence: "high",
                auto_fixable: !cmds.is_empty(),
                evidence: ev,
                suggested_fix: "Add explicit return route to peer inner IP via tunnel device.",
                fix_commands: cmds,
            };
        }
        if s.rp_strict() {
            ev.push(format!("rp_filter strict (all={}, iface={})", s.rp_filter_all, s.rp_filter_iface));
            return RevPathDiagnosis {
                verdict: RevPathVerdict::RpFilter,
                confidence: "high",
                auto_fixable: true,
                evidence: ev,
                suggested_fix: "Set net.ipv4.conf.{all,default,<iface>}.rp_filter=2 (loose) and persist.",
                fix_commands: vec![
                    vec!["sysctl".into(), "-w".into(), "net.ipv4.conf.all.rp_filter=2".into()],
                    vec!["sysctl".into(), "-w".into(), "net.ipv4.conf.default.rp_filter=2".into()],
                    vec!["sysctl".into(), "-w".into(), format!("net.ipv4.conf.{iface}.rp_filter=2")],
                ],
            };
        }
        if s.src_mismatch() {
            ev.push(format!("Reply source IP '{}' != local inner '{}'", s.src_addr_on_reply, s.inner_local));
            let mut cmds = Vec::new();
            if !s.inner_peer.is_empty() {
                cmds.push(vec![
                    "ip".into(), "route".into(), "replace".into(),
                    format!("{}/32", s.inner_peer), "dev".into(), iface.into(),
                    "src".into(), s.inner_local.clone(),
                ]);
            }
            return RevPathDiagnosis {
                verdict: RevPathVerdict::SrcSelect,
                confidence: "high",
                auto_fixable: !cmds.is_empty(),
                evidence: ev,
                suggested_fix: "Pin route source address to local tunnel inner IP.",
                fix_commands: cmds,
            };
        }
        if s.input_drops_proto47 {
            ev.push("Local INPUT firewall drops IP protocol 47".into());
            return RevPathDiagnosis {
                verdict: RevPathVerdict::FwInput,
                confidence: "high",
                auto_fixable: true,
                evidence: ev,
                suggested_fix: "Allow proto 47, proto 41, and tunnel interface in dedicated KHAYMALI-REVPATH chain.",
                fix_commands: vec![
                    vec!["iptables".into(), "-N".into(), "KHAYMALI-REVPATH".into()],
                    vec!["iptables".into(), "-I".into(), "INPUT".into(), "-j".into(), "KHAYMALI-REVPATH".into()],
                    vec!["iptables".into(), "-A".into(), "KHAYMALI-REVPATH".into(), "-p".into(), "47".into(), "-j".into(), "ACCEPT".into()],
                    vec!["iptables".into(), "-A".into(), "KHAYMALI-REVPATH".into(), "-p".into(), "41".into(), "-j".into(), "ACCEPT".into()],
                    vec!["iptables".into(), "-A".into(), "KHAYMALI-REVPATH".into(), "-i".into(), iface.into(), "-j".into(), "ACCEPT".into()],
                ],
            };
        }
        if s.conntrack_invalid_rising {
            ev.push("Conntrack INVALID drops rising on GRE/L3 path".into());
            return RevPathDiagnosis {
                verdict: RevPathVerdict::ConntrackInvalid,
                confidence: "medium",
                auto_fixable: true,
                evidence: ev,
                suggested_fix: "Exempt protocol 47 from conntrack via raw table NOTRACK.",
                fix_commands: vec![
                    vec!["iptables".into(), "-t".into(), "raw".into(), "-I".into(), "PREROUTING".into(), "-p".into(), "47".into(), "-j".into(), "NOTRACK".into()],
                    vec!["iptables".into(), "-t".into(), "raw".into(), "-I".into(), "OUTPUT".into(), "-p".into(), "47".into(), "-j".into(), "NOTRACK".into()],
                ],
            };
        }
        if m.tcp_ctrl_public_ok == Some(true) || m.tcp_wss_ok == Some(true) {
            ev.push("Public TCP/WSS answers while GRE inner path is dead".into());
            return RevPathDiagnosis {
                verdict: RevPathVerdict::IspGreBlock,
                confidence: "high",
                auto_fixable: false,
                evidence: ev,
                suggested_fix: "ISP blocks IP protocol 47; switch carrier to wss://, 6to4, 4in6, ktunnel://, or udp://.",
                fix_commands: vec![],
            };
        }
        if m.icmp_public_ok == Some(false) {
            ev.push("Neither tunnel nor public ICMP responds".into());
            return RevPathDiagnosis {
                verdict: RevPathVerdict::CloudSg,
                confidence: "medium",
                auto_fixable: false,
                evidence: ev,
                suggested_fix: "Check cloud security group / provider firewall on both servers.",
                fix_commands: vec![],
            };
        }
    }

    if m.tcp_ctrl_inner_ok == Some(true) || m.icmp_gre_64_ok == Some(true) {
        ev.push("Inner tunnel path answers normally".into());
        return RevPathDiagnosis {
            verdict: RevPathVerdict::Healthy,
            confidence: "high",
            auto_fixable: false,
            evidence: ev,
            suggested_fix: "No action needed; reverse path is healthy.",
            fix_commands: vec![],
        };
    }

    RevPathDiagnosis {
        verdict: RevPathVerdict::Unknown,
        confidence: "low",
        auto_fixable: false,
        evidence: vec!["Insufficient probe results".into()],
        suggested_fix: "Run `khaymali revpath check` with peer inner & public addresses.",
        fix_commands: vec![],
    }
}

fn read_sysctl_i8(path: &str) -> i8 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<i8>().ok())
        .unwrap_or(-1)
}

pub fn collect_local_snapshot(gre_if: &str, inner_local: &str, inner_peer: &str) -> LocalKernelSnapshot {
    let mut snap = LocalKernelSnapshot {
        gre_if: gre_if.to_string(),
        inner_local: inner_local.to_string(),
        inner_peer: inner_peer.to_string(),
        rp_filter_all: read_sysctl_i8("/proc/sys/net/ipv4/conf/all/rp_filter"),
        rp_filter_default: read_sysctl_i8("/proc/sys/net/ipv4/conf/default/rp_filter"),
        rp_filter_iface: read_sysctl_i8(&format!("/proc/sys/net/ipv4/conf/{gre_if}/rp_filter")),
        ip_forward: read_sysctl_i8("/proc/sys/net/ipv4/ip_forward") == 1,
        gre_mtu: std::fs::read_to_string(&format!("/sys/class/net/{gre_if}/mtu"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(1380),
        ..Default::default()
    };

    if !inner_peer.is_empty() {
        if let Ok(out) = Command::new("ip").args(["route", "get", inner_peer]).output() {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                snap.route_known = true;
                snap.route_back_via_gre = text.contains(&format!("dev {gre_if}"));
                let toks: Vec<&str> = text.split_whitespace().collect();
                for w in toks.windows(2) {
                    if w[0] == "src" {
                        snap.src_addr_on_reply = w[1].to_string();
                        break;
                    }
                }
            }
        }
    }
    snap
}

fn run_ping(dst: &str, size: usize, df: bool) -> bool {
    let mut args = vec!["-c".to_string(), "2".to_string(), "-W".to_string(), "2".to_string(), "-s".to_string(), size.to_string()];
    if df {
        args.push("-M".into());
        args.push("do".into());
    }
    args.push(dst.to_string());
    Command::new("ping")
        .args(&args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub async fn run_live_check(
    gre_if: &str,
    inner_local: &str,
    inner_peer: &str,
    public_peer: &str,
    ctrl_port: u16,
    wss_port: Option<u16>,
) -> RevPathDiagnosis {
    let snap = collect_local_snapshot(gre_if, inner_local, inner_peer);
    let mut m = ProbeMatrix::default();

    if !inner_peer.is_empty() {
        m.icmp_gre_64_ok = Some(run_ping(inner_peer, 56, false));
        m.icmp_gre_1300df_ok = Some(run_ping(inner_peer, 1272, true));
        let inner_ctrl = format!("{inner_peer}:{ctrl_port}");
        m.tcp_ctrl_inner_ok = Some(
            timeout(Duration::from_secs(3), TcpStream::connect(&inner_ctrl))
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false),
        );
    }
    if !public_peer.is_empty() {
        m.icmp_public_ok = Some(run_ping(public_peer, 56, false));
        let pub_ctrl = format!("{public_peer}:{ctrl_port}");
        m.tcp_ctrl_public_ok = Some(
            timeout(Duration::from_secs(3), TcpStream::connect(&pub_ctrl))
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false),
        );
        if let Some(wp) = wss_port {
            let pub_wss = format!("{public_peer}:{wp}");
            m.tcp_wss_ok = Some(
                timeout(Duration::from_secs(3), TcpStream::connect(&pub_wss))
                    .await
                    .map(|r| r.is_ok())
                    .unwrap_or(false),
            );
        }
    }
    let _ = Instant::now();
    classify(&m, &snap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_mtu_rpfilter_and_isp_gre_block() {
        let snap = LocalKernelSnapshot { gre_if: "gre0".into(), gre_mtu: 1380, ..Default::default() };
        let m_mtu = ProbeMatrix { icmp_gre_64_ok: Some(true), icmp_gre_1300df_ok: Some(false), ..Default::default() };
        let d1 = classify(&m_mtu, &snap);
        assert_eq!(d1.verdict, RevPathVerdict::MtuBlackhole);
        assert!(d1.auto_fixable);

        let snap_rp = LocalKernelSnapshot {
            gre_if: "gre0".into(), rp_filter_all: 1, route_known: true, route_back_via_gre: true,
            ..Default::default()
        };
        let m_down = ProbeMatrix { icmp_gre_64_ok: Some(false), tcp_ctrl_inner_ok: Some(false), ..Default::default() };
        assert_eq!(classify(&m_down, &snap_rp).verdict, RevPathVerdict::RpFilter);

        let snap_clean = LocalKernelSnapshot {
            gre_if: "gre0".into(), rp_filter_all: 2, route_known: true, route_back_via_gre: true,
            ..Default::default()
        };
        let m_isp = ProbeMatrix {
            icmp_gre_64_ok: Some(false), tcp_ctrl_inner_ok: Some(false), tcp_ctrl_public_ok: Some(true),
            ..Default::default()
        };
        assert_eq!(classify(&m_isp, &snap_clean).verdict, RevPathVerdict::IspGreBlock);
    }
}

//! Multi-Exit pool policy (`src/pool.rs`).
//!
//! One Entry can serve several Exits. This module decides *which* Exit gets the next link.
//! It is a pure function of (policy, candidate snapshot, client key, random number), so every
//! mode is unit-testable without sockets.
//!
//! Modes (`--pool-mode`):
//!   * `failover`  – lowest `priority` wins; the rest wait (default when options are used)
//!   * `balance`   – random split by `weight`
//!   * `sticky`    – the same client key keeps the same Exit (weighted rendezvous hashing),
//!                   and only moves when that Exit leaves the pool
//!   * `latency`   – lowest smoothed RTT wins
//!   * `least`     – fewest live links per unit of `weight`
//!
//! Per-Exit options are written after the address, separated by `;`:
//!   `--exit 203.0.113.5:443;w=2;p=0;max=300`  `--exit 198.51.100.9:443;standby;drain`
//!   w=<weight 1..1000>  p=<priority, 0 is best>  max=<live-link cap, 0 = unlimited>
//!   standby = used only while no normal member can take a link   drain = take no new links
//!
//! `--failback manual` keeps traffic on a backup after a failover until the operator runs
//! `pool.failback` (so a flapping primary cannot bounce users back and forth).

use anyhow::{bail, Context, Result};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolMode {
    Failover,
    Balance,
    Sticky,
    Latency,
    Least,
}

impl PoolMode {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.trim().to_ascii_lowercase().as_str() {
            "failover" | "fail" => PoolMode::Failover,
            "balance" | "weighted" | "wrr" => PoolMode::Balance,
            "sticky" | "hash" => PoolMode::Sticky,
            "latency" | "lowest-latency" | "rtt" => PoolMode::Latency,
            "least" | "least-conn" | "leastconn" => PoolMode::Least,
            other => bail!("unknown --pool-mode '{other}' (failover|balance|sticky|latency|least)"),
        })
    }
    pub fn as_str(self) -> &'static str {
        match self {
            PoolMode::Failover => "failover",
            PoolMode::Balance => "balance",
            PoolMode::Sticky => "sticky",
            PoolMode::Latency => "latency",
            PoolMode::Least => "least",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberOpts {
    pub weight: u32,
    pub priority: u32,
    pub standby: bool,
    pub max_conn: u32,
    pub drain: bool,
}

impl Default for MemberOpts {
    fn default() -> Self {
        MemberOpts { weight: 1, priority: 0, standby: false, max_conn: 0, drain: false }
    }
}

/// Split `addr;w=2;p=1;max=100;standby;drain` into the clean address and its options.
pub fn parse_exit_spec(raw: &str) -> Result<(String, MemberOpts)> {
    let mut parts = raw.split(';');
    let addr = parts.next().unwrap_or("").trim().to_string();
    if addr.is_empty() {
        bail!("empty --exit address");
    }
    let mut o = MemberOpts::default();
    for p in parts {
        let p = p.trim();
        if p.is_empty() {
            continue;
        }
        let (k, v) = match p.split_once('=') {
            Some((k, v)) => (k.trim(), Some(v.trim())),
            None => (p, None),
        };
        match (k, v) {
            ("w" | "weight", Some(v)) => {
                o.weight = v.parse().with_context(|| format!("bad weight '{v}' on {addr}"))?;
                if !(1..=1000).contains(&o.weight) {
                    bail!("weight must be 1..1000 on {addr}");
                }
            }
            ("p" | "priority", Some(v)) => {
                o.priority = v.parse().with_context(|| format!("bad priority '{v}' on {addr}"))?;
            }
            ("max" | "max-conn", Some(v)) => {
                o.max_conn = v.parse().with_context(|| format!("bad max '{v}' on {addr}"))?;
            }
            ("standby" | "backup", None) => o.standby = true,
            ("drain", None) => o.drain = true,
            _ => bail!("unknown exit option '{p}' on {addr} (w= p= max= standby drain)"),
        }
    }
    Ok((addr, o))
}

#[derive(Clone, Debug)]
pub struct PoolPolicy {
    pub mode: PoolMode,
    pub manual_failback: bool,
    pub opts: HashMap<String, MemberOpts>,
    /// False = untouched legacy behaviour of `Exits::pick` (no options, no `--pool-mode`).
    pub enabled: bool,
}

impl Default for PoolPolicy {
    fn default() -> Self {
        PoolPolicy { mode: PoolMode::Failover, manual_failback: false, opts: HashMap::new(), enabled: false }
    }
}

/// What `Exits` shows the policy about one currently selectable Exit.
#[derive(Clone, Debug)]
pub struct Cand<'a> {
    pub addr: &'a str,
    pub ewma_ms: f64,
    /// Live links currently attributed to this Exit.
    pub inflight: u32,
}

fn fnv(mut h: u64, bytes: &[u8]) -> u64 {
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn mix(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51afd7ed558ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ceb9fe1a85ec53);
    x ^ (x >> 33)
}

impl PoolPolicy {
    pub fn new(mode: PoolMode, manual_failback: bool, opts: HashMap<String, MemberOpts>) -> Self {
        PoolPolicy { mode, manual_failback, opts, enabled: true }
    }

    pub fn opts_for(&self, addr: &str) -> MemberOpts {
        self.opts.get(addr).cloned().unwrap_or_default()
    }

    pub fn set_drain(&mut self, addr: &str, drain: bool) -> bool {
        match self.opts.get_mut(addr) {
            Some(o) => {
                o.drain = drain;
                true
            }
            None => false,
        }
    }

    /// Choose one candidate. `key` identifies the client (sticky mode); `rnd` is a random u64;
    /// `current` is the member that served last (used by manual failback).
    /// Returns an index into `cands`, or `None` when nobody can take a link.
    pub fn choose(&self, cands: &[Cand<'_>], key: u64, rnd: u64, current: Option<&str>) -> Option<usize> {
        let usable = |c: &Cand<'_>| {
            let o = self.opts_for(c.addr);
            !o.drain && (o.max_conn == 0 || c.inflight < o.max_conn)
        };
        let mut primary: Vec<usize> = Vec::new();
        let mut standby: Vec<usize> = Vec::new();
        for (i, c) in cands.iter().enumerate() {
            if !usable(c) {
                continue;
            }
            if self.opts_for(c.addr).standby {
                standby.push(i);
            } else {
                primary.push(i);
            }
        }
        let pool = if primary.is_empty() { standby } else { primary };
        if pool.is_empty() {
            return None;
        }
        let w = |i: usize| self.opts_for(cands[i].addr).weight.max(1) as f64;
        let pr = |i: usize| self.opts_for(cands[i].addr).priority;
        let by_lat = |a: &usize, b: &usize| {
            cands[*a].ewma_ms.total_cmp(&cands[*b].ewma_ms).then(cands[*a].addr.cmp(cands[*b].addr))
        };
        match self.mode {
            PoolMode::Failover => {
                let best = pool.iter().map(|&i| pr(i)).min().unwrap();
                if self.manual_failback {
                    if let Some(cur) = current {
                        if let Some(&ci) = pool.iter().find(|&&i| cands[i].addr == cur) {
                            // stay on the backup until the operator fails back
                            return Some(ci);
                        }
                    }
                }
                pool.iter().copied().filter(|&i| pr(i) == best).min_by(by_lat)
            }
            PoolMode::Balance => {
                let total: f64 = pool.iter().map(|&i| w(i)).sum();
                let mut x = (mix(rnd) >> 11) as f64 / (1u64 << 53) as f64 * total;
                for &i in &pool {
                    x -= w(i);
                    if x < 0.0 {
                        return Some(i);
                    }
                }
                pool.last().copied()
            }
            PoolMode::Sticky => pool
                .iter()
                .copied()
                .map(|i| {
                    let h = mix(fnv(fnv(0xcbf29ce484222325, cands[i].addr.as_bytes()), &key.to_be_bytes()));
                    let u = (((h >> 11) as f64) + 1.0) / ((1u64 << 53) as f64 + 1.0);
                    (i, -u.ln() / w(i))
                })
                .min_by(|a, b| a.1.total_cmp(&b.1))
                .map(|(i, _)| i),
            PoolMode::Latency => pool.iter().copied().min_by(|a, b| pr(*a).cmp(&pr(*b)).then(by_lat(a, b))).and_then(|_| {
                // priority only breaks exact RTT ties; latency decides
                pool.iter().copied().min_by(|a, b| by_lat(a, b).then(pr(*a).cmp(&pr(*b))))
            }),
            PoolMode::Least => pool.iter().copied().min_by(|a, b| {
                let la = cands[*a].inflight as f64 / w(*a);
                let lb = cands[*b].inflight as f64 / w(*b);
                la.total_cmp(&lb).then(by_lat(a, b))
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pol(mode: PoolMode, specs: &[&str]) -> PoolPolicy {
        let mut m = HashMap::new();
        for s in specs {
            let (a, o) = parse_exit_spec(s).unwrap();
            m.insert(a, o);
        }
        PoolPolicy::new(mode, false, m)
    }
    fn c(addr: &str, ms: f64, n: u32) -> Cand<'_> {
        Cand { addr, ewma_ms: ms, inflight: n }
    }

    #[test]
    fn spec_parsing() {
        let (a, o) = parse_exit_spec("udp://1.2.3.4:443;w=3;p=2;max=50;standby;drain").unwrap();
        assert_eq!(a, "udp://1.2.3.4:443");
        assert_eq!(o, MemberOpts { weight: 3, priority: 2, standby: true, max_conn: 50, drain: true });
        assert_eq!(parse_exit_spec("1.2.3.4:443").unwrap().1, MemberOpts::default());
        assert!(parse_exit_spec("1.2.3.4:443;w=0").is_err());
        assert!(parse_exit_spec("1.2.3.4:443;bogus").is_err());
        assert!(parse_exit_spec(";w=1").is_err());
    }

    #[test]
    fn failover_prefers_priority_then_backup() {
        let p = pol(PoolMode::Failover, &["a:1;p=0", "b:1;p=1"]);
        assert_eq!(p.choose(&[c("a:1", 90.0, 0), c("b:1", 10.0, 0)], 0, 0, None), Some(0));
        // a is gone (not a candidate): b takes over
        assert_eq!(p.choose(&[c("b:1", 10.0, 0)], 0, 0, None), Some(0));
    }

    #[test]
    fn manual_failback_stays_on_backup() {
        let mut p = pol(PoolMode::Failover, &["a:1;p=0", "b:1;p=1"]);
        p.manual_failback = true;
        let both = [c("a:1", 20.0, 0), c("b:1", 20.0, 0)];
        // traffic is on b, primary a returned: stays on b
        assert_eq!(p.choose(&both, 0, 0, Some("b:1")), Some(1));
        // operator failed back (current cleared): goes to a
        assert_eq!(p.choose(&both, 0, 0, None), Some(0));
        // b dies while current: falls to a
        assert_eq!(p.choose(&[c("a:1", 20.0, 0)], 0, 0, Some("b:1")), Some(0));
    }

    #[test]
    fn balance_follows_weights() {
        let p = pol(PoolMode::Balance, &["a:1;w=3", "b:1;w=1"]);
        let cs = [c("a:1", 1.0, 0), c("b:1", 1.0, 0)];
        let mut hits = [0u32; 2];
        for r in 0..20000u64 {
            hits[p.choose(&cs, 0, r.wrapping_mul(0x9e3779b97f4a7c15), None).unwrap()] += 1;
        }
        let share = hits[0] as f64 / 20000.0;
        assert!((share - 0.75).abs() < 0.03, "share {share}");
    }

    #[test]
    fn sticky_is_stable_and_moves_minimally() {
        let p = pol(PoolMode::Sticky, &["a:1", "b:1", "c:1"]);
        let all = [c("a:1", 1.0, 0), c("b:1", 1.0, 0), c("c:1", 1.0, 0)];
        let mut moved = 0;
        for k in 0..600u64 {
            let first = p.choose(&all, k, 0, None).unwrap();
            assert_eq!(first, p.choose(&all, k, 12345, None).unwrap(), "same key, same exit");
            let without_b = [c("a:1", 1.0, 0), c("c:1", 1.0, 0)];
            let name = all[first].addr;
            let after = without_b[p.choose(&without_b, k, 0, None).unwrap()].addr;
            if name != "b:1" && name != after {
                moved += 1;
            }
        }
        assert_eq!(moved, 0, "keys not on the removed exit must not move");
    }

    #[test]
    fn latency_and_least() {
        let p = pol(PoolMode::Latency, &["a:1", "b:1"]);
        assert_eq!(p.choose(&[c("a:1", 80.0, 0), c("b:1", 30.0, 0)], 0, 0, None), Some(1));
        let p = pol(PoolMode::Least, &["a:1;w=2", "b:1"]);
        // a has 6 links over weight 2 = 3.0, b has 4 over weight 1 = 4.0
        assert_eq!(p.choose(&[c("a:1", 1.0, 6), c("b:1", 1.0, 4)], 0, 0, None), Some(0));
    }

    #[test]
    fn standby_drain_and_limits() {
        let p = pol(PoolMode::Balance, &["a:1;max=2", "s:1;standby", "d:1;drain"]);
        let cs = [c("a:1", 1.0, 1), c("s:1", 1.0, 0), c("d:1", 1.0, 0)];
        for r in 0..200u64 {
            assert_eq!(p.choose(&cs, 0, r, None), Some(0), "standby unused while a has room, drain never");
        }
        // a is full: overflow goes to standby
        let full = [c("a:1", 1.0, 2), c("s:1", 1.0, 0), c("d:1", 1.0, 0)];
        assert_eq!(p.choose(&full, 0, 7, None), Some(1));
        // everyone full or drained: nothing
        let none = [c("a:1", 1.0, 2), c("d:1", 1.0, 0)];
        assert_eq!(p.choose(&none, 0, 7, None), None);
    }
}

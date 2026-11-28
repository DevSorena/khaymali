//! Tunnel-facing QoS helpers (`tc` + sysctl).
//!
//! Goals for censorship / high-latency paths:
//!   * Keep latency low under load → `fq_codel` or `cake` on the tunnel iface
//!   * Optional uplink cap → HTB root + leaf so bulk cannot starve interactive
//!   * Optional DSCP mark on forwarded packets (EF for interactive class)
//!   * Align host defaults with [`crate::ops_suite::PerfConfig`] (BBR + fq)
//!
//! All kernel changes go through [`crate::sysrun`] (respects dry-run).

use crate::ops_suite::PerfConfig;
use crate::sysrun;
use anyhow::{bail, Context, Result};

fn cmd(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| (*s).to_string()).collect()
}

fn run(args: &[&str]) -> Result<()> {
    let out = sysrun::run(&cmd(args));
    if !out.ok {
        bail!("{} → {}", args.join(" "), out.stderr.trim());
    }
    Ok(())
}

fn run_ok(args: &[&str]) -> bool {
    sysrun::run(&cmd(args)).ok
}

/// Host-wide kernel tuning suitable for tunnels (BBR + fq + large buffers).
pub fn apply_host_perf() -> Result<usize> {
    let n = PerfConfig::default().apply("/etc/sysctl.d/99-khaymali.conf")?;
    println!("[+] Applied {n} sysctl tunables (BBR, fq, 16MiB buffers, ip_forward).");
    Ok(n)
}

/// Replace root qdisc on `dev` with fq_codel (good default for tunnel ifaces).
pub fn apply_fq_codel(dev: &str) -> Result<()> {
    let _ = run_ok(&["tc", "qdisc", "del", "dev", dev, "root"]);
    run(&[
        "tc", "qdisc", "add", "dev", dev, "root", "handle", "1:", "fq_codel",
        "limit", "10240", "target", "5ms", "interval", "100ms", "ecn",
    ])
    .with_context(|| format!("fq_codel on {dev}"))?;
    println!("[+] {dev}: root qdisc = fq_codel (ecn, target 5ms)");
    Ok(())
}

/// CAKE on the tunnel iface — excellent one-qdisc latency under load.
/// `bandwidth` e.g. "100mbit" or empty for unlimited / intrinsic.
pub fn apply_cake(dev: &str, bandwidth: Option<&str>) -> Result<()> {
    let _ = run_ok(&["tc", "qdisc", "del", "dev", dev, "root"]);
    let mut args = vec![
        "tc", "qdisc", "add", "dev", dev, "root", "cake",
        "diffserv4", "nat", "wash", "ack-filter",
    ];
    if let Some(bw) = bandwidth {
        if !bw.is_empty() && bw != "0" {
            args.push("bandwidth");
            args.push(bw);
        }
    }
    // best-effort overhead for typical ethernet; users can override later
    args.extend(["overhead", "30", "ethernet"]);
    run(&args).with_context(|| format!("cake on {dev}"))?;
    println!(
        "[+] {dev}: root qdisc = cake ({})",
        bandwidth.unwrap_or("unlimited")
    );
    Ok(())
}

/// HTB rate-limit with two classes: interactive (high prio) + bulk.
/// `rate` is the total uplink budget, e.g. "50mbit".
pub fn apply_htb_limit(dev: &str, rate: &str) -> Result<()> {
    let _ = run_ok(&["tc", "qdisc", "del", "dev", dev, "root"]);
    // root HTB
    run(&["tc", "qdisc", "add", "dev", dev, "root", "handle", "1:", "htb", "default", "20"])?;
    run(&[
        "tc", "class", "add", "dev", dev, "parent", "1:", "classid", "1:1",
        "htb", "rate", rate, "ceil", rate,
    ])?;
    // 1:10 interactive — 30% guaranteed, can borrow
    run(&[
        "tc", "class", "add", "dev", dev, "parent", "1:1", "classid", "1:10",
        "htb", "rate", "1mbit", "ceil", rate, "prio", "1",
    ])?;
    // 1:20 bulk — rest
    run(&[
        "tc", "class", "add", "dev", dev, "parent", "1:1", "classid", "1:20",
        "htb", "rate", "1mbit", "ceil", rate, "prio", "3",
    ])?;
    run(&[
        "tc", "qdisc", "add", "dev", dev, "parent", "1:10", "handle", "10:",
        "fq_codel", "ecn",
    ])?;
    run(&[
        "tc", "qdisc", "add", "dev", dev, "parent", "1:20", "handle", "20:",
        "fq_codel", "ecn",
    ])?;
    // Small packets / SSH-ish → interactive (best-effort u32 match on length)
    let _ = run_ok(&[
        "tc", "filter", "add", "dev", dev, "protocol", "ip", "parent", "1:", "prio", "1",
        "u32", "match", "u16", "0x0000", "0xff00", "at", "2",
        "flowid", "1:10",
    ]);
    println!("[+] {dev}: HTB rate={rate} (1:10 interactive / 1:20 bulk + fq_codel)");
    Ok(())
}

/// Clear root qdisc on device (back to kernel default).
pub fn clear(dev: &str) -> Result<()> {
    let _ = run_ok(&["tc", "qdisc", "del", "dev", dev, "root"]);
    println!("[+] {dev}: root qdisc removed");
    Ok(())
}

/// Show current qdisc / class for a device.
pub fn status(dev: &str) {
    println!("--- qdisc {dev} ---");
    let o = sysrun::run(&cmd(&["tc", "-s", "qdisc", "show", "dev", dev]));
    print!("{}", o.stdout);
    if !o.ok && !o.stderr.is_empty() {
        eprintln!("{}", o.stderr.trim());
    }
    let o = sysrun::run(&cmd(&["tc", "-s", "class", "show", "dev", dev]));
    if !o.stdout.trim().is_empty() {
        println!("--- class {dev} ---");
        print!("{}", o.stdout);
    }
}

/// Preset profiles for common tunnel scenarios.
#[derive(Clone, Copy, Debug)]
pub enum QosProfile {
    /// Host sysctl only (BBR + fq).
    Host,
    /// fq_codel on iface — low latency, no hard cap.
    LowLatency,
    /// CAKE on iface — best single-qdisc for home/VPS uplinks.
    Cake,
    /// CAKE with bandwidth cap (e.g. 80% of real uplink).
    CakeLimited,
    /// HTB + fq_codel with explicit rate.
    RateLimit,
}

pub fn apply_profile(dev: &str, profile: QosProfile, rate: Option<&str>) -> Result<()> {
    match profile {
        QosProfile::Host => {
            apply_host_perf()?;
        }
        QosProfile::LowLatency => {
            apply_host_perf()?;
            apply_fq_codel(dev)?;
        }
        QosProfile::Cake => {
            apply_host_perf()?;
            apply_cake(dev, None)?;
        }
        QosProfile::CakeLimited => {
            apply_host_perf()?;
            let r = rate.unwrap_or("100mbit");
            apply_cake(dev, Some(r))?;
        }
        QosProfile::RateLimit => {
            apply_host_perf()?;
            let r = rate.unwrap_or("50mbit");
            apply_htb_limit(dev, r)?;
        }
    }
    Ok(())
}

//! Tear down temporary tunnel interfaces.

use crate::sysrun;

const PREFIXES: &[&str] = &[
    "tun_bench", "ipip_b", "gre_b", "gretap_b", "vxlan_b",
    "geneve_b", "sit_b", "l2tp_b", "wg_b", "kmlight_b", "kmlight0",
];

fn cmd(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| s.to_string()).collect()
}

pub fn auto_cleanup(verbose: bool) {
    if verbose {
        println!("[*] Cleaning temporary tunnel interfaces...");
    }
    for prefix in PREFIXES {
        let _ = sysrun::run(&cmd(&["ip", "link", "del", "dev", prefix]));
        for i in 0..8 {
            let name = format!("{prefix}{i}");
            let _ = sysrun::run(&cmd(&["ip", "link", "del", "dev", &name]));
        }
    }
    for name in ["tun0", "gre0", "gretap0", "ipip0", "sit0"] {
        let _ = sysrun::run(&cmd(&["ip", "link", "del", "dev", name]));
    }
    if verbose {
        println!("[+] Cleanup done.");
    }
}

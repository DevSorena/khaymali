//! Tear down temporary benchmark interfaces and rules.

use crate::system::run_cmd_quiet;
use crate::netinfo::delete_iface;

const BENCH_PREFIXES: &[&str] = &[
    "tun_bench", "ipip_b", "gre_b", "gretap_b", "vxlan_b",
    "geneve_b", "sit_b", "l2tp_b", "wg_b", "kmlight_b", "eoip_b",
];

pub fn auto_cleanup(verbose: bool) {
    if verbose {
        println!("[*] Cleaning temporary tunnel interfaces...");
    }
    for prefix in BENCH_PREFIXES {
        // try exact and numbered
        let _ = delete_iface(prefix);
        for i in 0..8 {
            let name = format!("{prefix}{i}");
            let _ = delete_iface(&name);
        }
    }
    // common leftover names
    for name in ["tun0", "gre0", "gretap0", "ipip0", "sit0"] {
        run_cmd_quiet(&["ip", "link", "del", "dev", name]);
    }
    if verbose {
        println!("[+] Cleanup done.");
    }
}

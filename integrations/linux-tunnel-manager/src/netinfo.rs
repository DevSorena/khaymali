use crate::system::{run_cmd, run_cmd_ok, Result};

pub fn default_gateway() -> Option<String> {
    run_cmd(&["ip", "route", "show", "default"]).ok().and_then(|s| {
        s.split_whitespace().skip_while(|t| *t != "via").nth(1).map(|s| s.to_string())
    })
}

pub fn default_iface() -> Option<String> {
    run_cmd(&["ip", "route", "show", "default"]).ok().and_then(|s| {
        s.split_whitespace().skip_while(|t| *t != "dev").nth(1).map(|s| s.to_string())
    })
}

pub fn primary_ip() -> Option<String> {
    let iface = default_iface()?;
    run_cmd(&["ip", "-4", "-o", "addr", "show", "dev", &iface]).ok().and_then(|s| {
        s.split_whitespace()
            .find(|t| t.contains('/'))
            .map(|t| t.split('/').next().unwrap_or(t).to_string())
    })
}

pub fn iface_exists(name: &str) -> bool {
    run_cmd_ok(&["ip", "link", "show", "dev", name])
}

pub fn delete_iface(name: &str) -> Result<()> {
    if iface_exists(name) {
        run_cmd(&["ip", "link", "del", "dev", name])?;
    }
    Ok(())
}

//! System command runner with dry-run recording (`src/sysrun.rs`).
//!
//! Every module of the Khaymali port that touches the kernel (ip, iptables, nft, tc, sysctl,
//! systemctl, wg) goes through [`run`]. With `KHAYMALI_DRY_RUN=1` (or [`set_dry_run`]) nothing
//! is executed: commands are recorded and reported as successful, which is what the unit tests
//! and `--plan` CLI flags use. Commands are never passed through a shell.

use anyhow::{bail, Context, Result};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

static DRY: AtomicBool = AtomicBool::new(false);
static LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());

thread_local! {
    // Per-thread dry-run so parallel unit tests never leak into each other.
    static TL_DRY: std::cell::Cell<bool> = std::cell::Cell::new(false);
    static TL_LOG: std::cell::RefCell<Vec<String>> = std::cell::RefCell::new(Vec::new());
}

/// Process-wide dry-run (CLI `--plan`).
pub fn set_dry_run_global(on: bool) {
    DRY.store(on, Ordering::SeqCst);
}

/// Dry-run for the current thread only (unit tests).
pub fn set_dry_run(on: bool) {
    TL_DRY.with(|c| c.set(on));
}

fn thread_dry() -> bool {
    TL_DRY.with(|c| c.get())
}

pub fn is_dry_run() -> bool {
    thread_dry() || DRY.load(Ordering::SeqCst) || std::env::var("KHAYMALI_DRY_RUN").map(|v| v == "1").unwrap_or(false)
}

fn record(s: String) {
    if thread_dry() {
        TL_LOG.with(|l| l.borrow_mut().push(s));
    } else {
        LOG.lock().unwrap().push(s);
    }
}

/// Commands recorded while in dry-run mode (drained; thread-local log first).
pub fn take_log() -> Vec<String> {
    let tl = TL_LOG.with(|l| std::mem::take(&mut *l.borrow_mut()));
    if thread_dry() {
        return tl;
    }
    let mut g = std::mem::take(&mut *LOG.lock().unwrap());
    let mut out = tl;
    out.append(&mut g);
    out
}

pub fn render(cmd: &[String]) -> String {
    cmd.iter()
        .map(|a| {
            if a.is_empty() || a.chars().any(|c| c.is_whitespace() || "\"'$`\\;&|<>(){}*".contains(c)) {
                format!("'{}'", a.replace('\'', "'\\''"))
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub struct Out {
    pub ok: bool,
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Run argv with a timeout. Never panics; a missing binary is reported as `ok=false, code=127`.
pub fn run_timeout(cmd: &[String], to: Duration) -> Out {
    if cmd.is_empty() {
        return Out { ok: false, code: -1, stdout: String::new(), stderr: "empty command".into() };
    }
    if is_dry_run() {
        record(render(cmd));
        return Out { ok: true, code: 0, stdout: String::new(), stderr: String::new() };
    }
    let child = Command::new(&cmd[0])
        .args(&cmd[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => return Out { ok: false, code: 127, stdout: String::new(), stderr: format!("{}: {e}", cmd[0]) },
    };
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if start.elapsed() > to {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Out { ok: false, code: 124, stdout: String::new(), stderr: format!("{} timed out after {:?}", cmd[0], to) };
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Out { ok: false, code: -1, stdout: String::new(), stderr: e.to_string() },
        }
    }
    match child.wait_with_output() {
        Ok(o) => Out {
            ok: o.status.success(),
            code: o.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        },
        Err(e) => Out { ok: false, code: -1, stdout: String::new(), stderr: e.to_string() },
    }
}

pub fn run(cmd: &[String]) -> Out {
    run_timeout(cmd, Duration::from_secs(15))
}

/// Run and fail with stderr on non-zero exit.
pub fn must(cmd: &[String]) -> Result<String> {
    let o = run(cmd);
    if !o.ok {
        bail!("`{}` failed ({}): {}", render(cmd), o.code, o.stderr.trim());
    }
    Ok(o.stdout)
}

/// Run a whole plan; stops at the first failure unless `best_effort`.
pub fn run_plan(plan: &[Vec<String>], best_effort: bool) -> Result<usize> {
    let mut ok = 0;
    for c in plan {
        let o = run(c);
        if o.ok {
            ok += 1;
        } else if !best_effort {
            bail!("`{}` failed ({}): {}", render(c), o.code, o.stderr.trim());
        }
    }
    Ok(ok)
}

/// Feed `input` on stdin (iptables-restore, nft -f -). Dry-run records `<cmd> <<< N bytes`.
pub fn run_stdin(cmd: &[String], input: &str) -> Result<String> {
    if is_dry_run() {
        record(format!("{} <<< {} bytes", render(cmd), input.len()));
        return Ok(String::new());
    }
    use std::io::Write;
    let mut child = Command::new(&cmd[0])
        .args(&cmd[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn {}", cmd[0]))?;
    child.stdin.take().context("stdin")?.write_all(input.as_bytes())?;
    let o = child.wait_with_output()?;
    if !o.status.success() {
        bail!("`{}` failed: {}", render(cmd), String::from_utf8_lossy(&o.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

/// `v!["ip", "link", x]` -> Vec<String>
#[macro_export]
macro_rules! v {
    ($($x:expr),* $(,)?) => { vec![$($x.to_string()),*] };
}

pub fn which(bin: &str) -> Option<String> {
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into());
    for d in path.split(':') {
        let p = format!("{d}/{bin}");
        if std::path::Path::new(&p).is_file() {
            return Some(p);
        }
    }
    None
}

/// Write a systemd unit and (unless dry-run) daemon-reload + enable --now.
pub fn install_unit(dir: &str, name: &str, body: &str, start: bool) -> Result<()> {
    let path = format!("{dir}/{name}");
    if is_dry_run() {
        record(format!("write {path} ({} bytes)", body.len()));
    } else {
        crate::hjson::write_atomic(&path, body.as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
        }
    }
    let _ = run(&crate::v!["systemctl", "daemon-reload"]);
    if start {
        must(&crate::v!["systemctl", "enable", "--now", name])?;
    }
    Ok(())
}

pub fn unit_active(name: &str) -> bool {
    if is_dry_run() {
        return true;
    }
    run(&crate::v!["systemctl", "is-active", "--quiet", name]).ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dry_run_records_and_quotes() {
        set_dry_run(true);
        let _ = take_log();
        let o = run(&crate::v!["iptables", "-A", "X", "-m", "comment", "--comment", "a b"]);
        assert!(o.ok);
        run_plan(&[crate::v!["ip", "link"], crate::v!["tc", "qdisc"]], false).unwrap();
        let log = take_log();
        assert_eq!(log[0], "iptables -A X -m comment --comment 'a b'");
        assert_eq!(log.len(), 3);
        set_dry_run(false);
    }

    #[test]
    fn missing_binary_is_127() {
        let o = run_timeout(&crate::v!["/nonexistent/khaymali-bin"], Duration::from_secs(1));
        if !is_dry_run() {
            assert_eq!(o.code, 127);
            assert!(!o.ok);
        }
    }
}

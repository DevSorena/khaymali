//! Encrypted backups (`src/backup.rs`).
//!
//! `khaymali backup run --pass-file F` packs the config directories into one `.enc` file:
//!
//!   "KHB1" | salt(16) | nonce(12) | AES-256-GCM(tar.gz) + tag(16)
//!
//! The key is PBKDF2-HMAC-SHA256 of the passphrase (200 000 rounds, random salt), so a stolen
//! backup cannot be opened without the passphrase and any change to the file is detected.
//! Restore never trusts the archive: every member path is checked first (no absolute paths, no
//! `..`, no links) and files are extracted under a directory you choose, never over `/`.
//! Old backups are rotated (`--keep N`, default 14).

use crate::cluster_mesh::{aes256_gcm_decrypt, aes256_gcm_encrypt};
use crate::util::{now_unix, rand_bytes};
use anyhow::{bail, Context, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::Write;
use std::process::{Command, Stdio};

const MAGIC: &[u8; 4] = b"KHB1";
pub const PBKDF2_ROUNDS: u32 = 200_000;
pub const DEFAULT_KEEP: usize = 14;
pub const DEFAULT_SOURCES: &[&str] = &["/etc/khaymali", "/var/lib/khaymali"];

type HmacSha256 = Hmac<Sha256>;

/// PBKDF2-HMAC-SHA256, one 32-byte block (RFC 8018).
pub fn pbkdf2(pass: &[u8], salt: &[u8], rounds: u32) -> [u8; 32] {
    let base = HmacSha256::new_from_slice(pass).expect("hmac accepts any key length");
    let mut m = base.clone();
    m.update(salt);
    m.update(&1u32.to_be_bytes());
    let mut u = m.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&u);
    for _ in 1..rounds {
        let mut m = base.clone();
        m.update(&u);
        u = m.finalize().into_bytes();
        for (o, b) in out.iter_mut().zip(u.iter()) {
            *o ^= b;
        }
    }
    out
}

pub fn seal(pass: &str, plain: &[u8], rounds: u32) -> Vec<u8> {
    let salt = rand_bytes::<16>();
    let nonce = rand_bytes::<12>();
    let key = pbkdf2(pass.as_bytes(), &salt, rounds);
    let ct = aes256_gcm_encrypt(&key, &nonce, plain);
    let mut o = Vec::with_capacity(4 + 16 + 12 + ct.len());
    o.extend_from_slice(MAGIC);
    o.extend_from_slice(&salt);
    o.extend_from_slice(&nonce);
    o.extend_from_slice(&ct);
    o
}

pub fn open(pass: &str, blob: &[u8], rounds: u32) -> Result<Vec<u8>> {
    if blob.len() < 4 + 16 + 12 + 16 || &blob[..4] != MAGIC {
        bail!("not a Khaymali backup (bad header)");
    }
    let key = pbkdf2(pass.as_bytes(), &blob[4..20], rounds);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob[20..32]);
    aes256_gcm_decrypt(&key, &nonce, &blob[32..]).context("wrong passphrase or the backup file is damaged")
}

/// A tar member name is safe only when it stays inside the restore directory.
pub fn safe_member(name: &str) -> bool {
    let n = name.trim();
    !n.is_empty() && !n.starts_with('/') && !n.contains('\0') && !n.split('/').any(|c| c == "..")
}

fn tar_create(sources: &[String]) -> Result<Vec<u8>> {
    let existing: Vec<&String> = sources.iter().filter(|s| std::path::Path::new(s.as_str()).exists()).collect();
    if existing.is_empty() {
        bail!("none of the backup sources exist: {}", sources.join(", "));
    }
    // -P keeps names absolute-free via -C /; strip the leading slash ourselves
    let mut cmd = Command::new("tar");
    cmd.args(["-czf", "-", "-C", "/"]);
    for s in existing {
        cmd.arg(s.trim_start_matches('/'));
    }
    let out = cmd.output().context("running tar")?;
    if !out.status.success() && out.stdout.is_empty() {
        bail!("tar failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(out.stdout)
}

/// Check every member (and refuse links) before anything is written.
pub fn verify_archive(tgz: &[u8]) -> Result<Vec<String>> {
    let mut c = Command::new("tar")
        .args(["-tzvf", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("running tar")?;
    let mut si = c.stdin.take().unwrap();
    let data = tgz.to_vec();
    let w = std::thread::spawn(move || {
        let _ = si.write_all(&data);
    });
    let out = c.wait_with_output()?;
    let _ = w.join();
    if !out.status.success() {
        bail!("archive is not a valid tar.gz");
    }
    let mut names = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let kind = line.chars().next().unwrap_or('?');
        if kind == 'l' || kind == 'h' {
            bail!("archive contains a link ({line}); refusing to restore");
        }
        // verbose listing: perms owner size date time name
        let name = line.split_whitespace().skip(5).collect::<Vec<_>>().join(" ");
        let name = name.as_str();
        if !safe_member(name) {
            bail!("archive contains an unsafe path '{name}'; refusing to restore");
        }
        names.push(name.to_string());
    }
    Ok(names)
}

pub fn file_name(ts: u64) -> String {
    format!("khaymali-backup-{ts}.enc")
}

/// Create one backup file in `dir`; returns its path.
pub fn run(dir: &str, pass: &str, sources: &[String], keep: usize, rounds: u32) -> Result<String> {
    if pass.len() < 8 {
        bail!("backup passphrase must be at least 8 characters");
    }
    std::fs::create_dir_all(dir).with_context(|| format!("creating {dir}"))?;
    let tgz = tar_create(sources)?;
    let blob = seal(pass, &tgz, rounds);
    let path = format!("{}/{}", dir.trim_end_matches('/'), file_name(now_unix()));
    let tmp = format!("{path}.part");
    std::fs::write(&tmp, &blob)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, &path)?;
    rotate(dir, keep)?;
    Ok(path)
}

pub fn list(dir: &str) -> Vec<(String, u64, u64)> {
    let mut v: Vec<(String, u64, u64)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            let ts = n.strip_prefix("khaymali-backup-")?.strip_suffix(".enc")?.parse().ok()?;
            Some((n, e.metadata().ok()?.len(), ts))
        })
        .collect();
    v.sort_by_key(|x| x.2);
    v
}

pub fn rotate(dir: &str, keep: usize) -> Result<usize> {
    let l = list(dir);
    let mut removed = 0;
    if l.len() > keep.max(1) {
        for (n, _, _) in &l[..l.len() - keep.max(1)] {
            std::fs::remove_file(format!("{}/{n}", dir.trim_end_matches('/')))?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// Decrypt, check every path, then extract under `dest`. Returns the member names.
pub fn restore(file: &str, pass: &str, dest: &str, rounds: u32) -> Result<Vec<String>> {
    let blob = std::fs::read(file).with_context(|| format!("reading {file}"))?;
    let tgz = open(pass, &blob, rounds)?;
    let names = verify_archive(&tgz)?;
    std::fs::create_dir_all(dest)?;
    let mut c = Command::new("tar")
        .args(["-xzf", "-", "-C", dest, "--no-same-owner"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("running tar")?;
    let mut si = c.stdin.take().unwrap();
    let w = std::thread::spawn(move || {
        let _ = si.write_all(&tgz);
    });
    let out = c.wait_with_output()?;
    let _ = w.join();
    if !out.status.success() {
        bail!("tar extract failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    const R: u32 = 50; // fast rounds for tests

    #[test]
    fn pbkdf2_matches_rfc6070_style_vector() {
        // PBKDF2-HMAC-SHA256, P="password", S="salt", c=1 (widely published vector)
        let k = pbkdf2(b"password", b"salt", 1);
        let hex: String = k.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
        let k2: String = pbkdf2(b"password", b"salt", 2).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(k2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");
    }

    #[test]
    fn seal_open_roundtrip_wrong_pass_and_tamper() {
        let blob = seal("correct horse", b"hello backup", R);
        assert_eq!(open("correct horse", &blob, R).unwrap(), b"hello backup");
        assert!(open("wrong pass!!", &blob, R).is_err());
        let mut bad = blob.clone();
        let n = bad.len();
        bad[n - 20] ^= 1;
        assert!(open("correct horse", &bad, R).is_err(), "tampering is detected");
        assert!(open("correct horse", b"junk", R).is_err());
    }

    #[test]
    fn member_paths() {
        assert!(safe_member("etc/khaymali/a.json") && safe_member("./x"));
        assert!(!safe_member("/etc/passwd") && !safe_member("../x") && !safe_member("a/../../x") && !safe_member(""));
    }

    #[test]
    fn full_cycle_rotation_and_malicious_archive() {
        let base = format!("{}/khb-{}", std::env::temp_dir().display(), std::process::id());
        let src = format!("{base}/src/etc");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(format!("{src}/settings.json"), b"[1,2,3]").unwrap();
        let bdir = format!("{base}/bk");
        // tar_create strips the leading slash, -C / makes names relative
        let p = run(&bdir, "passphrase-1", &[src.clone()], 2, R).unwrap();
        assert!(std::fs::metadata(&p).unwrap().len() > 40);
        let dest = format!("{base}/out");
        let names = restore(&p, "passphrase-1", &dest, R).unwrap();
        assert!(names.iter().any(|n| n.ends_with("settings.json")));
        let restored = format!("{dest}/{}/settings.json", src.trim_start_matches('/'));
        assert_eq!(std::fs::read(restored).unwrap(), b"[1,2,3]");
        assert!(restore(&p, "bad-passphrase", &dest, R).is_err());
        // rotation keeps the newest 2
        for i in 1..=3u64 {
            std::fs::write(format!("{bdir}/{}", file_name(100 + i)), b"x").unwrap();
        }
        rotate(&bdir, 2).unwrap();
        assert_eq!(list(&bdir).len(), 2);
        // a hostile archive: path traversal must be refused before extraction
        let evil_src = format!("{base}/evil");
        std::fs::create_dir_all(&evil_src).unwrap();
        std::fs::write(format!("{evil_src}/f"), b"x").unwrap();
        let tgz = Command::new("tar")
            .args(["-czf", "-", "--transform", "s,^,../,", "-C", &evil_src, "f"])
            .output()
            .unwrap()
            .stdout;
        assert!(verify_archive(&tgz).is_err(), "../ member must be rejected");
        let _ = std::fs::remove_dir_all(base);
    }
}

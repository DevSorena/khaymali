//! Minimal, dependency-free JSON value + Base64 codec (`src/hjson.rs`).
//!
//! Khaymali keeps a zero-extra-crate policy (`--locked` builds, small audit surface). The Khaymali
//! port needs JSON for state files (`spoof.json`, `hubs.json`, `nodes.json`,
//! `swap.json`) and for wire bundles (`BAGHER:`, `SPOOF1:`), and Base64 for those bundles.
//! This module is intentionally strict: it rejects trailing garbage, unpaired surrogates,
//! nesting deeper than 64 and inputs larger than 8 MiB.

use anyhow::{bail, Result};
use std::collections::BTreeMap;
use std::fmt::Write as _;

pub const MAX_JSON_BYTES: usize = 8 * 1024 * 1024;
const MAX_DEPTH: usize = 64;

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

impl Json {
    pub fn obj() -> Json {
        Json::Obj(BTreeMap::new())
    }
    /// Builder-style insert; no-op on non-objects.
    pub fn set(mut self, k: &str, v: impl Into<Json>) -> Json {
        if let Json::Obj(m) = &mut self {
            m.insert(k.to_string(), v.into());
        }
        self
    }
    pub fn insert(&mut self, k: &str, v: impl Into<Json>) {
        if let Json::Obj(m) = self {
            m.insert(k.to_string(), v.into());
        }
    }
    pub fn get(&self, k: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m.get(k),
            _ => None,
        }
    }
    pub fn str_of(&self, k: &str) -> String {
        match self.get(k) {
            Some(Json::Str(s)) => s.clone(),
            Some(Json::Num(n)) => fmt_num(*n),
            _ => String::new(),
        }
    }
    pub fn num_of(&self, k: &str) -> f64 {
        match self.get(k) {
            Some(Json::Num(n)) => *n,
            Some(Json::Str(s)) => s.trim().parse().unwrap_or(0.0),
            _ => 0.0,
        }
    }
    pub fn i64_of(&self, k: &str) -> i64 {
        self.num_of(k) as i64
    }
    pub fn u64_of(&self, k: &str) -> u64 {
        let n = self.num_of(k);
        if n <= 0.0 { 0 } else { n as u64 }
    }
    pub fn bool_of(&self, k: &str) -> bool {
        matches!(self.get(k), Some(Json::Bool(true)))
    }
    pub fn arr_of(&self, k: &str) -> Vec<Json> {
        match self.get(k) {
            Some(Json::Arr(a)) => a.clone(),
            _ => Vec::new(),
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Num(n) => Some(*n),
            _ => None,
        }
    }

    pub fn to_string_compact(&self) -> String {
        let mut s = String::new();
        self.write(&mut s, None, 0);
        s
    }
    pub fn to_string_pretty(&self) -> String {
        let mut s = String::new();
        self.write(&mut s, Some(2), 0);
        s.push('\n');
        s
    }

    fn write(&self, out: &mut String, indent: Option<usize>, lvl: usize) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Num(n) => out.push_str(&fmt_num(*n)),
            Json::Str(s) => write_str(out, s),
            Json::Arr(a) => {
                if a.is_empty() {
                    out.push_str("[]");
                    return;
                }
                out.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    nl(out, indent, lvl + 1);
                    v.write(out, indent, lvl + 1);
                }
                nl(out, indent, lvl);
                out.push(']');
            }
            Json::Obj(m) => {
                if m.is_empty() {
                    out.push_str("{}");
                    return;
                }
                out.push('{');
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    nl(out, indent, lvl + 1);
                    write_str(out, k);
                    out.push(':');
                    if indent.is_some() {
                        out.push(' ');
                    }
                    v.write(out, indent, lvl + 1);
                }
                nl(out, indent, lvl);
                out.push('}');
            }
        }
    }

    pub fn parse(s: &str) -> Result<Json> {
        if s.len() > MAX_JSON_BYTES {
            bail!("json too large ({} bytes)", s.len());
        }
        let mut p = Parser { b: s.as_bytes(), i: 0 };
        p.ws();
        let v = p.value(0)?;
        p.ws();
        if p.i != p.b.len() {
            bail!("json: trailing data at byte {}", p.i);
        }
        Ok(v)
    }
}

fn nl(out: &mut String, indent: Option<usize>, lvl: usize) {
    if let Some(n) = indent {
        out.push('\n');
        for _ in 0..n * lvl {
            out.push(' ');
        }
    }
}

pub fn fmt_num(n: f64) -> String {
    if !n.is_finite() {
        return "0".into();
    }
    if n.fract() == 0.0 && n.abs() < 9.0e15 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

pub fn write_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// JSON-escape a string without surrounding quotes (for hand-built control replies).
pub fn esc(s: &str) -> String {
    let mut o = String::new();
    write_str(&mut o, s);
    o[1..o.len() - 1].to_string()
}

impl From<&str> for Json {
    fn from(s: &str) -> Json {
        Json::Str(s.to_string())
    }
}
impl From<String> for Json {
    fn from(s: String) -> Json {
        Json::Str(s)
    }
}
impl From<&String> for Json {
    fn from(s: &String) -> Json {
        Json::Str(s.clone())
    }
}
impl From<bool> for Json {
    fn from(b: bool) -> Json {
        Json::Bool(b)
    }
}
impl From<f64> for Json {
    fn from(n: f64) -> Json {
        Json::Num(n)
    }
}
impl From<i64> for Json {
    fn from(n: i64) -> Json {
        Json::Num(n as f64)
    }
}
impl From<u64> for Json {
    fn from(n: u64) -> Json {
        Json::Num(n as f64)
    }
}
impl From<u32> for Json {
    fn from(n: u32) -> Json {
        Json::Num(n as f64)
    }
}
impl From<u16> for Json {
    fn from(n: u16) -> Json {
        Json::Num(n as f64)
    }
}
impl From<i32> for Json {
    fn from(n: i32) -> Json {
        Json::Num(n as f64)
    }
}
impl From<usize> for Json {
    fn from(n: usize) -> Json {
        Json::Num(n as f64)
    }
}
impl From<Vec<Json>> for Json {
    fn from(v: Vec<Json>) -> Json {
        Json::Arr(v)
    }
}
impl From<Vec<String>> for Json {
    fn from(v: Vec<String>) -> Json {
        Json::Arr(v.into_iter().map(Json::Str).collect())
    }
}
impl From<Vec<u16>> for Json {
    fn from(v: Vec<u16>) -> Json {
        Json::Arr(v.into_iter().map(|n| Json::Num(n as f64)).collect())
    }
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn lit(&mut self, s: &str, v: Json) -> Result<Json> {
        if self.b[self.i..].starts_with(s.as_bytes()) {
            self.i += s.len();
            Ok(v)
        } else {
            bail!("json: bad literal at byte {}", self.i)
        }
    }
    fn value(&mut self, depth: usize) -> Result<Json> {
        if depth > MAX_DEPTH {
            bail!("json: nesting too deep");
        }
        match self.peek() {
            None => bail!("json: unexpected end"),
            Some(b'n') => self.lit("null", Json::Null),
            Some(b't') => self.lit("true", Json::Bool(true)),
            Some(b'f') => self.lit("false", Json::Bool(false)),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b'[') => {
                self.i += 1;
                let mut v = Vec::new();
                self.ws();
                if self.peek() == Some(b']') {
                    self.i += 1;
                    return Ok(Json::Arr(v));
                }
                loop {
                    self.ws();
                    v.push(self.value(depth + 1)?);
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Json::Arr(v));
                        }
                        _ => bail!("json: expected , or ] at byte {}", self.i),
                    }
                }
            }
            Some(b'{') => {
                self.i += 1;
                let mut m = BTreeMap::new();
                self.ws();
                if self.peek() == Some(b'}') {
                    self.i += 1;
                    return Ok(Json::Obj(m));
                }
                loop {
                    self.ws();
                    if self.peek() != Some(b'"') {
                        bail!("json: expected key at byte {}", self.i);
                    }
                    let k = self.string()?;
                    self.ws();
                    if self.peek() != Some(b':') {
                        bail!("json: expected : at byte {}", self.i);
                    }
                    self.i += 1;
                    self.ws();
                    let v = self.value(depth + 1)?;
                    m.insert(k, v);
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(Json::Obj(m));
                        }
                        _ => bail!("json: expected , or }} at byte {}", self.i),
                    }
                }
            }
            Some(c) if c == b'-' || c.is_ascii_digit() => {
                let st = self.i;
                self.i += 1;
                while let Some(c) = self.peek() {
                    if c.is_ascii_digit() || matches!(c, b'.' | b'e' | b'E' | b'+' | b'-') {
                        self.i += 1;
                    } else {
                        break;
                    }
                }
                let s = std::str::from_utf8(&self.b[st..self.i])?;
                let n: f64 = s.parse().map_err(|_| anyhow::anyhow!("json: bad number {s:?}"))?;
                Ok(Json::Num(n))
            }
            Some(c) => bail!("json: unexpected byte {c:#x} at {}", self.i),
        }
    }
    fn hex4(&mut self) -> Result<u32> {
        if self.i + 4 > self.b.len() {
            bail!("json: short \\u escape");
        }
        let s = std::str::from_utf8(&self.b[self.i..self.i + 4])?;
        self.i += 4;
        u32::from_str_radix(s, 16).map_err(|_| anyhow::anyhow!("json: bad \\u escape"))
    }
    fn string(&mut self) -> Result<String> {
        self.i += 1; // opening quote
        let mut out: Vec<u8> = Vec::new();
        loop {
            let Some(c) = self.peek() else { bail!("json: unterminated string") };
            self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let Some(e) = self.peek() else { bail!("json: bad escape") };
                    self.i += 1;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let mut cp = self.hex4()?;
                            if (0xD800..0xDC00).contains(&cp) {
                                if self.b.get(self.i) != Some(&b'\\') || self.b.get(self.i + 1) != Some(&b'u') {
                                    bail!("json: unpaired surrogate");
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    bail!("json: bad low surrogate");
                                }
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                            } else if (0xDC00..0xE000).contains(&cp) {
                                bail!("json: unpaired surrogate");
                            }
                            let ch = char::from_u32(cp).ok_or_else(|| anyhow::anyhow!("json: bad codepoint"))?;
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => bail!("json: bad escape \\{}", e as char),
                    }
                }
                c if c < 0x20 => bail!("json: control char in string"),
                c => out.push(c),
            }
        }
        Ok(String::from_utf8(out)?)
    }
}

// ----------------------------------------------------------------------------------------------
// Base64 (RFC 4648 standard + URL-safe, padding optional on decode)
// ----------------------------------------------------------------------------------------------

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64_enc_with(data: &[u8], tbl: &[u8; 64], pad: bool) -> String {
    let mut o = String::with_capacity((data.len() + 2) / 3 * 4);
    for ch in data.chunks(3) {
        let n = match ch.len() {
            3 => (ch[0] as u32) << 16 | (ch[1] as u32) << 8 | ch[2] as u32,
            2 => (ch[0] as u32) << 16 | (ch[1] as u32) << 8,
            _ => (ch[0] as u32) << 16,
        };
        o.push(tbl[(n >> 18) as usize & 63] as char);
        o.push(tbl[(n >> 12) as usize & 63] as char);
        if ch.len() > 1 {
            o.push(tbl[(n >> 6) as usize & 63] as char);
        } else if pad {
            o.push('=');
        }
        if ch.len() > 2 {
            o.push(tbl[n as usize & 63] as char);
        } else if pad {
            o.push('=');
        }
    }
    o
}

pub fn b64_encode(data: &[u8]) -> String {
    b64_enc_with(data, B64, true)
}
/// URL-safe, unpadded (Xray REALITY keys use this form).
pub fn b64url_encode(data: &[u8]) -> String {
    b64_enc_with(data, B64URL, false)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>> {
    let mut vals = Vec::with_capacity(s.len());
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => continue,
            b' ' | b'\n' | b'\r' | b'\t' => continue,
            _ => bail!("base64: invalid character {:?}", c as char),
        };
        vals.push(v as u32);
    }
    if vals.len() % 4 == 1 {
        bail!("base64: truncated input");
    }
    let mut out = Vec::with_capacity(vals.len() * 3 / 4);
    for ch in vals.chunks(4) {
        let mut n = 0u32;
        for (i, v) in ch.iter().enumerate() {
            n |= v << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if ch.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if ch.len() > 3 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

/// Atomic write (tmp + rename), mode 0600 on Unix. Used for every state file of the port.
pub fn write_atomic(path: &str, data: &[u8]) -> Result<()> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let tmp = format!("{path}.tmp.{}", std::process::id());
    std::fs::write(&tmp, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub fn read_json_file(path: &str) -> Result<Option<Json>> {
    match std::fs::read_to_string(path) {
        Ok(s) if s.trim().is_empty() => Ok(None),
        Ok(s) => Ok(Some(Json::parse(&s)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_roundtrip_nested_unicode() {
        let src = r#"{"a":[1,2.5,-3e2,true,null],"b":{"c":"سلام \"x\"\n\u00e9 \ud83d\ude00"},"d":""}"#;
        let v = Json::parse(src).unwrap();
        assert_eq!(v.get("b").unwrap().str_of("c"), "سلام \"x\"\n\u{e9} \u{1F600}");
        let again = Json::parse(&v.to_string_compact()).unwrap();
        assert_eq!(v, again);
        let pretty = Json::parse(&v.to_string_pretty()).unwrap();
        assert_eq!(v, pretty);
        assert_eq!(v.arr_of("a").len(), 5);
        assert_eq!(fmt_num(-300.0), "-300");
    }

    #[test]
    fn json_rejects_bad_inputs() {
        for bad in ["", "{", "[1,]", "{\"a\" 1}", "tru", "\"\\ud800\"", "1 2", "\"a\u{1}\"", "{\"a\":1,}"] {
            assert!(Json::parse(bad).is_err(), "should reject {bad:?}");
        }
        let deep = "[".repeat(100) + &"]".repeat(100);
        assert!(Json::parse(&deep).is_err());
    }

    #[test]
    fn base64_vectors() {
        let cases: [(&str, &str); 7] = [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy")];
        for (raw, enc) in cases {
            assert_eq!(b64_encode(raw.as_bytes()), enc);
            assert_eq!(b64_decode(enc).unwrap(), raw.as_bytes());
        }
        let bin: Vec<u8> = (0..=255).collect();
        assert_eq!(b64_decode(&b64_encode(&bin)).unwrap(), bin);
        assert_eq!(b64_decode(&b64url_encode(&bin)).unwrap(), bin);
        assert!(!b64url_encode(&bin).contains('='));
        assert!(b64_decode("Zm9v!").is_err());
        assert!(b64_decode("Z").is_err());
    }
}

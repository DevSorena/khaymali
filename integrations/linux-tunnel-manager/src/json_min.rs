//! Tiny JSON helpers for config (no serde).

use std::collections::HashMap;

pub fn get_str<'a>(obj: &'a str, key: &str) -> Option<&'a str> {
    // very small extractor: "key": "value"
    let pat = format!("\"{key}\"");
    let i = obj.find(&pat)?;
    let rest = &obj[i + pat.len()..];
    let rest = rest.trim_start();
    if !rest.starts_with(':') {
        return None;
    }
    let rest = rest[1..].trim_start();
    if rest.starts_with('"') {
        let rest = &rest[1..];
        let end = rest.find('"')?;
        Some(&rest[..end])
    } else {
        // number or bare
        let end = rest
            .find(|c: char| c == ',' || c == '}' || c.is_whitespace())
            .unwrap_or(rest.len());
        Some(rest[..end].trim())
    }
}

pub fn get_u64(obj: &str, key: &str) -> Option<u64> {
    get_str(obj, key)?.parse().ok()
}

pub fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

pub fn obj_from_map(map: &HashMap<&str, String>) -> String {
    let mut parts = Vec::new();
    for (k, v) in map {
        if v.parse::<i64>().is_ok() || v == "true" || v == "false" {
            parts.push(format!("  \"{k}\": {v}"));
        } else {
            parts.push(format!("  \"{k}\": \"{}\"", escape(v)));
        }
    }
    format!("{{\n{}\n}}", parts.join(",\n"))
}

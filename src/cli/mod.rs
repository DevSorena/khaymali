//! CLI argument parsing and subcommand helpers.
//!
//! Extracted from `main.rs` to reduce its size and improve maintainability.

use anyhow::{bail, Context, Result};
use std::collections::HashMap;

/// Simple but effective argument parser used throughout Khaymali.
#[derive(Debug, Clone)]
pub struct Args(HashMap<String, Vec<String>>);

impl Args {
    pub fn parse(rest: &[String]) -> Self {
        let mut m: HashMap<String, Vec<String>> = HashMap::new();
        let mut i = 0;
        while i < rest.len() {
            if let Some(k) = rest[i].strip_prefix("--") {
                if let Some((ek, ev)) = k.split_once('=') {
                    m.entry(ek.to_string()).or_default().push(ev.to_string());
                } else {
                    let v = if i + 1 < rest.len() && !rest[i + 1].starts_with("--") {
                        i += 1;
                        rest[i].clone()
                    } else {
                        "true".to_string()
                    };
                    m.entry(k.to_string()).or_default().push(v);
                }
            }
            i += 1;
        }
        Args(m)
    }

    pub fn get(&self, k: &str) -> Option<String> {
        self.0.get(k).and_then(|v| v.last().cloned())
    }

    pub fn all(&self, k: &str) -> Vec<String> {
        self.0.get(k).cloned().unwrap_or_default()
    }

    pub fn req(&self, k: &str) -> Result<String> {
        self.get(k).with_context(|| format!("missing --{k}"))
    }

    pub fn flag(&self, k: &str) -> bool {
        self.0.contains_key(k)
    }

    pub fn num(&self, k: &str, default: usize) -> usize {
        self.get(k).and_then(|v| v.parse().ok()).unwrap_or(default)
    }

    pub fn key(&self) -> Result<Vec<u8>> {
        use crate::util::unhex;
        let h = self
            .get("key")
            .or_else(|| std::env::var("KHAYMALI_KEY").ok())
            .context("missing --key or KHAYMALI_KEY")?;
        let k = unhex(&h)?;
        if k.len() != 32 {
            bail!("private key must be 32 bytes (64 hex chars)");
        }
        Ok(k)
    }
}

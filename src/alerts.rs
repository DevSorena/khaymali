//! Alerts (`src/alerts.rs`): tell the operator when a tunnel goes down, comes back, or when
//! Autopilot moves it. Two channels, both optional:
//!   * `--alert-webhook URL`            POST `{"source","host","text"}` as JSON
//!   * `--alert-telegram TOKEN:CHAT_ID` Telegram Bot API `sendMessage`
//! Environment fallbacks: `KHAYMALI_ALERT_WEBHOOK`, `KHAYMALI_ALERT_TELEGRAM`.
//!
//! Delivery uses the system `curl` (already a Khaymali prerequisite) so the binary needs no TLS
//! stack of its own. Secrets are handed to curl through a config on stdin, never on the command
//! line, so they do not show up in `ps`. Sending is best effort and never blocks the tunnel.

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Default)]
pub struct AlertCfg {
    pub webhook: Option<String>,
    /// `(bot token, chat id)`
    pub telegram: Option<(String, String)>,
    /// Optional proxy URL (e.g. `socks5h://127.0.0.1:1088` via Tunnel Egress Bridge).
    pub proxy: Option<String>,
}

impl AlertCfg {
    pub fn parse_telegram(s: &str) -> Option<(String, String)> {
        let (tok, chat) = s.rsplit_once(':')?;
        if tok.is_empty() || chat.is_empty() || !tok.contains(':') {
            return None;
        }
        Some((tok.to_string(), chat.to_string()))
    }
    pub fn is_empty(&self) -> bool {
        self.webhook.is_none() && self.telegram.is_none()
    }
}

pub struct Alerts {
    cfg: AlertCfg,
    host: String,
    last: Mutex<Option<Instant>>,
}

fn cfg_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n"))
}

fn json_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            c if (c as u32) < 0x20 => o.push(' '),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// curl `-K -` config for the webhook channel.
pub fn webhook_config(url: &str, host: &str, text: &str) -> String {
    let body = format!("{{\"source\":\"khaymali\",\"host\":{},\"text\":{}}}", json_str(host), json_str(text));
    format!(
        "url = {}\nrequest = \"POST\"\nheader = \"Content-Type: application/json\"\ndata = {}\n",
        cfg_quote(url),
        cfg_quote(&body)
    )
}

/// curl `-K -` config for Telegram.
pub fn telegram_config(token: &str, chat: &str, host: &str, text: &str) -> String {
    format!(
        "url = {}\ndata-urlencode = {}\ndata-urlencode = {}\n",
        cfg_quote(&format!("https://api.telegram.org/bot{token}/sendMessage")),
        cfg_quote(&format!("chat_id={chat}")),
        cfg_quote(&format!("text=[{host}] {text}")),
    )
}

fn curl(config: String) {
    let mut c = match Command::new("curl")
        .args(["-sS", "-m", "10", "-K", "-", "-o", "/dev/null"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return,
    };
    if let Some(mut si) = c.stdin.take() {
        let _ = si.write_all(config.as_bytes());
    }
    let _ = c.wait();
}

impl Alerts {
    pub fn new(cfg: AlertCfg) -> Option<std::sync::Arc<Alerts>> {
        if cfg.is_empty() {
            return None;
        }
        let host = std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()).unwrap_or_default();
        Some(std::sync::Arc::new(Alerts {
            cfg,
            host: if host.is_empty() { "khaymali".into() } else { host },
            last: Mutex::new(None),
        }))
    }

    /// Fire and forget. At most one message per second so a flapping tunnel cannot flood a chat.
    pub fn send(&self, text: &str) {
        {
            let mut l = self.last.lock().unwrap();
            if l.is_some_and(|t| t.elapsed() < Duration::from_secs(1)) {
                return;
            }
            *l = Some(Instant::now());
        }
        let mut jobs = Vec::new();
        let proxy_line = self
            .cfg
            .proxy
            .as_ref()
            .map(|p| format!("proxy = {}
", cfg_quote(p)))
            .unwrap_or_default();
        if let Some(u) = &self.cfg.webhook {
            jobs.push(format!("{}{}", webhook_config(u, &self.host, text), proxy_line));
        }
        if let Some((t, c)) = &self.cfg.telegram {
            jobs.push(format!("{}{}", telegram_config(t, c, &self.host, text), proxy_line));
        }
        for j in jobs {
            match tokio::runtime::Handle::try_current() {
                Ok(h) => {
                    h.spawn_blocking(move || curl(j));
                }
                Err(_) => {
                    std::thread::spawn(move || curl(j));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telegram_spec_parses() {
        assert_eq!(AlertCfg::parse_telegram("123456:AAH-x_y:-100200"), Some(("123456:AAH-x_y".into(), "-100200".into())));
        assert_eq!(AlertCfg::parse_telegram("nochat"), None);
        assert_eq!(AlertCfg::parse_telegram("tok:"), None);
    }

    #[test]
    fn configs_escape_and_keep_secrets_off_argv() {
        let w = webhook_config("https://h.example/x?k=1", "ir-1", "down \"now\"\nline2");
        assert!(w.contains("url = \"https://h.example/x?k=1\""));
        assert!(w.contains("\\\"text\\\":\\\"down \\\\\\\"now\\\\\\\"\\\\nline2\\\""), "{w}");
        let t = telegram_config("1:ABC", "-5", "ir-1", "x & y");
        assert!(t.contains("bot1:ABC/sendMessage") && t.contains("text=[ir-1] x & y"));
    }
}

//! Telegram control bot (`src/tgbot.rs`): check and steer a running Entry from your phone.
//!
//!   khaymali tgbot --token BOT_TOKEN --admin CHAT_ID[,CHAT_ID] [--control SOCK]
//!
//! Commands: /status /pool /health /autopilot /backups /drain ADDR /undrain ADDR /failback /help
//!
//! Safety: only the listed admin chat ids are answered (everyone else is ignored silently and
//! logged), commands are a fixed set (nothing is ever run through a shell), and the bot talks to
//! the Entry only through its local control socket. Telegram is reached with the system `curl`
//! (long polling); the token goes to curl through a config on stdin, never on the command line.

use crate::hjson::Json;
use std::io::Write;
use std::process::{Command, Stdio};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cmd {
    Help,
    Status,
    Pool,
    Health,
    Autopilot,
    Backups,
    Drain(String),
    Undrain(String),
    Failback,
    Unknown(String),
}

pub fn parse_command(text: &str) -> Option<Cmd> {
    let t = text.trim();
    if !t.starts_with('/') {
        return None;
    }
    let mut it = t.split_whitespace();
    let head = it.next()?.trim_start_matches('/');
    let head = head.split('@').next().unwrap_or(head).to_ascii_lowercase();
    let arg = it.next().unwrap_or("").to_string();
    Some(match head.as_str() {
        "start" | "help" => Cmd::Help,
        "status" => Cmd::Status,
        "pool" => Cmd::Pool,
        "health" => Cmd::Health,
        "autopilot" => Cmd::Autopilot,
        "backups" => Cmd::Backups,
        "drain" if !arg.is_empty() => Cmd::Drain(arg),
        "undrain" if !arg.is_empty() => Cmd::Undrain(arg),
        "failback" => Cmd::Failback,
        other => Cmd::Unknown(other.to_string()),
    })
}

pub fn help_text() -> String {
    "Khaymali bot\n\
/status  tunnel status\n\
/pool  Exit pool (links, weights, drain)\n\
/health  3-layer health\n\
/autopilot  Autopilot history\n\
/backups  list backups\n\
/drain ADDR  stop new links to an Exit\n\
/undrain ADDR  allow it again\n\
/failback  return to the primary Exit"
        .to_string()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Update {
    pub id: i64,
    pub chat: i64,
    pub text: String,
}

/// Parse a `getUpdates` reply into updates and the next offset to ask for.
pub fn parse_updates(body: &str) -> (Vec<Update>, Option<i64>) {
    let j = match Json::parse(body) {
        Ok(j) => j,
        Err(_) => return (vec![], None),
    };
    if !j.bool_of("ok") {
        return (vec![], None);
    }
    let mut out = Vec::new();
    let mut next = None;
    for u in j.arr_of("result") {
        let id = u.i64_of("update_id");
        next = Some(next.map_or(id + 1, |n: i64| n.max(id + 1)));
        if let Some(m) = u.get("message") {
            let chat = m.get("chat").map(|c| c.i64_of("id")).unwrap_or(0);
            let text = m.str_of("text");
            if chat != 0 && !text.is_empty() {
                out.push(Update { id, chat, text });
            }
        }
    }
    (out, next)
}

pub fn is_admin(admins: &[i64], chat: i64) -> bool {
    admins.contains(&chat)
}

/// Human text for the `pool.status` reply.
pub fn format_pool(json: &str) -> String {
    let j = match Json::parse(json.trim()) {
        Ok(j) => j,
        Err(_) => return json.trim().to_string(),
    };
    if !j.bool_of("ok") {
        return format!("pool: {}", j.str_of("error"));
    }
    let mut s = format!("Pool mode: {}{}\n", j.str_of("mode"), if j.bool_of("manual_failback") { " (manual failback)" } else { "" });
    for m in j.arr_of("members") {
        let mut flags = Vec::new();
        if m.bool_of("standby") {
            flags.push("standby");
        }
        if m.bool_of("drain") {
            flags.push("drain");
        }
        if m.bool_of("serving") {
            flags.push("serving");
        }
        s.push_str(&format!(
            "{} {}  links={} rtt={:.0}ms w={} p={}{}\n",
            if m.bool_of("up") { "UP  " } else { "DOWN" },
            m.str_of("addr"),
            m.i64_of("links"),
            m.num_of("rtt_ms"),
            m.i64_of("weight"),
            m.i64_of("priority"),
            if flags.is_empty() { String::new() } else { format!("  [{}]", flags.join(",")) }
        ));
    }
    s
}

pub fn clip(s: &str) -> String {
    const MAX: usize = 3500;
    if s.chars().count() <= MAX {
        s.to_string()
    } else {
        let mut o: String = s.chars().take(MAX).collect();
        o.push_str("\n…");
        o
    }
}

fn cfg_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n"))
}

/// curl `-K -` config for one Bot API call.
pub fn api_config(token: &str, method: &str, form: &[(&str, String)]) -> String {
    let mut c = format!("url = {}\n", cfg_quote(&format!("https://api.telegram.org/bot{token}/{method}")));
    for (k, v) in form {
        c.push_str(&format!("data-urlencode = {}\n", cfg_quote(&format!("{k}={v}"))));
    }
    c
}

pub fn api_call(token: &str, method: &str, form: &[(&str, String)], max_secs: u32) -> anyhow::Result<String> {
    let mut c = Command::new("curl")
        .args(["-sS", "-m", &max_secs.to_string(), "-K", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    if let Some(mut si) = c.stdin.take() {
        si.write_all(api_config(token, method, form).as_bytes())?;
    }
    let out = c.wait_with_output()?;
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Long-poll loop. `handle` turns a command into reply text.
pub async fn run<F, Fut>(token: String, admins: Vec<i64>, mut handle: F) -> anyhow::Result<()>
where
    F: FnMut(Cmd) -> Fut,
    Fut: std::future::Future<Output = String>,
{
    let mut offset: i64 = 0;
    eprintln!("[tgbot] running for {} admin chat(s)", admins.len());
    loop {
        let t = token.clone();
        let off = offset;
        let body = tokio::task::spawn_blocking(move || {
            api_call(&t, "getUpdates", &[("timeout", "25".into()), ("offset", off.to_string())], 40)
        })
        .await??;
        let (updates, next) = parse_updates(&body);
        if let Some(n) = next {
            offset = n;
        }
        if updates.is_empty() && next.is_none() {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await; // network trouble: do not spin
        }
        for u in updates {
            let Some(cmd) = parse_command(&u.text) else { continue };
            if !is_admin(&admins, u.chat) {
                eprintln!("[tgbot] ignored command from non-admin chat {}", u.chat);
                continue;
            }
            let reply = clip(&handle(cmd).await);
            let t = token.clone();
            let _ = tokio::task::spawn_blocking(move || {
                api_call(&t, "sendMessage", &[("chat_id", u.chat.to_string()), ("text", reply)], 15)
            })
            .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands() {
        assert_eq!(parse_command("/status"), Some(Cmd::Status));
        assert_eq!(parse_command("/Pool@my_bot"), Some(Cmd::Pool));
        assert_eq!(parse_command("/drain 1.2.3.4:443"), Some(Cmd::Drain("1.2.3.4:443".into())));
        assert_eq!(parse_command("/drain"), Some(Cmd::Unknown("drain".into())));
        assert_eq!(parse_command("/rm -rf /"), Some(Cmd::Unknown("rm".into())));
        assert_eq!(parse_command("hello"), None);
    }

    #[test]
    fn updates_parse_and_offset() {
        let body = r#"{"ok":true,"result":[
          {"update_id":10,"message":{"chat":{"id":555},"text":"/status"}},
          {"update_id":11,"message":{"chat":{"id":-100},"text":"/pool"}},
          {"update_id":12,"edited_message":{"chat":{"id":1},"text":"x"}}]}"#;
        let (u, next) = parse_updates(body);
        assert_eq!(u.len(), 2);
        assert_eq!(u[0], Update { id: 10, chat: 555, text: "/status".into() });
        assert_eq!(u[1].chat, -100);
        assert_eq!(next, Some(13));
        assert_eq!(parse_updates("garbage"), (vec![], None));
        assert_eq!(parse_updates(r#"{"ok":false}"#), (vec![], None));
    }

    #[test]
    fn admin_gate() {
        assert!(is_admin(&[1, 2], 2) && !is_admin(&[1, 2], 3) && !is_admin(&[], 0));
    }

    #[test]
    fn pool_text() {
        let j = r#"{"ok":true,"mode":"balance","manual_failback":false,"policy":true,"members":[
          {"addr":"1.1.1.1:443","up":true,"links":7,"rtt_ms":31.4,"weight":3,"priority":0,"standby":false,"drain":false,"serving":true},
          {"addr":"2.2.2.2:443","up":false,"links":0,"rtt_ms":0.0,"weight":1,"priority":1,"standby":true,"drain":true,"serving":false}]}"#;
        let t = format_pool(j);
        assert!(t.contains("Pool mode: balance") && t.contains("UP   1.1.1.1:443  links=7 rtt=31ms w=3 p=0  [serving]"), "{t}");
        assert!(t.contains("DOWN 2.2.2.2:443") && t.contains("[standby,drain]"), "{t}");
    }

    #[test]
    fn config_keeps_token_out_of_argv_and_escapes() {
        let c = api_config("1:ABC", "sendMessage", &[("chat_id", "5".into()), ("text", "a \"b\"\nc".into())]);
        assert!(c.contains("bot1:ABC/sendMessage") && c.contains("text=a \\\"b\\\"\\nc"), "{c}");
        assert!(clip(&"x".repeat(5000)).chars().count() < 3600);
    }
}

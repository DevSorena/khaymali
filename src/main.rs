use khaymali::{
    alerts, autopilot, backup, bridge, camo, carrier_swap, cluster_lb, cluster_mesh, dial_route,
    engines, entry, exit, fleet, forward, harsh_nlp, kani_nlp, l3, l3_wraps, link, node_cluster,
    ops_suite, pathtest, pool, rescue, revpath, setup_bundle, spoof_carrier, sshfwd, stats, sysrun,
    tgbot, transport, transport_engine, util, xray_engine,
};
use khaymali::intelligence::{simulate_packet_twin, AdaptiveExperimentManager, CalibrationExample, DigitalTwinConfig, HardResourceBudget, NetworkSample, RiskCalibrator, TwinScenario};
use khaymali::kani_nlp::{CandidatePromotionDecision, NetIntent, NlpAdvisor};

use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tokio::time::timeout;
use util::{check_code_short, hex, root_check_code, sha256_hex, unhex};

struct Args(HashMap<String, Vec<String>>);

impl Args {
    fn parse(rest: &[String]) -> Args {
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
    fn get(&self, k: &str) -> Option<String> {
        self.0.get(k).and_then(|v| v.last().cloned())
    }
    fn all(&self, k: &str) -> Vec<String> {
        self.0.get(k).cloned().unwrap_or_default()
    }
    fn req(&self, k: &str) -> Result<String> {
        self.get(k).with_context(|| format!("missing --{k}"))
    }
    fn flag(&self, k: &str) -> bool {
        self.0.contains_key(k)
    }
    fn num(&self, k: &str, d: usize) -> usize {
        self.get(k).and_then(|v| v.parse().ok()).unwrap_or(d)
    }
    fn key(&self) -> Result<Vec<u8>> {
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
    fn pubkeys(&self, k: &str) -> Result<Vec<Vec<u8>>> {
        self.all(k)
            .iter()
            .map(|h| {
                let b = unhex(h)?;
                if b.len() != 32 {
                    bail!("--{k}: public keys are 32 bytes (64 hex chars)");
                }
                Ok(b)
            })
            .collect()
    }
    fn camo(&self, client: bool) -> Result<Option<camo::CamoCfg>> {
        let Some(h) = self.get("camo-secret").or_else(|| std::env::var("KHAYMALI_CAMO_SECRET").ok()) else {
            return Ok(None);
        };
        let secret = unhex(&h)?;
        if secret.len() < 16 {
            bail!("--camo-secret must be at least 16 bytes of hex (generate one with `khaymali secret`)");
        }
        let sni = if client { self.req("camo-sni")? } else { self.get("camo-sni").unwrap_or_default() };
        let pad_max = self.num("camo-pad", 48);
        if pad_max > 1000 {
            bail!("--camo-pad too large (max 1000)");
        }
        Ok(Some(camo::CamoCfg { secret, sni, fallback: self.get("camo-fallback"), pad_max }))
    }
}

/// Compact self-contained `khaymali://` Join Code URI.
pub fn encode_join_code(
    endpoint: &str,
    exit_pub_hex: &str,
    transport: &str,
    sni: &str,
    secret_hex: &str,
    forwards: &str,
) -> String {
    let mut params = vec![
        format!("ep={endpoint}"),
        format!("pk={exit_pub_hex}"),
        format!("tr={transport}"),
    ];
    if !sni.is_empty() {
        params.push(format!("sni={sni}"));
    }
    if !secret_hex.is_empty() {
        params.push(format!("sec={secret_hex}"));
    }
    if !forwards.is_empty() {
        params.push(format!("fwd={forwards}"));
    }
    format!("khaymali://v1?{}", params.join("&"))
}

pub fn decode_join_code(code: &str) -> Result<HashMap<String, String>> {
    let body = code
        .trim()
        .strip_prefix("khaymali://v1?")
        .context("invalid join code (expected 'khaymali://v1?...')")?;
    let mut out = HashMap::new();
    for pair in body.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = pair.split_once('=').context("malformed join code parameter")?;
        out.insert(k.to_string(), v.to_string());
    }
    if !out.contains_key("ep") || !out.contains_key("pk") {
        bail!("join code missing required 'ep' or 'pk' fields");
    }
    Ok(out)
}

#[cfg(unix)]
async fn send_control_rpc(sock_path: &str, payload: &str) -> Result<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;
    let mut s = UnixStream::connect(sock_path)
        .await
        .with_context(|| format!("cannot connect to control socket {sock_path}"))?;
    s.write_all(payload.as_bytes()).await?;
    if !payload.ends_with('\n') {
        s.write_all(b"\n").await?;
    }
    let mut resp = String::new();
    s.read_to_string(&mut resp).await?;
    Ok(resp)
}

fn usage() {
    eprintln!(
        "khaymali {ver}  (Khaymali Pure Tunneling Suite)

  khaymali ui | menu                    live dashboard (TUI) | setup & management menu
  khaymali keygen                       new static keypair + 12-char check code + SHA-256 fingerprint
  khaymali secret                       new random camouflage secret
  khaymali check-code <HEX_PUBKEY>      print UI tag, 12-char check code & full SHA-256 fingerprint
  khaymali join-code --endpoint HOST:PORT --exit-pub PUB [--transport auto|udp|ktunnel|camo|tcp]
                     [--camo-sni NAME] [--camo-secret HEX] [--forward 443,2052]
  khaymali parse-join <JOIN_CODE>       decode a khaymali://v1?... join code into CLI flags
  khaymali status [--control SOCK]      query live status from running service control socket
  khaymali forward add|ls|rm ...        manage live port forwards on running Entry
  khaymali tgbot --token T --admin CHAT_ID   Telegram control bot (admin chats only)
  khaymali backup run|list|verify|restore     encrypted config backups (--pass-file, --dir, --keep)
  khaymali pool status|drain|undrain|failback   multi-Exit pool control on running Entry
  khaymali autopilot [--state FILE]     show Autopilot history
  khaymali pathtest serve|run ...       end-to-end multi-carrier path test & benchmark (pt1_...)
  khaymali revpath check|fix ...        6-layer Reverse-Path Doctor & safe auto-fix
  khaymali carrier wrap|mtu|pair|swap|swap-bundle|swap-foreign-serve
                                        GRE wraps (direct|wss|6to4|4in6), MTU keeper, /30 pair, live swap
  khaymali dial status|set <MODE>       smart dial route (auto|gre|public) on running Entry
  khaymali health [--control SOCK]      3-layer tunnel health check (service+session+data)
  khaymali rescue check|egress ...      one-way block detector & Telegram/Cloudflare Egress SOCKS5 bridge
  khaymali spoof gen|parse|import|apply|stop|status|run-native|tester
                                        Spoof+WireGuard & native raw-socket spoof carrier
  khaymali bundle parse|make-frp|make-backhaul|make-gre-backhaul
                                        hsh1_ / bh1_ / gh1_ tunnel setup bundles
  khaymali setup iran|foreign|from-bundle ... [--plan]
                                        transactional FRP / Backhaul / GRE+Backhaul tunnel setup
  khaymali sshfwd gen|apply|lock-key    SSH port-forward engine & restricted authorized_keys lock
  khaymali xray keygen|gen ...          Xray REALITY/VLESS keygen, server/Iran-bridge JSON & URI
  khaymali mesh hub-fwd|join-code|serve|add|remove
                                        Iran-to-Iran Hub Mesh (/_hc) & DNS failover
  khaymali lb nft|serve ...             multi-mode Cluster Load Balancer (failover|balance|sticky|latency|least)
  khaymali node probe|fleet ...         tunnel node RTT probing & fleet registry
  khaymali ops doctor|tune [--apply]    kernel sysctl BBR/FQ/MTU tuning & tunnel readiness doctor
  khaymali harsh-nlp eval|status|mode   Harsh-Network Micro-NLP (shadow/active, auto-rollback, 180s lockout)
  khaymali up | down [role]             start or stop systemd khaymali services
  khaymali doctor                       local host/clock/artifact/loopback readiness check
  khaymali diagnose <SYMPTOM_TEXT>      offline KANI TinyNetNlp symptom classifier (--stdin | --stdin-combined)
  khaymali intelligence-lab [OPTIONS]   offline deterministic packet/queue digital twin
  khaymali calibrate-risk <TR> <HO> <O> fit Platt risk calibrator artifact
  khaymali promote-nlp-candidate <HO>   evaluate & promote staged NLP candidate artifact
  khaymali transports                   list registered carriers & capabilities
  khaymali verify-config <FILE> <KEY>   verify SignedConfig HMAC & anti-rollback revision

  khaymali exit   --listen ADDR [--udp-listen ADDR] [--ktunnel-listen ADDR]
                  [--ws-listen ADDR] [--wss-listen ADDR]
                  [--reverse-entry HOST:PORT [--reverse-pool N]]
                  --key HEX --allow ENTRY_PUB [--allow ...] [--allow-private]
                  [--tun IFNAME [--tun-cidr 10.200.0.1/30]]
                  [--camo-secret HEX --camo-fallback HOST:PORT [--camo-pad N]]
                  [--metrics ADDR] [--control /run/khaymali/exit.sock]

  khaymali entry  --key HEX --exit-pub EXIT_PUB [--socks ADDR] [--pool N] [--max-age SECS]
                  [--listen-exit ADDR] [--tun khaymali0]
                  [--mux-carriers N] [--no-mux] [--no-session-resume] [--pool-max N] [--no-adapt] [--adapt-state FILE|off]
                  [--bridge-listen ADDR --allow-bridge BRIDGE_PUB [--allow-bridge ...] [--require-channel-binding]]
                  [--exit HOST:PORT|auto://|udp://|ktunnel://|ws://|wss://|ssh://|spoof://...[;w=N;p=N;max=N;standby;drain] [--exit ...]]
                  [--pool-mode failover|balance|sticky|latency|least] [--failback auto|manual]
                  [--autopilot [--ap-down MIN] [--ap-cooldown MIN] [--ap-per-day N] [--ap-no-path-test]
                                [--ap-quiet FROM-TO] [--ap-carriers tcp,udp,ktunnel,ws,wss,ssh,spoof,auto] [--ap-state FILE|off]]
                  [--alert-webhook URL] [--alert-telegram BOT_TOKEN:CHAT_ID] [--alert-proxy socks5h://127.0.0.1:1088]
                  [--egress-bridge 127.0.0.1:1088] [--dial-mode auto|gre|public --dial-gre-addr IP:PORT --dial-public-addr IP:PORT]
                  [--camo-secret HEX --camo-sni NAME [--camo-pad N]]
                  [--forward 443,2052|SPEC [--forward ...]] [--metrics ADDR] [--control /run/khaymali/entry.sock]

  khaymali bridge --key HEX --entry HOST:PORT --entry-pub ENTRY_PUB --exit HOST:PORT [--exit ...]
                  [--pool N] [--no-adapt] [--adapt-state FILE|off] [--camo-secret HEX --camo-sni NAME [--camo-pad N]]
                  [--metrics ADDR] [--control /run/khaymali/bridge.sock]

  khaymali tun    --key HEX --exit-pub EXIT_PUB --exit HOST:PORT|auto://HOST:PORT|udp://HOST:PORT
                  [--tun khaymali0] [--cidr 10.200.0.2/30] [--peer-ip 10.200.0.1]
                  [--mode tun|gre|ipip] [--mtu 1380] [--route CIDR [--route ...]] [--allow-private]
                  [--camo-secret HEX --camo-sni NAME [--camo-pad N]]

  Secrets via env: KHAYMALI_KEY, KHAYMALI_CAMO_SECRET, KHAYMALI_NLP_MODE (shadow|active|off).
  Specification: docs/SPEC.md | Tunneling Suite: docs/KHAYMALI_TUNNELING_SUITE.md",
        ver = env!("CARGO_PKG_VERSION")
    );
}

fn adapt_state_path(a: &Args, role: &str) -> Option<String> {
    match a.get("adapt-state") {
        Some(p) if p == "off" => None,
        Some(p) => Some(p),
        None => std::path::Path::new("/var/lib/khaymali")
            .is_dir()
            .then(|| format!("/var/lib/khaymali/{role}-adapt.state")),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // `khaymali status | head`, `... | grep -q`: when the reader closes early, Rust's `println!`
    // panics with "Broken pipe" and prints a backtrace. A closed pipe on the main thread is not an
    // error worth a panic, so leave quietly (worker-thread panics keep the default handler).
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let msg = info
            .payload()
            .downcast_ref::<String>()
            .map(|s| s.as_str())
            .or_else(|| info.payload().downcast_ref::<&str>().copied())
            .unwrap_or("");
        if std::thread::current().name() == Some("main") && msg.contains("Broken pipe") {
            std::process::exit(0);
        }
        default_hook(info);
    }));
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = argv.first().cloned() else {
        usage();
        return Ok(());
    };
    let a = Args::parse(&argv[1..]);
    match cmd.as_str() {
        "ui" | "tui" | "menu" | "dashboard" => {
            // `khaymali ui` -> live dashboard, `khaymali menu` -> setup menu (same look on every server)
            let tool = if cmd == "menu" { "khaymali-manager" } else { "khaymali-tui" };
            let rest: Vec<String> = argv[1..].to_vec();
            let st = std::process::Command::new(tool).args(&rest).status();
            match st {
                Ok(s) => std::process::exit(s.code().unwrap_or(1)),
                Err(e) => bail!("{tool} not found ({e}); reinstall with install.sh or run khaymali-manager update-manager"),
            }
        }
        "keygen" => {
            let (sk, pk) = link::keygen()?;
            println!(
                "private:    {}
public:     {}
ui-tag:     {}
check-code: {}
sha256:     {}",
                hex(&sk),
                hex(&pk),
                check_code_short(&pk),
                root_check_code(&pk),
                sha256_hex(&pk),
            );
        }
        "secret" => println!("{}", hex(&util::rand_bytes::<32>())),
        "check-code" => {
            let h = argv.get(1).context("usage: khaymali check-code <HEX_PUBKEY>")?;
            let raw = unhex(h)?;
            println!(
                "ui-tag:     {}
check-code: {}
sha256:     {}",
                check_code_short(&raw),
                root_check_code(&raw),
                sha256_hex(&raw),
            );
        }
        "join-code" => {
            let ep = a.req("endpoint")?;
            let pk = a.req("exit-pub")?;
            let tr = a.get("transport").unwrap_or_else(|| "auto".to_string());
            let sni = a.get("camo-sni").unwrap_or_default();
            let sec = a.get("camo-secret").unwrap_or_default();
            let fwd = a.get("forward").unwrap_or_default();
            println!("{}", encode_join_code(&ep, &pk, &tr, &sni, &sec, &fwd));
        }
        "parse-join" => {
            let code = argv.get(1).context("usage: khaymali parse-join <khaymali://v1?...>")?;
            let m = decode_join_code(code)?;
            let ep = m.get("ep").unwrap();
            let pk = m.get("pk").unwrap();
            let tr = m.get("tr").map(|s| s.as_str()).unwrap_or("auto");
            let exit_uri = match tr {
                "auto" => format!("auto://{ep}"),
                "udp" => format!("udp://{ep}"),
                "ktunnel" => format!("ktunnel://{ep}"),
                "ws" => format!("ws://{ep}"),
                "wss" => format!("wss://{ep}"),
                "ssh" => format!("ssh://{ep}"),
                "spoof" => format!("spoof://{ep}"),
                _ => ep.clone(),
            };
            println!("endpoint:   {ep}");
            println!("exit-pub:   {pk}");
            println!("transport:  {tr}");
            println!("exit-uri:   {exit_uri}");
            if let Some(sni) = m.get("sni") {
                println!("camo-sni:   {sni}");
            }
            if let Some(sec) = m.get("sec") {
                println!("camo-secret:{sec}");
            }
            if let Some(fwd) = m.get("fwd") {
                println!("forward:    {fwd}");
            }
        }
        "status" => {
            #[cfg(unix)]
            {
                let sock = a.get("control").unwrap_or_else(|| "/run/khaymali/entry.sock".to_string());
                let resp = send_control_rpc(&sock, "{\"method\":\"status\"}").await?;
                print!("{resp}");
            }
            #[cfg(not(unix))]
            bail!("status command requires Unix domain sockets");
        }
        "forward" => {
            #[cfg(unix)]
            {
                let sub = argv.get(1).map(|s| s.as_str()).unwrap_or("ls");
                let sock = a.get("control").unwrap_or_else(|| "/run/khaymali/entry.sock".to_string());
                match sub {
                    "add" => {
                        let spec = argv.get(2).context("usage: khaymali forward add <SPEC>")?;
                        let rpc = format!("{{\"method\":\"forwards.add\",\"spec\":\"{}\"}}", spec.replace('"', "\\\""));
                        let resp = send_control_rpc(&sock, &rpc).await?;
                        print!("{resp}");
                    }
                    "rm" | "remove" | "del" => {
                        let port = argv.get(2).context("usage: khaymali forward rm <PORT>")?;
                        let rpc = format!("{{\"method\":\"forwards.remove\",\"port\":\"{}\"}}", port.replace('"', "\\\""));
                        let resp = send_control_rpc(&sock, &rpc).await?;
                        print!("{resp}");
                    }
                    "ls" | "list" => {
                        let resp = send_control_rpc(&sock, "{\"method\":\"forwards.list\"}").await?;
                        print!("{resp}");
                    }
                    _ => bail!("usage: khaymali forward add <SPEC> | ls | rm <PORT>"),
                }
            }
            #[cfg(not(unix))]
            bail!("forward CLI requires Unix domain sockets");
        }
        "autopilot" => {
            let path = a.get("state").unwrap_or_else(|| "/var/lib/khaymali/autopilot.state".into());
            print!("{}", autopilot::status_text(&path));
        }
        "pool" => {
            #[cfg(unix)]
            {
                let sub = argv.get(1).map(|s| s.as_str()).unwrap_or("status");
                let sock = a.get("control").unwrap_or_else(|| "/run/khaymali/entry.sock".to_string());
                let rpc = match sub {
                    "status" | "ls" => "{\"method\":\"pool.status\"}".to_string(),
                    "drain" | "undrain" => {
                        let addr = argv.get(2).context("usage: khaymali pool drain|undrain <EXIT_ADDR>")?;
                        format!("{{\"method\":\"pool.{sub}\",\"addr\":\"{}\"}}", addr.replace('"', ""))
                    }
                    "failback" => "{\"method\":\"pool.failback\"}".to_string(),
                    _ => bail!("usage: khaymali pool status | drain <ADDR> | undrain <ADDR> | failback"),
                };
                print!("{}", send_control_rpc(&sock, &rpc).await?);
            }
            #[cfg(not(unix))]
            bail!("pool CLI requires Unix domain sockets");
        }
        "pathtest" => {
            let sub = argv.get(1).map(|s| s.as_str()).unwrap_or("help");
            match sub {
                "serve" => {
                    let host = a.req("host")?;
                    let host6 = a.get("host6");
                    let base_port = a.num("base-port", 24000) as u16;
                    let ssh_port = a.num("ssh-port", 22) as u16;
                    let sni = a.get("sni").unwrap_or_else(|| "www.cloudflare.com".into());
                    let minutes = a.num("minutes", 5) as u16;
                    pathtest::serve(host, host6, base_port, ssh_port, sni, minutes).await?;
                }
                "run" => {
                    let code = argv.get(2).context("usage: khaymali pathtest run <pt1_CODE>")?;
                    let results = pathtest::run_client(code).await?;
                    print!("{}", pathtest::format_table(&results));
                }
                _ => bail!("usage: khaymali pathtest serve --host IP [--host6 IP6] [--base-port 24000] | run <pt1_CODE>"),
            }
        }
        "revpath" => {
            let sub = argv.get(1).map(|s| s.as_str()).unwrap_or("check");
            let iface = a.get("iface").unwrap_or_else(|| "khaymali0".into());
            let local_inner = a.get("local-inner").unwrap_or_default();
            let peer_inner = a.get("peer-inner").unwrap_or_default();
            let peer_pub = a.get("peer-pub").unwrap_or_default();
            let ctrl_port = a.num("ctrl-port", 443) as u16;
            let wss_port = a.get("wss-port").and_then(|v| v.parse::<u16>().ok());
            let diag = revpath::run_live_check(&iface, &local_inner, &peer_inner, &peer_pub, ctrl_port, wss_port).await;
            println!("verdict:      {}", diag.verdict.as_str());
            println!("confidence:   {}", diag.confidence);
            println!("auto_fixable: {}", diag.auto_fixable);
            println!("suggestion:   {}", diag.suggested_fix);
            for e in &diag.evidence {
                println!("  evidence:   {e}");
            }
            if !diag.fix_commands.is_empty() {
                println!("fix plan ({} command(s)):", diag.fix_commands.len());
                for c in &diag.fix_commands {
                    println!("  $ {}", c.join(" "));
                }
            }
            if sub == "fix" && a.flag("apply") {
                if !diag.auto_fixable || diag.fix_commands.is_empty() {
                    println!("No automatic fix available for verdict {}", diag.verdict.as_str());
                } else {
                    for c in &diag.fix_commands {
                        let st = std::process::Command::new(&c[0]).args(&c[1..]).status();
                        println!("  applied [{}]: {}", if st.map(|s| s.success()).unwrap_or(false) { "OK" } else { "WARN" }, c.join(" "));
                    }
                }
            }
        }
        "carrier" => {
            let sub = argv.get(1).map(|s| s.as_str()).unwrap_or("help");
            match sub {
                "wrap" => {
                    let kind = argv.get(2).context("usage: khaymali carrier wrap direct|wss|6to4|4in6 --iface IF --local-inner IP --peer-inner IP ...")?;
                    let iface = a.get("iface").unwrap_or_else(|| "gre-tunnel".into());
                    let inner_local: Ipv4Addr = a.req("local-inner")?.parse().context("invalid --local-inner")?;
                    let inner_remote: Ipv4Addr = a.req("peer-inner")?.parse().context("invalid --peer-inner")?;
                    let wrap = match kind.as_str() {
                        "direct" => l3_wraps::GreWrapKind::Direct {
                            local_v4: a.req("local-v4")?.parse().context("invalid --local-v4")?,
                            remote_v4: a.req("remote-v4")?.parse().context("invalid --remote-v4")?,
                        },
                        "6to4" => l3_wraps::GreWrapKind::SixToFour {
                            local_v4: a.req("local-v4")?.parse().context("invalid --local-v4")?,
                            remote_v4: a.req("remote-v4")?.parse().context("invalid --remote-v4")?,
                        },
                        "4in6" => l3_wraps::GreWrapKind::FourInSix {
                            local_v6: a.req("local-v6")?.parse().context("invalid --local-v6")?,
                            remote_v6: a.req("remote-v6")?.parse().context("invalid --remote-v6")?,
                        },
                        "wss" => l3_wraps::GreWrapKind::Wss {
                            remote_host: a.get("remote").unwrap_or_default(),
                            port: a.num("port", 8443) as u16,
                            sni: a.get("sni").unwrap_or_else(|| "www.cloudflare.com".into()),
                        },
                        other => bail!("unknown wrap '{other}' (expected direct|wss|6to4|4in6)"),
                    };
                    let mtu = a.num("mtu", wrap.recommended_mtu() as usize) as u16;
                    let cmds = wrap.render_apply_commands(&iface, inner_local, inner_remote, mtu)?;
                    println!("carrier wrap={} iface={} mtu={} mss={}:", wrap.name(), iface, mtu, mtu.saturating_sub(40));
                    for c in &cmds {
                        println!("  $ {}", c.join(" "));
                    }
                    if a.flag("apply") {
                        wrap.apply(&iface, inner_local, inner_remote, mtu)?;
                        println!("Applied successfully.");
                    } else {
                        println!("(dry-run; pass --apply to execute)");
                    }
                }
                "mtu" => {
                    let state = a.get("file").unwrap_or_else(|| l3_wraps::DEFAULT_MTU_FILE.into());
                    let keeper = l3_wraps::PathMtuKeeper::new(state, l3_wraps::MTU_DIRECT_GRE);
                    match argv.get(2).map(|s| s.as_str()) {
                        Some("set") => {
                            let val: u16 = argv.get(3).context("usage: khaymali carrier mtu set <1280..1420>")?.parse()?;
                            let saved = keeper.set(val)?;
                            println!("mtu={saved} mss={}", keeper.mss_clamp_value());
                        }
                        Some("step-down") => {
                            let next = keeper.step_down();
                            println!("mtu={next} mss={}", keeper.mss_clamp_value());
                        }
                        _ => println!("mtu={} mss={}", keeper.current(), keeper.mss_clamp_value()),
                    }
                }
                "pair" => {
                    let mut used = Vec::new();
                    for raw in a.all("used") {
                        if let Some((ip_s, pfx_s)) = raw.split_once('/') {
                            if let (Ok(ip), Ok(pfx)) = (ip_s.parse::<Ipv4Addr>(), pfx_s.parse::<u8>()) {
                                used.push((ip, pfx));
                            }
                        }
                    }
                    let (a_ip, b_ip) = l3_wraps::GrePairAllocator::allocate_free(&used)?;
                    println!("iran_inner:    {a_ip}/30
foreign_inner: {b_ip}/30");
                }
                "swap" => {
                    #[cfg(unix)]
                    {
                        let target = argv.get(2).context("usage: khaymali carrier swap <EXIT_ADDR|auto>")?;
                        let sock = a.get("control").unwrap_or_else(|| "/run/khaymali/entry.sock".into());
                        let rpc = format!("{{\"method\":\"carrier.swap\",\"addr\":\"{}\"}}", target.replace('"', ""));
                        print!("{}", send_control_rpc(&sock, &rpc).await?);
                    }
                    #[cfg(not(unix))]
                    bail!("carrier swap requires Unix domain sockets");
                }
                "swap-bundle" => {
                    let to = carrier_swap::CarrierChoice::parse(&a.req("to")?)?;
                    let raw_ports = setup_bundle::parse_raw_ports(&a.get("ports").unwrap_or_default());
                    let t = carrier_swap::SwapTunnel {
                        id: a.num("id", 0) as u32,
                        name: a.get("name").unwrap_or_else(|| "main".into()),
                        main: a.num("id", 0) == 0,
                        current: carrier_swap::CarrierChoice::parse(&a.get("from").unwrap_or_else(|| "frp:tcp".into()))?,
                        gre_ok: !a.flag("no-gre"),
                        ctrl_port: a.num("ctrl-port", 7000) as u16,
                        remote_pub: a.get("remote-pub").unwrap_or_default(),
                        local_pub: a.req("local-pub")?,
                        local_gre: a.get("local-gre").unwrap_or_else(|| "10.10.0.1".into()),
                        peer_gre: a.get("peer-gre").unwrap_or_else(|| "10.10.0.2".into()),
                        token: a.req("token")?,
                        ports: setup_bundle::extract_numeric_ports(&raw_ports),
                        raw_ports,
                        udp_companion_port: a.num("udp-port", 0) as u16,
                    };
                    println!("{}", t.manual_bundle(&to));
                }
                "swap-foreign-serve" => {
                    let bind = a.get("bind").unwrap_or_else(|| "0.0.0.0:18082".into());
                    let secret = a.req("secret")?;
                    if a.flag("dry-run") {
                        sysrun::set_dry_run_global(true);
                    }
                    let paths = engines::EnginePaths::default();
                    let token = a.get("token").unwrap_or_default();
                    let agent = carrier_swap::ForeignSwapAgent::new(
                        secret,
                        std::sync::Arc::new(move |choice, req| {
                            let sr = engines::SetupRequest {
                                role: "foreign".into(),
                                engine: choice.engine.clone(),
                                transport: choice.transport.clone(),
                                local_pub: String::new(),
                                remote_pub: req.remote.clone(),
                                ctrl_port: if req.port == 0 { 7000 } else { req.port },
                                local_gre: String::new(),
                                peer_gre: req.peer_gre.clone(),
                                token: token.clone(),
                                raw_ports: if req.raw.is_empty() {
                                    req.ports.iter().map(|p| p.to_string()).collect()
                                } else {
                                    req.raw.clone()
                                },
                                accept_udp: false,
                                udp_companion_port: 0,
                                connection_pool: engines::BH_POOL_DEFAULT,
                                peer_id: 0,
                                frp_perf: engines::FrpPerfOpts::default(),
                                fou_port1: 443,
                                fou_port2: 55555,
                            };
                            let _ = engines::apply_setup(&sr, &paths)?;
                            Ok(())
                        }),
                    );
                    let listener = tokio::net::TcpListener::bind(&bind).await?;
                    println!("ForeignSwapAgent listening on {bind}");
                    agent.serve_listener(listener).await?;
                }
                _ => bail!("usage: khaymali carrier wrap|mtu|pair|swap|swap-bundle|swap-foreign-serve ..."),
            }
        }
        "dial" => {
            #[cfg(unix)]
            {
                let sub = argv.get(1).map(|s| s.as_str()).unwrap_or("status");
                let sock = a.get("control").unwrap_or_else(|| "/run/khaymali/entry.sock".into());
                let rpc = match sub {
                    "status" => "{\"method\":\"dial.status\"}".to_string(),
                    "set" => {
                        let m = argv.get(2).context("usage: khaymali dial set auto|gre|public")?;
                        format!("{{\"method\":\"dial.set\",\"mode\":\"{}\"}}", m.replace('"', ""))
                    }
                    _ => bail!("usage: khaymali dial status | set auto|gre|public"),
                };
                print!("{}", send_control_rpc(&sock, &rpc).await?);
            }
            #[cfg(not(unix))]
            bail!("dial CLI requires Unix domain sockets");
        }
        "health" => {
            #[cfg(unix)]
            {
                let sock = a.get("control").unwrap_or_else(|| "/run/khaymali/entry.sock".into());
                print!("{}", send_control_rpc(&sock, "{\"method\":\"health.three_layer\"}").await?);
                print!("{}", send_control_rpc(&sock, "{\"method\":\"carriers.summary\"}").await?);
            }
            #[cfg(not(unix))]
            bail!("health CLI requires Unix domain sockets");
        }
        "rescue" => {
            let sub = argv.get(1).map(|s| s.as_str()).unwrap_or("check");
            match sub {
                "check" => {
                    let peer = a.req("peer")?;
                    let port = a.num("port", 443) as u16;
                    let listen_port = a.num("listen-port", 4445) as u16;
                    let r = rescue::detect_one_way_block(&peer, port, listen_port).await;
                    println!("icmp_ok={} tcp_outbound_ok={} one_way_suspected={}
{}", r.icmp_ok, r.tcp_outbound_ok, r.one_way_suspected, r.rescue_advice);
                }
                "egress" => {
                    let bind = a.get("bind").unwrap_or_else(|| "127.0.0.1:1088".into());
                    let socks = a.get("socks").unwrap_or_else(|| "127.0.0.1:1080".into());
                    let extra = a.all("allow-host");
                    rescue::serve_egress_bridge(bind, socks, extra).await?;
                }
                _ => bail!("usage: khaymali rescue check --peer IP [--port 443] | egress [--bind 127.0.0.1:1088 --socks 127.0.0.1:1080]"),
            }
        }
        "spoof" => {
            let sub = argv.get(1).map(|s| s.as_str()).unwrap_or("gen");
            let paths = spoof_carrier::SpoofPaths::default();
            if a.flag("dry-run") || a.flag("plan") {
                sysrun::set_dry_run_global(true);
            }
            match sub {
                "gen" => {
                    let role = spoof_carrier::SpoofRole::parse(&a.get("role").unwrap_or_else(|| "local".into()))?;
                    let local_ip = a.req("local-ip")?;
                    let peer_ip = a.req("peer-ip")?;
                    let mut cfg = spoof_carrier::SpoofConfig::new_default(role, local_ip, peer_ip);
                    cfg.ensure_keys()?;
                    cfg.ensure_peer_keypair()?;
                    cfg.spoof_ips = spoof_carrier::SpoofConfig::clean_spoof_ips(&[a.req("spoof-ips")?]);
                    if let Some(st) = a.get("send") { cfg.send_transport = spoof_carrier::SpoofTransport::parse(&st)?; }
                    if let Some(rt) = a.get("recv") { cfg.recv_transport = spoof_carrier::SpoofTransport::parse(&rt)?; }
                    if let Some(fp) = a.get("forward") {
                        cfg.set_forward_ports(&fp, &[])?;
                    }
                    cfg.validate()?;
                    println!("=== /etc/spoof/config.json ===\n{}", cfg.render_spoof_core_json());
                    println!("=== /etc/wireguard/wg-spoof.conf ===\n{}", cfg.render_wg_conf());
                    let nft = cfg.render_forward_nft();
                    if !nft.is_empty() {
                        println!("=== /etc/spoof/forward.nft ===\n{nft}");
                    }
                    if cfg.role == spoof_carrier::SpoofRole::Local {
                        println!("=== Khaymali Bundle (spf1_) ===\n{}", cfg.make_khaymali_bundle()?);
                    }
                    println!("=== Remote Bundle ===\n{}", cfg.encode_remote_bundle(&cfg.wg_peer_priv));
                    if a.flag("save") {
                        cfg.save_state(&paths)?;
                        println!("Saved state to {}", paths.state_path());
                    }
                }
                "parse" => {
                    let b = argv.get(2).context("usage: khaymali spoof parse <spf1_...|SPOOF1:...>")?;
                    let m = spoof_carrier::SpoofConfig::decode_remote_bundle(b)?;
                    let mut keys: Vec<_> = m.keys().collect();
                    keys.sort();
                    for k in keys {
                        println!("{k}={}", m[k]);
                    }
                }
                "import" => {
                    let b = argv.get(2).context("usage: khaymali spoof import <spf1_...|SPOOF1:...> [--spoof-ips IP1,IP2]")?;
                    let mut prev = spoof_carrier::SpoofConfig::load_state(&paths)?
                        .unwrap_or_else(|| spoof_carrier::SpoofConfig::new_default(spoof_carrier::SpoofRole::Remote, String::new(), String::new()));
                    if let Some(ips) = a.get("spoof-ips") {
                        prev.spoof_ips = spoof_carrier::SpoofConfig::clean_spoof_ips(&[ips]);
                    }
                    let imported = spoof_carrier::SpoofConfig::import_bundle(b, &prev)?;
                    imported.save_state(&paths)?;
                    println!("Imported remote spoof config (peer={}, send={}, recv={})",
                        imported.peer_public_ip, imported.send_transport.as_str(), imported.recv_transport.as_str());
                }
                "apply" => {
                    let cfg = spoof_carrier::SpoofConfig::load_state(&paths)?
                        .context("no spoof.json state found (run `khaymali spoof gen --save` or `spoof import` first)")?;
                    let msg = spoof_carrier::apply_spoof(&cfg, &paths, a.flag("native"))?;
                    println!("{msg}");
                    if sysrun::is_dry_run() {
                        for l in sysrun::take_log() {
                            println!("  [plan] {l}");
                        }
                    }
                }
                "stop" => {
                    spoof_carrier::stop_spoof()?;
                    println!("Spoof tunnel stopped.");
                }
                "status" => {
                    let cfg = spoof_carrier::SpoofConfig::load_state(&paths)?
                        .unwrap_or_else(|| spoof_carrier::SpoofConfig::new_default(spoof_carrier::SpoofRole::Local, String::new(), String::new()));
                    let h = spoof_carrier::spoof_runtime_health(&cfg);
                    println!("core_active={} wg_active={} peer_ping={} handshake_age={:?}",
                        h.core_active, h.wg_active, h.peer_ping, h.handshake_age_secs);
                }
                "run-native" => {
                    let state_cfg = spoof_carrier::SpoofConfig::load_state(&paths)?
                        .context("no spoof.json state found")?;
                    let eng = std::sync::Arc::new(spoof_carrier::RawSpoofEngine::new(state_cfg)?);
                    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                    println!("Running native RawSpoofEngine...");
                    eng.run(stop).await?;
                }
                "tester" => {
                    let req = spoof_carrier::SpoofTesterRequest {
                        mode: a.get("mode").unwrap_or_else(|| "receiver".into()),
                        protocol: a.get("protocol").unwrap_or_else(|| "icmp".into()),
                        sources: a.req("sources")?.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
                        dst_ip: a.get("dst-ip").unwrap_or_default(),
                        dst_port: a.num("dst-port", 80) as u16,
                        timeout_secs: a.num("timeout", 30) as u32,
                        packet_count: a.num("packet-count", 10) as u32,
                        max_loss_pct: a.get("max-loss").and_then(|v| v.parse().ok()).unwrap_or(20.0),
                    };
                    let res = spoof_carrier::run_spoof_tester(req, &paths)?;
                    for r in res {
                        println!("{} {}/{} {:.1}%", r.ip, r.received, r.sent, r.loss_pct);
                    }
                }
                _ => bail!("usage: khaymali spoof gen|parse|import|apply|stop|status|run-native|tester ..."),
            }
        }
        "mesh" => {
            let sub = argv.get(1).map(|s| s.as_str()).unwrap_or("hub-fwd");
            let state_path = a.get("state").unwrap_or_else(|| "/etc/khaymali/hubs.json".into());
            match sub {
                "hub-fwd" => {
                    let port = a.num("port", 443) as u16;
                    let proto = a.get("proto").unwrap_or_else(|| "tcp".into());
                    let peer_hub = a.req("peer-hub")?;
                    let cmds = cluster_mesh::render_hub_forward_rules(port, &proto, &peer_hub)?;
                    for c in &cmds {
                        println!("$ {}", c.join(" "));
                    }
                }
                "join-code" => {
                    let cfg = match cluster_mesh::ClusterMeshConfig::load(&state_path)? {
                        Some(c) => c,
                        None => cluster_mesh::ClusterMeshConfig {
                            node_id: a.get("id").unwrap_or_else(|| format!("hub-{}", &hex(&util::rand_bytes::<4>()))),
                            name: a.get("name").unwrap_or_else(|| "Iran-Hub".into()),
                            public_ip: a.req("public-ip")?,
                            public_ip6: a.get("public-ip6").unwrap_or_default(),
                            listen_port: a.num("port", 18081) as u16,
                            secret: a.get("secret").unwrap_or_default(),
                            weight: a.num("weight", 1) as u32,
                            master: a.flag("master"),
                            healthy_pools: setup_bundle::parse_numeric_ports(&a.get("pools").unwrap_or_else(|| "443".into())),
                            hubs: Vec::new(),
                        },
                    };
                    let node = cluster_mesh::MeshNode::new(cfg, Some(state_path));
                    println!("{}", node.join_code()?);
                }
                "serve" => {
                    let cfg = cluster_mesh::ClusterMeshConfig::load(&state_path)?
                        .context("no hubs.json state found (run `khaymali mesh join-code` first)")?;
                    let bind = a.get("bind").unwrap_or_else(|| format!("0.0.0.0:{}", cfg.listen_port));
                    let node = cluster_mesh::MeshNode::new(cfg, Some(state_path));
                    let listener = tokio::net::TcpListener::bind(&bind).await?;
                    println!("Cluster Mesh listening on {bind} (prefix /_hc)");
                    let hb_node = node.clone();
                    tokio::spawn(async move {
                        loop {
                            tokio::time::sleep(Duration::from_secs(cluster_mesh::MESH_EVERY_SECS)).await;
                            hb_node.beat_once().await;
                        }
                    });
                    node.serve_listener(listener).await?;
                }
                "add" => {
                    let code = argv.get(2).context("usage: khaymali mesh add <hc1_...> --state hubs.json")?;
                    let cfg = cluster_mesh::ClusterMeshConfig::load(&state_path)?
                        .context("no local hubs.json state found (run `khaymali mesh join-code` first)")?;
                    let node = cluster_mesh::MeshNode::new(cfg, Some(state_path));
                    let peer = node.add_hub(code).await?;
                    println!("Linked hub {} ({}) at {}", peer.name, peer.id, peer.url);
                }
                "remove" => {
                    let id = argv.get(2).context("usage: khaymali mesh remove <HUB_ID>")?;
                    let cfg = cluster_mesh::ClusterMeshConfig::load(&state_path)?
                        .context("no hubs.json state found")?;
                    let node = cluster_mesh::MeshNode::new(cfg, Some(state_path));
                    if node.remove_hub(id).await {
                        println!("Unlinked hub {id}");
                    } else {
                        bail!("hub '{id}' not found");
                    }
                }
                _ => bail!("usage: khaymali mesh hub-fwd|join-code|serve|add|remove ..."),
            }
        }
        "bundle" => {
            let sub = argv.get(1).map(|s| s.as_str()).unwrap_or("parse");
            match sub {
                "parse" => {
                    let raw = argv.get(2).context("usage: khaymali bundle parse <hsh1_...|bh1_...|gh1_...>")?;
                    let b = setup_bundle::parse_bundle(raw)?;
                    println!(
                        "engine={} transport={} udp={} udp_port={} iran_pub={} ctrl_port={} iran_gre={} foreign_gre={} token={} ports={:?} raw_ports={:?} fou_ports={:?}",
                        b.engine, b.transport, b.udp, b.udp_port, b.iran_pub, b.ctrl_port,
                        b.iran_gre, b.foreign_gre, b.token, b.ports, b.raw_ports, b.fou_ports
                    );
                }
                "make-frp" => {
                    let ports = setup_bundle::parse_numeric_ports(&a.get("ports").unwrap_or_default());
                    println!(
                        "{}",
                        setup_bundle::make_frp_bundle(
                            &a.req("iran-pub")?,
                            a.num("ctrl-port", 7000) as u16,
                            &a.get("iran-gre").unwrap_or_else(|| "10.10.0.1".into()),
                            &a.get("foreign-gre").unwrap_or_else(|| "10.10.0.2".into()),
                            &a.req("token")?,
                            &ports,
                            &a.get("transport").unwrap_or_else(|| "tcp".into()),
                            a.num("fou1", 443) as u16,
                            a.num("fou2", 55555) as u16,
                        )
                    );
                }
                "make-backhaul" => {
                    let raw_ports = setup_bundle::parse_raw_ports(&a.get("ports").unwrap_or_default());
                    let tr = setup_bundle::backhaul_bundle_transport(
                        &a.get("transport").unwrap_or_else(|| "tcpmux".into()),
                        a.num("udp-port", 0) as u16,
                    );
                    println!(
                        "{}",
                        setup_bundle::make_backhaul_bundle(
                            &a.req("iran-pub")?,
                            a.num("ctrl-port", 3080) as u16,
                            &tr,
                            &a.req("token")?,
                            &raw_ports,
                        )
                    );
                }
                "make-gre-backhaul" => {
                    let raw_ports = setup_bundle::parse_raw_ports(&a.get("ports").unwrap_or_default());
                    let tr = setup_bundle::backhaul_bundle_transport(
                        &a.get("transport").unwrap_or_else(|| "tcpmux".into()),
                        a.num("udp-port", 0) as u16,
                    );
                    println!(
                        "{}",
                        setup_bundle::make_gre_backhaul_bundle(
                            &a.req("iran-pub")?,
                            a.num("ctrl-port", 3080) as u16,
                            &a.get("iran-gre").unwrap_or_else(|| "10.10.0.1".into()),
                            &a.get("foreign-gre").unwrap_or_else(|| "10.10.0.2".into()),
                            &tr,
                            &a.req("token")?,
                            &raw_ports,
                        )
                    );
                }
                _ => bail!("usage: khaymali bundle parse|make-frp|make-backhaul|make-gre-backhaul ..."),
            }
        }
        "setup" => {
            let sub = argv.get(1).map(|s| s.as_str()).unwrap_or("iran");
            if a.flag("dry-run") || a.flag("plan") {
                sysrun::set_dry_run_global(true);
            }
            let paths = engines::EnginePaths::default();
            match sub {
                "iran" | "foreign" => {
                    let engine = a.get("engine").unwrap_or_else(|| "frp".into());
                    let default_tr = if engine == "frp" { "tcp" } else { "tcpmux" };
                    let req = engines::SetupRequest {
                        role: sub.into(),
                        engine,
                        transport: a.get("transport").unwrap_or_else(|| default_tr.into()),
                        local_pub: a.get("local-pub").unwrap_or_default(),
                        remote_pub: a.get("remote-pub").unwrap_or_default(),
                        ctrl_port: a.num("ctrl-port", 7000) as u16,
                        local_gre: a.get("local-gre").unwrap_or_default(),
                        peer_gre: a.get("peer-gre").unwrap_or_default(),
                        token: a.get("token").unwrap_or_else(|| hex(&util::rand_bytes::<16>())),
                        raw_ports: setup_bundle::parse_raw_ports(&a.get("ports").unwrap_or_else(|| "443".into())),
                        accept_udp: a.flag("accept-udp") || a.num("udp-port", 0) > 0,
                        udp_companion_port: a.num("udp-port", 0) as u16,
                        connection_pool: a.num("pool", engines::BH_POOL_DEFAULT as usize) as u32,
                        peer_id: a.num("peer-id", 0) as u32,
                        frp_perf: engines::FrpPerfOpts {
                            proxy_protocol: a.get("proxy-protocol").unwrap_or_else(|| "off".into()),
                            bandwidth_mb: a.num("bandwidth-mb", 0) as u32,
                            health_check: a.flag("health-check"),
                        },
                        fou_port1: a.num("fou1", 443) as u16,
                        fou_port2: a.num("fou2", 55555) as u16,
                    };
                    let out = engines::apply_setup(&req, &paths)?;
                    println!("units={:?} configs={:?}", out.unit_names, out.config_paths);
                    if let Some(b) = out.foreign_bundle {
                        println!("foreign_bundle={b}");
                    }
                    if sysrun::is_dry_run() {
                        for l in sysrun::take_log() {
                            println!("  [plan] {l}");
                        }
                    }
                }
                "from-bundle" => {
                    let raw = argv.get(2).context("usage: khaymali setup from-bundle <hsh1_...|bh1_...|gh1_...> [--ports ...] [--plan]")?;
                    let b = setup_bundle::parse_bundle(raw)?;
                    let extra = a.get("ports");
                    let req = engines::SetupRequest::from_bundle(&b, extra.as_deref());
                    let out = engines::apply_setup(&req, &paths)?;
                    println!("Applied foreign bundle: units={:?} configs={:?}", out.unit_names, out.config_paths);
                    if sysrun::is_dry_run() {
                        for l in sysrun::take_log() {
                            println!("  [plan] {l}");
                        }
                    }
                }
                _ => bail!("usage: khaymali setup iran|foreign|from-bundle ... [--plan]"),
            }
        }
        "lb" => {
            let sub = argv.get(1).map(|s| s.as_str()).unwrap_or("nft");
            match sub {
                "nft" => {
                    let port = a.num("port", 443) as u16;
                    let proto = a.get("proto").unwrap_or_else(|| "tcp".into());
                    let backends: Vec<std::net::SocketAddr> = a
                        .all("backend")
                        .iter()
                        .map(|s| s.parse().with_context(|| format!("invalid --backend '{s}'")))
                        .collect::<Result<_>>()?;
                    println!("{}", cluster_lb::render_lb_nft_rules(port, &proto, &backends)?);
                }
                "serve" => {
                    let bind = a.req("bind")?;
                    let mode = cluster_lb::LbMode::parse(&a.get("mode").unwrap_or_else(|| "failover".into()))?;
                    let mut targets = Vec::new();
                    for (i, addr) in a.all("backend").into_iter().enumerate() {
                        targets.push(cluster_lb::LbTarget {
                            link_id: (i + 1) as u32,
                            addr,
                            weight: 1,
                            priority: i as u32,
                            healthy: true,
                            latency_ms: 0.0,
                            active_conns: 0,
                        });
                    }
                    let listener = tokio::net::TcpListener::bind(&bind).await?;
                    let port = listener.local_addr()?.port();
                    let pool = cluster_lb::LbPoolRuntime::new(port, "tcp", mode, targets)?;
                    println!("Cluster TCP LB listening on {bind} (mode={})", mode.as_str());
                    pool.serve_tcp(listener).await?;
                }
                _ => bail!("usage: khaymali lb nft --port 443 --proto tcp|udp|both --backend IP:PORT | serve --bind 0.0.0.0:443 --mode failover|balance|sticky|latency|least --backend IP:PORT"),
            }
        }
        "node" => {
            let sub = argv.get(1).map(|s| s.as_str()).unwrap_or("probe");
            let fleet_path = a.get("fleet").unwrap_or_else(|| "/etc/khaymali/nodes.json".into());
            match sub {
                "probe" => {
                    let addr = a.req("addr")?;
                    let (ok, rtt) = node_cluster::probe_node(&addr, Duration::from_secs(3)).await;
                    println!("addr={addr} online={ok} rtt_ms={rtt:.1}");
                }
                "fleet" => {
                    let mut nodes = node_cluster::load_fleet(&fleet_path)?;
                    node_cluster::probe_fleet(&mut nodes, Duration::from_secs(2)).await;
                    node_cluster::save_fleet(&fleet_path, &nodes)?;
                    for n in &nodes {
                        println!("{} ({}) addr={} online={} rtt_ms={:.1}", n.id, n.role, n.addr, n.online, n.rtt_ms);
                    }
                }
                _ => bail!("usage: khaymali node probe --addr IP:PORT | fleet [--fleet /etc/khaymali/nodes.json]"),
            }
        }
        "sshfwd" => {
            let sub = argv.get(1).map(|s| s.as_str()).unwrap_or("gen");
            if a.flag("dry-run") || a.flag("plan") {
                sysrun::set_dry_run_global(true);
            }
            match sub {
                "gen" | "apply" => {
                    let cfg = sshfwd::SshFwdConfig {
                        enabled: true,
                        mode: a.get("mode").unwrap_or_else(|| "reverse".into()),
                        remote_host: a.req("remote")?,
                        ssh_port: a.num("ssh-port", 22) as u16,
                        ssh_user: a.get("user").unwrap_or_else(|| "root".into()),
                        key_path: a.get("key-file").unwrap_or_else(|| "/etc/khaymali/sshfwd_ed25519".into()),
                        frp_port: a.num("frp-port", 7000) as u16,
                        ports: setup_bundle::parse_numeric_ports(&a.get("ports").unwrap_or_else(|| "443".into())),
                        compression: a.flag("compress"),
                    };
                    if sub == "apply" {
                        sshfwd::apply_sshfwd(&cfg, "/etc/systemd/system")?;
                        println!("Applied khaymali-sshfwd.service");
                    } else {
                        println!("{}", cfg.render_service_unit()?);
                    }
                }
                "lock-key" => {
                    let pk = a.req("pubkey")?;
                    let mode = a.get("mode").unwrap_or_else(|| "direct".into());
                    let frp_port = a.num("frp-port", 7000) as u16;
                    let ports = setup_bundle::parse_numeric_ports(&a.get("ports").unwrap_or_default());
                    println!("{}", sshfwd::format_authorized_key_line(&pk, &mode, frp_port, &ports)?);
                }
                _ => bail!("usage: khaymali sshfwd gen|apply --remote IP --ports 443 | lock-key --pubkey '...'"),
            }
        }
        "xray" => {
            let sub = argv.get(1).map(|s| s.as_str()).unwrap_or("keygen");
            if a.flag("dry-run") || a.flag("plan") {
                sysrun::set_dry_run_global(true);
            }
            match sub {
                "keygen" => {
                    let k = xray_engine::XrayKeys::generate();
                    println!("uuid={}\nreality_private={}\nreality_public={}\nshort_id={}",
                        k.uuid, k.reality_priv, k.reality_pub, k.short_id);
                }
                "gen" => {
                    let preset = xray_engine::xray_preset(&a.get("preset").unwrap_or_else(|| "reality-vision".into()))?;
                    let side = a.get("side").unwrap_or_else(|| "foreign".into());
                    let keys = xray_engine::XrayKeys::generate();
                    let link = xray_engine::XrayLink {
                        id: a.num("id", 1) as u32,
                        side: side.clone(),
                        listen_port: a.num("port", 8443) as u16,
                        remote_host: a.get("remote").unwrap_or_else(|| "127.0.0.1".into()),
                        forward_ports: setup_bundle::parse_numeric_ports(&a.get("ports").unwrap_or_else(|| "443".into())),
                        keys,
                        profile: preset,
                    };
                    if side == "iran" {
                        println!("{}", link.render_iran_bridge_json()?);
                    } else {
                        println!("{}", link.render_server_json()?);
                        println!("\n# Client VLESS URI:\n{}", link.vless_uri(&link.remote_host, "khaymali"));
                    }
                }
                _ => bail!("usage: khaymali xray keygen | gen --preset reality-vision|reality-grpc|reality-xhttp|ws-tls|kcp-noise [--side foreign|iran]"),
            }
        }
        "ops" => {
            let sub = argv.get(1).map(|s| s.as_str()).unwrap_or("doctor");
            if a.flag("dry-run") || a.flag("plan") {
                sysrun::set_dry_run_global(true);
            }
            match sub {
                "doctor" => {
                    let rep = ops_suite::run_full_diagnostics();
                    println!("{}", rep.to_json().to_string_pretty());
                }
                "tune" => {
                    let perf = ops_suite::PerfConfig::default();
                    if a.flag("apply") {
                        let n = perf.apply("/etc/sysctl.d/99-khaymali.conf")?;
                        println!("Applied {n} sysctl performance parameters.");
                        if sysrun::is_dry_run() {
                            for l in sysrun::take_log() {
                                println!("  [plan] {l}");
                            }
                        }
                    } else {
                        println!("{}", perf.render_sysctl_conf());
                    }
                }
                _ => bail!("usage: khaymali ops doctor | tune [--apply] [--plan]"),
            }
        }
        "tgbot" => {
            #[cfg(unix)]
            {
                let token = a.get("token").or_else(|| std::env::var("KHAYMALI_TG_TOKEN").ok()).context("--token BOT_TOKEN (or KHAYMALI_TG_TOKEN) is required")?;
                let admins: Vec<i64> = a
                    .get("admin")
                    .or_else(|| std::env::var("KHAYMALI_TG_ADMIN").ok())
                    .context("--admin CHAT_ID[,CHAT_ID] is required (only these chats are answered)")?
                    .split(',')
                    .filter_map(|x| x.trim().parse().ok())
                    .collect();
                if admins.is_empty() {
                    bail!("--admin must contain at least one numeric chat id");
                }
                let sock = a.get("control").unwrap_or_else(|| "/run/khaymali/entry.sock".into());
                let ap_state = a.get("ap-state").unwrap_or_else(|| "/var/lib/khaymali/autopilot.state".into());
                let bdir = a.get("dir").unwrap_or_else(|| "/var/backups/khaymali".into());
                tgbot::run(token, admins, move |cmd| {
                    let (sock, ap_state, bdir) = (sock.clone(), ap_state.clone(), bdir.clone());
                    async move {
                        use tgbot::Cmd;
                        let rpc = |m: String| {
                            let s = sock.clone();
                            async move { send_control_rpc(&s, &m).await.unwrap_or_else(|e| format!("control socket error: {e}")) }
                        };
                        let q = |s: &str| s.replace(['"', '\\', '\n'], "");
                        match cmd {
                            Cmd::Help => tgbot::help_text(),
                            Cmd::Status => rpc("{\"method\":\"status\"}".into()).await,
                            Cmd::Pool => tgbot::format_pool(&rpc("{\"method\":\"pool.status\"}".into()).await),
                            Cmd::Health => rpc("{\"method\":\"health.three_layer\"}".into()).await,
                            Cmd::Autopilot => autopilot::status_text(&ap_state),
                            Cmd::Backups => {
                                let l = backup::list(&bdir);
                                if l.is_empty() { "no backups".into() } else { l.iter().map(|(n, sz, _)| format!("{n}  {sz} bytes")).collect::<Vec<_>>().join("\n") }
                            }
                            Cmd::Drain(a) => rpc(format!("{{\"method\":\"pool.drain\",\"addr\":\"{}\"}}", q(&a))).await,
                            Cmd::Undrain(a) => rpc(format!("{{\"method\":\"pool.undrain\",\"addr\":\"{}\"}}", q(&a))).await,
                            Cmd::Failback => rpc("{\"method\":\"pool.failback\"}".into()).await,
                            Cmd::Unknown(_) => format!("unknown command\n\n{}", tgbot::help_text()),
                        }
                    }
                })
                .await?;
            }
            #[cfg(not(unix))]
            bail!("tgbot requires Unix domain sockets");
        }
        "backup" => {
            let sub = argv.get(1).map(|s| s.as_str()).unwrap_or("list");
            let dir = a.get("dir").unwrap_or_else(|| "/var/backups/khaymali".into());
            let pass = || -> Result<String> {
                if let Some(f) = a.get("pass-file") {
                    return Ok(std::fs::read_to_string(&f).with_context(|| format!("reading {f}"))?.trim().to_string());
                }
                std::env::var("KHAYMALI_BACKUP_PASS").context("give --pass-file FILE or set KHAYMALI_BACKUP_PASS")
            };
            match sub {
                "run" => {
                    let sources: Vec<String> = match a.get("src") {
                        Some(s) => s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect(),
                        None => backup::DEFAULT_SOURCES.iter().map(|s| s.to_string()).collect(),
                    };
                    let p = backup::run(&dir, &pass()?, &sources, a.num("keep", backup::DEFAULT_KEEP).clamp(1, 1000), backup::PBKDF2_ROUNDS)?;
                    println!("backup written: {p}");
                }
                "list" | "ls" => {
                    for (n, size, ts) in backup::list(&dir) {
                        println!("{n}  {size} bytes  (unix {ts})");
                    }
                }
                "verify" => {
                    let f = argv.get(2).context("usage: khaymali backup verify <FILE>")?;
                    let blob = std::fs::read(f)?;
                    let names = backup::verify_archive(&backup::open(&pass()?, &blob, backup::PBKDF2_ROUNDS)?)?;
                    println!("OK: {} entries, all paths safe", names.len());
                }
                "restore" => {
                    let f = argv.get(2).context("usage: khaymali backup restore <FILE> --to DIR")?;
                    let to = a.get("to").context("--to DIR is required (restore never writes over / directly)")?;
                    let names = backup::restore(f, &pass()?, &to, backup::PBKDF2_ROUNDS)?;
                    println!("restored {} entries under {to}", names.len());
                }
                _ => bail!("usage: khaymali backup run|list|verify <FILE>|restore <FILE> --to DIR [--dir D] [--pass-file F]"),
            }
        }
        "harsh-nlp" => {
            let sub = argv.get(1).map(|s| s.as_str()).unwrap_or("eval");
            match sub {
                "eval" => {
                    let mode = harsh_nlp::PolicyMode::parse(&a.get("mode").unwrap_or_else(|| "shadow".into()));
                    let mut ctl = harsh_nlp::HarshNlpController::new(mode);
                    let snap = harsh_nlp::TelemetrySnapshot {
                        ts_unix: util::now_unix(),
                        rtt_ms: a.get("rtt").and_then(|v| v.parse().ok()).unwrap_or(45.0),
                        base_rtt_ms: a.get("base-rtt").and_then(|v| v.parse().ok()).unwrap_or(40.0),
                        jitter_ms: a.get("jitter").and_then(|v| v.parse().ok()).unwrap_or(3.0),
                        loss_pct: a.get("loss").and_then(|v| v.parse().ok()).unwrap_or(0.0),
                        retransmit_pct: a.get("retx").and_then(|v| v.parse().ok()).unwrap_or(0.0),
                        disconnects_per_min: a.num("disconnects", 0) as u32,
                        big_pkt_drop_ratio: a.get("big-drop").and_then(|v| v.parse().ok()).unwrap_or(0.0),
                        goodput_kbps: a.get("goodput").and_then(|v| v.parse().ok()).unwrap_or(15_000.0),
                        recent_log: a.get("log").unwrap_or_default(),
                    };
                    let dec = ctl.evaluate(&snap);
                    println!("{}", dec.to_json().to_string_pretty());
                }
                "status" => {
                    #[cfg(unix)]
                    {
                        let sock = a.get("control").unwrap_or_else(|| "/run/khaymali/entry.sock".into());
                        print!("{}", send_control_rpc(&sock, "{\"method\":\"harsh_nlp.status\"}").await?);
                    }
                    #[cfg(not(unix))]
                    bail!("harsh-nlp status requires Unix domain sockets");
                }
                "mode" => {
                    #[cfg(unix)]
                    {
                        let m = argv.get(2).context("usage: khaymali harsh-nlp mode shadow|active [--control SOCK]")?;
                        let sock = a.get("control").unwrap_or_else(|| "/run/khaymali/entry.sock".into());
                        let rpc = format!("{{\"method\":\"harsh_nlp.mode\",\"mode\":\"{}\"}}", m.replace('"', ""));
                        print!("{}", send_control_rpc(&sock, &rpc).await?);
                    }
                    #[cfg(not(unix))]
                    bail!("harsh-nlp mode requires Unix domain sockets");
                }
                _ => bail!("usage: khaymali harsh-nlp eval [--mode shadow|active] [--rtt MS] [--loss PCT] [--jitter MS] [--log TEXT] | status | mode shadow|active"),
            }
        }
        "up" | "down" => {
            let action = if cmd == "up" { "start" } else { "stop" };
            let target = argv.get(1).map(|r| format!("khaymali-{r}")).unwrap_or_else(|| "khaymali-entry".to_string());
            let st = std::process::Command::new("systemctl")
                .args([action, &target])
                .status()
                .context("failed to invoke systemctl")?;
            if !st.success() {
                bail!("systemctl {action} {target} failed");
            }
            println!("{target}: {action} OK");
        }
        "diagnose" if argv.get(1).map(|s| s.as_str()) == Some("--stdin") => {
            // batch mode for scripts/eval_nlp_replay.py: one log per line ->
            // intent \t confidence \t abstained \t action
            use std::io::BufRead;
            let nlp = kani_nlp::TinyNetNlp::load_configured_or_pretrained();
            for line in std::io::stdin().lock().lines() {
                let p = nlp.classify(&line.unwrap_or_default());
                println!("{}\t{:.3}\t{}\t{}", p.intent.as_str(), p.confidence, p.abstained, p.action.as_str());
            }
        }
        "diagnose" if argv.get(1).map(|s| s.as_str()) == Some("--stdin-combined") => {
            // TSV input: log, loss_pct, rtt_ms, base_rtt_ms, jitter_ms, retransmit_pct,
            // stall_bytes, rx_idle_ms, resets_last_min, connect_fail_ratio,
            // big_frames_lost, small_frames_ok. Empty stall_bytes means None.
            use std::io::BufRead;
            let nlp = kani_nlp::TinyNetNlp::load_configured_or_pretrained();
            for line in std::io::stdin().lock().lines() {
                let line = line.unwrap_or_default();
                let f: Vec<&str> = line.split('\t').collect();
                let get = |i: usize| f.get(i).copied().unwrap_or("");
                let parse_f = |i: usize| get(i).parse::<f32>().ok().filter(|v| v.is_finite()).unwrap_or(0.0);
                let parse_u = |i: usize| get(i).parse::<u32>().unwrap_or(0);
                let m = kani_nlp::LinkMetrics {
                    loss_pct: parse_f(1), rtt_ms: parse_u(2), base_rtt_ms: parse_u(3),
                    jitter_ms: parse_u(4), retransmit_pct: parse_f(5),
                    stall_bytes: get(6).parse::<u64>().ok(), rx_idle_ms: parse_u(7),
                    resets_last_min: parse_u(8), connect_fail_ratio: parse_f(9),
                    big_frames_lost: get(10) == "1", small_frames_ok: get(11) == "1",
                };
                let p = nlp.classify_combined(get(0), &m);
                println!("{}\t{:.3}\t{}\t{}", p.intent.as_str(), p.confidence, p.abstained, p.action.as_str());
            }
        }
        "diagnose" => {
            let text = argv[1..].join(" ");
            let nlp = kani_nlp::TinyNetNlp::load_configured_or_pretrained();
            let pred = nlp.classify(&text);
            println!(
                "intent:     {}
confidence: {:.3}
abstained:  {}
action:     {}",
                pred.intent.as_str(),
                pred.confidence,
                pred.abstained,
                pred.action.as_str()
            );
        }
        "promote-nlp-candidate" => {
            if std::env::var_os("KHAYMALI_NLP_MODEL_PATH").is_none() || std::env::var_os("KHAYMALI_NLP_CANDIDATE_PATH").is_none() {
                bail!("set both KHAYMALI_NLP_MODEL_PATH and KHAYMALI_NLP_CANDIDATE_PATH before promotion");
            }
            let holdout_path = argv.get(1).context("usage: khaymali promote-nlp-candidate <HOLDOUT.tsv> [--min-samples N]")?;
            let text = std::fs::read_to_string(holdout_path).with_context(|| format!("read {holdout_path}"))?;
            let mut holdout = Vec::new();
            for (line_no, line) in text.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') { continue; }
                let (log, label) = line.split_once('\t').with_context(|| format!("{holdout_path}:{} expected log<TAB>class", line_no + 1))?;
                let expected = match label {
                    "healthy" => NetIntent::Healthy,
                    "early_rst" => NetIntent::EarlyRst,
                    "byte_freeze" => NetIntent::ByteFreeze,
                    "pmtu_drop" => NetIntent::PmtuDrop,
                    "throttle" => NetIntent::Throttle,
                    "route_or_dns_fail" => NetIntent::RouteOrDnsFail,
                    "unrelated" => NetIntent::Unrelated,
                    _ => bail!("{holdout_path}:{} unknown class '{label}'", line_no + 1),
                };
                holdout.push((log, expected));
                if holdout.len() > 100_000 { bail!("holdout exceeds 100000 rows"); }
            }
            let mut advisor = NlpAdvisor::new();
            let overlap = kani_nlp::holdout_overlap(&holdout, advisor.candidate_learned());
            println!("holdout_rows={} candidate_learned={} overlap={:.1}% (max 5%)",
                holdout.len(), advisor.candidate_learned().len(), overlap * 100.0);
            let decision = advisor.evaluate_and_promote_candidate(&holdout, a.num("min-samples", 30), 0.5, 0.25);
            println!("candidate_decision={decision:?}");
            if decision != CandidatePromotionDecision::Promoted { bail!("candidate was not promoted; active model unchanged"); }
        }
        "calibrate-risk" => {
            let train_path = argv.get(1).context("usage: khaymali calibrate-risk <TRAIN.tsv> <HOLDOUT.tsv> <OUTPUT.model>")?;
            let holdout_path = argv.get(2).context("missing HOLDOUT.tsv")?;
            let output_path = argv.get(3).context("missing OUTPUT.model")?;
            let parse_examples = |path: &str| -> Result<Vec<CalibrationExample>> {
                let text = std::fs::read_to_string(path).with_context(|| format!("read {path}"))?;
                let mut out = Vec::new();
                for (line_no, line) in text.lines().enumerate() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') { continue; }
                    let fields: Vec<_> = line.split('\t').collect();
                    if fields.len() != 2 { bail!("{path}:{} expected score<TAB>degraded(0|1)", line_no + 1); }
                    let score: f64 = fields[0].parse().with_context(|| format!("{path}:{} invalid score", line_no + 1))?;
                    if !score.is_finite() || !(0.0..=100.0).contains(&score) { bail!("{path}:{} score must be within 0..100", line_no + 1); }
                    let degraded = match fields[1] { "1" | "true" => true, "0" | "false" => false, _ => bail!("{path}:{} label must be 0 or 1", line_no + 1) };
                    out.push(CalibrationExample { score, degraded_within_horizon: degraded });
                    if out.len() > 100_000 { bail!("{path}: dataset exceeds 100000 rows"); }
                }
                Ok(out)
            };
            let train = parse_examples(train_path)?;
            let holdout = parse_examples(holdout_path)?;
            let mut calibrator = RiskCalibrator::default();
            if !calibrator.fit(&train) { bail!("training data rejected: need >=30 valid rows and >=5 rows per class"); }
            let metrics = calibrator.evaluate(&holdout).context("holdout dataset is empty or invalid")?;
            calibrator.save_artifact_atomic(std::path::Path::new(output_path)).map_err(anyhow::Error::msg)?;
            println!("calibrator_saved=true train={} holdout={} brier={:.5} log_loss={:.5} ece={:.5}",
                train.len(), metrics.samples, metrics.brier_score, metrics.log_loss, metrics.expected_calibration_error);
        }
        "doctor" => {
            let mut warnings = 0u32;
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let clock_ok = now_unix >= 1_700_000_000;
            println!("version:    khaymali {}", env!("CARGO_PKG_VERSION"));
            println!("clock_utc:  {} ({})", now_unix, if clock_ok { "OK" } else { warnings += 1; "WARN: clock behind 2023 (anti-replay may fail)" });
            let loopback_ok = std::net::TcpListener::bind("127.0.0.1:0").is_ok();
            println!("loopback:   {}", if loopback_ok { "OK (127.0.0.1 bindable)" } else { warnings += 1; "WARN: cannot bind 127.0.0.1:0" });
            #[cfg(target_os = "linux")]
            {
                if let Ok(lim) = std::fs::read_to_string("/proc/self/limits") {
                    if let Some(line) = lim.lines().find(|l| l.starts_with("Max open files")) {
                        let soft = line.split_whitespace().nth(3).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
                        let ok = soft >= 4096;
                        if !ok { warnings += 1; }
                        println!("ulimit_nofile: {} ({})", soft, if ok { "OK" } else { "WARN: recommend >= 65535 for 200-300 clients" });
                    }
                }
            }
            let nlp_mode_env = std::env::var("KHAYMALI_NLP_MODE").unwrap_or_else(|_| "shadow (default)".into());
            let path_intel_env = std::env::var("KHAYMALI_PATH_INTEL").unwrap_or_else(|_| "shadow (default)".into());
            println!("nlp_mode:   {nlp_mode_env}");
            println!("path_intel: {path_intel_env}");
            match std::env::var_os("KHAYMALI_NLP_MODEL_PATH").map(std::path::PathBuf::from) {
                Some(p) => match kani_nlp::TinyNetNlp::load_artifact(&p) {
                    Ok(m) => println!("nlp_model:  OK ({}, online_updates={})", p.display(), m.online_updates_total()),
                    Err(e) => { warnings += 1; println!("nlp_model:  WARN ({}: {e})", p.display()); }
                },
                None => println!("nlp_model:  builtin pretrained v4.2 (KHAYMALI_NLP_MODEL_PATH unset)"),
            }
            match std::env::var_os("KHAYMALI_RISK_CALIBRATOR_PATH").map(std::path::PathBuf::from) {
                Some(p) => match RiskCalibrator::load_artifact(&p) {
                    Ok(c) => println!("calibrator: OK ({}, samples={})", p.display(), c.samples()),
                    Err(e) => { warnings += 1; println!("calibrator: WARN ({}: {e})", p.display()); }
                },
                None => println!("calibrator: unset (probabilities disabled until calibrated)"),
            }
            println!("doctor:     {} ({warnings} warning(s))", if warnings == 0 { "PASS" } else { "PASS_WITH_WARNINGS" });
        }
        "intelligence-lab" => {
            let scenario_arg = a.get("scenario").unwrap_or_else(|| "all".to_string());
            let steps = a.num("steps", 1000).clamp(1, 100_000);
            let capacity = a.get("capacity-kbps").and_then(|v| v.parse::<f64>().ok()).unwrap_or(10_000.0);
            let offered = a.get("offered-kbps").and_then(|v| v.parse::<f64>().ok()).unwrap_or((capacity * 0.8).max(500.0));
            let queue = a.num("queue", 64).clamp(1, 4096);
            let compare_cap = a.get("compare-capacity-kbps").and_then(|v| v.parse::<f64>().ok());
            let cfg = DigitalTwinConfig { link_capacity_kbps: capacity, offered_load_kbps: offered, queue_capacity_packets: queue, ..Default::default() };
            let scenarios: Vec<TwinScenario> = match scenario_arg.as_str() {
                "all" => vec![TwinScenario::Clean, TwinScenario::AddedLatency, TwinScenario::RandomLoss,
                    TwinScenario::Jitter, TwinScenario::Throttle, TwinScenario::IntermittentOutage],
                "clean" => vec![TwinScenario::Clean],
                "latency" => vec![TwinScenario::AddedLatency],
                "loss" => vec![TwinScenario::RandomLoss],
                "jitter" => vec![TwinScenario::Jitter],
                "throttle" => vec![TwinScenario::Throttle],
                "outage" => vec![TwinScenario::IntermittentOutage],
                _ => bail!("unknown --scenario (use all|clean|latency|loss|jitter|throttle|outage)"),
            };
            let base = NetworkSample { rtt_ms: 40.0, baseline_rtt_ms: 40.0, jitter_ms: 3.0,
                loss_pct: 0.0, retransmit_pct: 0.0, goodput_kbps: capacity, connect_success_pct: 100.0 };
            if let Some(cand_cap) = compare_cap {
                let mut mgr = AdaptiveExperimentManager::default();
                let mut budget = HardResourceBudget::new(128, scenarios.len() * 2 + 2, 65_536);
                let cand_cfg = DigitalTwinConfig { link_capacity_kbps: cand_cap, ..cfg };
                for scenario in scenarios {
                    let (b_rep, c_rep) = mgr.compare_configs(base, scenario, steps, cfg, cand_cfg, &mut budget)
                        .context("invalid paired digital-twin comparison")?;
                    println!("scenario={:?} base_goodput_kbps={:.2} cand_goodput_kbps={:.2} base_p95_ms={:.2} cand_p95_ms={:.2} base_dropped={} cand_dropped={} base_sev={:.1} cand_sev={:.1}",
                        scenario, b_rep.goodput_kbps, c_rep.goodput_kbps, b_rep.p95_latency_ms,
                        c_rep.p95_latency_ms, b_rep.packets_dropped, c_rep.packets_dropped, b_rep.mean_severity, c_rep.mean_severity);
                }
            } else {
                for scenario in scenarios {
                    let r = simulate_packet_twin(base, scenario, steps, cfg).context("invalid digital-twin configuration")?;
                    println!("scenario={:?} steps={} delivered={} dropped={} mean_ms={:.2} p95_ms={:.2} peak_queue={} goodput_kbps={:.2} severity={:.1}",
                        r.scenario, r.steps, r.packets_delivered, r.packets_dropped, r.mean_latency_ms,
                        r.p95_latency_ms, r.peak_queue_packets, r.goodput_kbps, r.mean_severity);
                }
            }
        }
        "transports" => {
            let reg = transport_engine::TransportRegistry::new();
            for d in reg.list_descriptors() {
                println!(
                    "{:<12} mux={:<5} migration={:<5} fec={:<5} mtu={}",
                    d.kind.as_str(),
                    d.supports_multiplex,
                    d.supports_migration,
                    d.supports_fec,
                    d.max_payload_bytes
                );
            }
        }
        "verify-config" => {
            let path = argv.get(1).context("usage: khaymali verify-config <FILE> <HEX_KEY> [MIN_REV]")?;
            let key_hex = argv.get(2).context("missing <HEX_KEY>")?;
            let min_rev: u64 = argv.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
            let key = unhex(key_hex)?;
            let text = std::fs::read_to_string(path)?;
            let sc = fleet::SignedConfig::parse_file(&text)?;
            fleet::verify_signed_config_now(&sc, &key, min_rev)?;
            println!("OK: signed config revision={} verified", sc.revision);
        }
        "version" | "--version" => println!("khaymali {}", env!("CARGO_PKG_VERSION")),
        "exit" => {
            let allowed = a.pubkeys("allow")?;
            if allowed.is_empty() {
                bail!("need at least one --allow <entry public key>");
            }
            let camo = a.camo(false)?;
            if camo.as_ref().is_some_and(|c| c.fallback.is_none()) {
                eprintln!("[exit] WARNING: camouflage without --camo-fallback: unauthenticated probes get silence, not a real site");
            }
            if let Some(m) = a.get("metrics") {
                tokio::spawn(stats::serve(m, None));
            }
            exit::run(exit::ExitCfg {
                listen: a.req("listen")?,
                udp_listen: a.get("udp-listen"),
                ktunnel_listen: a.get("ktunnel-listen"),
                ws_listen: a.get("ws-listen"),
                wss_listen: a.get("wss-listen"),
                key: a.key()?,
                allowed,
                allow_private: a.flag("allow-private"),
                camo,
                control: a.get("control"),
                tun: a.get("tun"),
                tun_cidr: a.get("tun-cidr"),
                reverse_entry: a.get("reverse-entry"),
                reverse_pool: a.num("reverse-pool", 4),
            })
            .await?;
        }
        "entry" => {
            let exit_pub = a.pubkeys("exit-pub")?.into_iter().next().context("missing --exit-pub")?;
            let raw_exits = a.all("exit");
            let mut exits = Vec::new();
            let mut member_opts = std::collections::HashMap::new();
            let mut any_opts = false;
            for raw in &raw_exits {
                let (addr, o) = pool::parse_exit_spec(raw)?;
                any_opts |= raw.contains(';');
                member_opts.insert(addr.clone(), o);
                exits.push(addr);
            }
            let pool_mode = match a.get("pool-mode") {
                Some(m) => Some(pool::PoolMode::parse(&m)?),
                None => None,
            };
            let manual_failback = match a.get("failback").as_deref() {
                None | Some("auto") => false,
                Some("manual") => true,
                Some(o) => bail!("--failback must be auto|manual, got '{o}'"),
            };
            let pool_policy = if pool_mode.is_some() || any_opts || manual_failback {
                pool::PoolPolicy::new(pool_mode.unwrap_or(pool::PoolMode::Failover), manual_failback, member_opts)
            } else {
                pool::PoolPolicy::default()
            };
            let alert_cfg = alerts::AlertCfg {
                webhook: a.get("alert-webhook").or_else(|| std::env::var("KHAYMALI_ALERT_WEBHOOK").ok()),
                telegram: match a.get("alert-telegram").or_else(|| std::env::var("KHAYMALI_ALERT_TELEGRAM").ok()) {
                    Some(t) => Some(alerts::AlertCfg::parse_telegram(&t).context("--alert-telegram must be BOT_TOKEN:CHAT_ID")?),
                    None => None,
                },
                proxy: a.get("alert-proxy").or_else(|| std::env::var("KHAYMALI_ALERT_PROXY").ok()),
            };
            let dial_router = if let (Some(g_addr), Some(p_addr)) = (a.get("dial-gre-addr"), a.get("dial-public-addr")) {
                let dm = dial_route::DialMode::parse(&a.get("dial-mode").unwrap_or_else(|| "auto".into()))?;
                Some(std::sync::Arc::new(dial_route::DialRouter::new(dm, g_addr, p_addr)))
            } else {
                None
            };
            let camo = if exits.is_empty() { None } else { a.camo(true)? };
            let mut parsed_forwards = Vec::new();
            for raw_spec in a.all("forward") {
                parsed_forwards.extend(forward::ForwardSpec::parse_many(&raw_spec)?);
            }
            entry::run(entry::EntryCfg {
                socks: a.get("socks").unwrap_or_else(|| "127.0.0.1:1080".into()),
                key: a.key()?,
                exit_pub,
                bridge_listen: a.get("bridge-listen"),
                allowed_bridges: a.pubkeys("allow-bridge")?,
                listen_exit: a.get("listen-exit"),
                tun_if: a.get("tun"),
                exits,
                pool: a.num("pool", 16),
                max_age: Duration::from_secs(a.num("max-age", 120) as u64),
                camo,
                metrics: a.get("metrics"),
                control: a.get("control"),
                require_channel_binding: a.flag("require-channel-binding"),
                mux: !a.flag("no-mux"),
                mux_carriers: a.num("mux-carriers", 4),
                session_resume: !a.flag("no-session-resume"),
                forwards: parsed_forwards,
                adapt: !a.flag("no-adapt"),
                pool_max: a.num("pool-max", (a.num("pool", 16) * 8).clamp(64, 128)),
                adapt_state: adapt_state_path(&a, "entry"),
                pool_policy,
                autopilot: {
                    let alerts_on = !alert_cfg.is_empty();
                    if a.flag("autopilot") {
                        let quiet = match a.get("ap-quiet") {
                            Some(q) => {
                                let (x, y) = q.split_once('-').context("--ap-quiet FROM-TO, e.g. 2-5")?;
                                let (x, y): (u8, u8) = (x.trim().parse()?, y.trim().parse()?);
                                if x > 23 || y > 23 {
                                    bail!("--ap-quiet hours must be 0-23");
                                }
                                Some((x, y))
                            }
                            None => None,
                        };
                        Some(autopilot::Limits {
                            down_min: a.num("ap-down", 5).clamp(1, 720) as u64,
                            cooldown_min: a.num("ap-cooldown", 30).clamp(1, 1440) as u64,
                            per_day: a.num("ap-per-day", 6).clamp(1, 24) as u32,
                            path_test: !a.flag("ap-no-path-test"),
                            quiet,
                            allowed: a.get("ap-carriers").map(|c| c.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()).unwrap_or_default(),
                            tz_offset_min: std::env::var("KHAYMALI_TZ_OFFSET_MIN").ok().and_then(|v| v.parse().ok()).unwrap_or(0),
                            monitor_only: false,
                            ..Default::default()
                        })
                    } else if alerts_on {
                        Some(autopilot::Limits { monitor_only: true, ..Default::default() })
                    } else {
                        None
                    }
                },
                autopilot_state: Some(a.get("ap-state").unwrap_or_else(|| "/var/lib/khaymali/autopilot.state".into())).filter(|p| p != "off"),
                alerts: alert_cfg,
                egress_bridge: a.get("egress-bridge"),
                dial_router,
            })
            .await?;
        }
        "bridge" => {
            let entry_pub = a.pubkeys("entry-pub")?.into_iter().next().context("missing --entry-pub")?;
            let exits = a.all("exit");
            if exits.is_empty() {
                bail!("need at least one --exit");
            }
            bridge::run(bridge::BridgeCfg {
                key: a.key()?,
                entry: a.req("entry")?,
                entry_pub,
                exits,
                pool: a.num("pool", 16),
                camo: a.camo(true)?,
                metrics: a.get("metrics"),
                control: a.get("control"),
                adapt: !a.flag("no-adapt"),
                adapt_state: adapt_state_path(&a, "bridge"),
            })
            .await?;
        }
        "tun" => {
            let exit_pub = a.pubkeys("exit-pub")?.into_iter().next().context("missing --exit-pub")?;
            let exit_addr = a.req("exit")?;
            let key = a.key()?;
            let camo = a.camo(true)?;
            let mode_str = a.get("mode").unwrap_or_else(|| "tun".to_string());
            let mode = l3::L3Mode::from_str(&mode_str)
                .with_context(|| format!("unknown --mode '{mode_str}' (expected tun|gre|ipip)"))?;
            let peer_ip: IpAddr = a
                .get("peer-ip")
                .unwrap_or_else(|| "10.200.0.1".to_string())
                .parse()
                .context("invalid --peer-ip")?;
            let gre_key = a.get("gre-key").and_then(|s| s.parse::<u32>().ok());
            let tun_cfg = l3::TunConfig {
                if_name: a.get("tun").unwrap_or_else(|| "khaymali0".to_string()),
                mode,
                local_cidr: a.get("cidr").unwrap_or_else(|| "10.200.0.2/30".to_string()),
                peer_ip,
                mtu: a.num("mtu", l3::DEFAULT_TUN_MTU as usize) as u16,
                allow_private_routes: a.flag("allow-private"),
                routes: a.all("route"),
                gre_key,
            };

            let tx_impl: Box<dyn transport::Transport> = if transport::needs_multi_transport(std::slice::from_ref(&exit_addr)) {
                if transport::requires_carrier_secret(std::slice::from_ref(&exit_addr)) && camo.is_none() {
                    bail!("udp://, ktunnel://, and wss:// exits require --camo-secret");
                }
                let udp_key = camo.as_ref().map(|c| c.secret.clone()).unwrap_or_default();
                Box::new(transport::AutoTransport {
                    camo,
                    udp_auth_key: udp_key,
                    connect_timeout: Duration::from_secs(10),
                })
            } else if let Some(c) = camo {
                Box::new(transport::CamoTransport {
                    cfg: c,
                    connect_timeout: Duration::from_secs(10),
                })
            } else {
                Box::new(transport::TcpTransport {
                    connect_timeout: Duration::from_secs(10),
                })
            };

            let raw = timeout(Duration::from_secs(10), tx_impl.dial(&exit_addr)).await??;
            let mut lk = timeout(Duration::from_secs(10), link::initiate(raw, &key, &exit_pub)).await??;
            let mode_byte = match mode {
                l3::L3Mode::Gre => 1u8,
                l3::L3Mode::Ipip => 2u8,
                _ => 0u8,
            };
            lk.send(&[4, mode_byte]).await?;
            let ack = timeout(Duration::from_secs(10), lk.recv()).await??;
            if ack != [0] {
                bail!("exit refused L3 TUN session (ensure exit runs with --tun <IFNAME>)");
            }
            #[cfg(target_os = "linux")]
            {
                let dev = l3::LinuxTunDevice::open(&tun_cfg)?;
                eprintln!(
                    "[tun] interface {} up (cidr={}, mode={}, mtu={}) -> {}",
                    dev.if_name,
                    tun_cfg.local_cidr,
                    tun_cfg.mode.as_str(),
                    dev.mtu,
                    exit_addr
                );
                l3::bridge_tun_over_link(dev, lk, tun_cfg).await?;
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (tun_cfg, Ipv4Addr::UNSPECIFIED);
                l3::run_tun_not_supported().await?;
            }
        }
        _ => usage(),
    }
    Ok(())
}

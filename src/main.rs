use khaymali::{
    bridge, camo, entry, exit, fleet, forward, kani_nlp, l3, link, stats, transport,
    transport_engine, util,
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
        "khaymali {ver}  (Khaymali Tunnel)

  khaymali keygen                       new static keypair + 12-char check code + SHA-256 fingerprint
  khaymali secret                       new random camouflage secret
  khaymali check-code <HEX_PUBKEY>      print UI tag, 12-char check code & full SHA-256 fingerprint
  khaymali join-code --endpoint HOST:PORT --exit-pub PUB [--transport auto|udp|ktunnel|camo|tcp]
                     [--camo-sni NAME] [--camo-secret HEX] [--forward 443,2052]
  khaymali parse-join <JOIN_CODE>       decode a khaymali://v1?... join code into CLI flags
  khaymali status [--control SOCK]      query live status from running service control socket
  khaymali forward add|ls|rm ...        manage live port forwards on running Entry
  khaymali up | down [role]             start or stop systemd khaymali services
  khaymali doctor                       local host/clock/artifact/loopback readiness check
  khaymali diagnose <SYMPTOM_TEXT>      offline KANI TinyNetNlp symptom classifier (--stdin | --stdin-combined)
  khaymali intelligence-lab [OPTIONS]   offline deterministic packet/queue digital twin
  khaymali calibrate-risk <TR> <HO> <O> fit Platt risk calibrator artifact
  khaymali promote-nlp-candidate <HO>   evaluate & promote staged NLP candidate artifact
  khaymali transports                   list registered carriers & capabilities
  khaymali intelligence-lab [--scenario all|clean|latency|loss|jitter|throttle|outage]
                             [--steps N] [--capacity-kbps N] [--queue N]
                                         run deterministic offline network digital-twin scenarios
  khaymali calibrate-risk <TRAIN.tsv> <HOLDOUT.tsv> <OUTPUT.model>
                                         fit and independently evaluate a degradation-risk calibrator
  khaymali promote-nlp-candidate <HOLDOUT.tsv> [--min-samples N]
                                         evaluate a staged NLP candidate before promotion
  khaymali verify-config <FILE> <KEY>   verify SignedConfig HMAC & anti-rollback revision

  khaymali exit   --listen ADDR [--udp-listen ADDR] [--ktunnel-listen ADDR]
                  [--reverse-entry HOST:PORT [--reverse-pool N]]
                  --key HEX --allow ENTRY_PUB [--allow ...] [--allow-private]
                  [--tun IFNAME [--tun-cidr 10.200.0.1/30]]
                  [--camo-secret HEX --camo-fallback HOST:PORT [--camo-pad N]]
                  [--metrics ADDR] [--control /run/khaymali/exit.sock]

  khaymali entry  --key HEX --exit-pub EXIT_PUB [--socks ADDR] [--pool N] [--max-age SECS]
                  [--listen-exit ADDR] [--tun khaymali0]
                  [--mux-carriers N] [--no-mux] [--no-session-resume] [--pool-max N] [--no-adapt] [--adapt-state FILE|off]
                  [--bridge-listen ADDR --allow-bridge BRIDGE_PUB [--allow-bridge ...] [--require-channel-binding]]
                  [--exit HOST:PORT|auto://HOST:PORT|udp://HOST:PORT|ktunnel://HOST:PORT [--exit ...]]
                  [--camo-secret HEX --camo-sni NAME [--camo-pad N]]
                  [--forward 443,2052|SPEC [--forward ...]] [--metrics ADDR] [--control /run/khaymali/entry.sock]

  khaymali bridge --key HEX --entry HOST:PORT --entry-pub ENTRY_PUB --exit HOST:PORT [--exit ...]
                  [--pool N] [--no-adapt] [--adapt-state FILE|off] [--camo-secret HEX --camo-sni NAME [--camo-pad N]]
                  [--metrics ADDR] [--control /run/khaymali/bridge.sock]

  khaymali tun    --key HEX --exit-pub EXIT_PUB --exit HOST:PORT|auto://HOST:PORT|udp://HOST:PORT
                  [--tun khaymali0] [--cidr 10.200.0.2/30] [--peer-ip 10.200.0.1]
                  [--mode tun|gre|ipip] [--mtu 1380] [--route CIDR [--route ...]] [--allow-private]
                  [--camo-secret HEX --camo-sni NAME [--camo-pad N]]

  Secrets via env: KHAYMALI_KEY, KHAYMALI_CAMO_SECRET.  Specification: docs/SPEC.md",
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
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = argv.first().cloned() else {
        usage();
        return Ok(());
    };
    let a = Args::parse(&argv[1..]);
    match cmd.as_str() {
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
            let exits = a.all("exit");
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
                pool: a.num("pool", 8),
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
                pool_max: a.num("pool-max", (a.num("pool", 8) * 8).clamp(64, 128)),
                adapt_state: adapt_state_path(&a, "entry"),
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
                pool: a.num("pool", 8),
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

            let tx_impl: Box<dyn transport::Transport> = if exit_addr.starts_with("udp://")
                || exit_addr.starts_with("ktunnel://")
                || exit_addr.starts_with("auto://")
            {
                let udp_key = camo
                    .as_ref()
                    .map(|c| c.secret.clone())
                    .context("udp://, ktunnel://, and auto:// exits require --camo-secret")?;
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

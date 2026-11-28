# Linux Tunnel Manager (integrated into core)

This companion is **part of the main Khaymali binary** (pure Rust).

There is no separate Python/Go package anymore.

## Commands

```bash
# Interactive classic tunnels + Khaymali Light
sudo khaymali tunnels

# Boot restore / cleanup
sudo khaymali tunnels-restore
sudo khaymali tunnels-clean

# Data plane (usually managed via systemd after menu setup)
sudo khaymali light --config /etc/khaymali-light/config.json
```

## State

- Classic tunnels: `/etc/khaymali/tunnels/tunnels.json`
- Light config: `/etc/khaymali-light/config.json`
- Service: `khaymali-light.service` (ExecStart → `khaymali light --config ...`)
- Boot unit: `khaymali-tunnels-restore.service`

## Build

Built with the main crate — no extra crate required:

```bash
cargo build --release
sudo install -m 755 target/release/khaymali /usr/local/bin/khaymali
```

Source lives in `src/ltm/`.

## Automatic benchmark (iperf3)

```bash
# Peer A (server side of the tunnel inner IP)
sudo khaymali tunnels-bench --server --port 5201 --duration 5

# Peer B (client)
sudo khaymali tunnels-bench --target 10.99.1.2 --bind 10.99.1.1 --duration 5 --proto gre
```

Or from the interactive menu: `khaymali tunnels` → option **9**.

If `iperf3` is missing, a pure-TCP flood/sink fallback is used automatically.

## QoS on tunnel interfaces

```bash
# Recommended default: CAKE on the tunnel iface + host BBR/fq
sudo khaymali tunnels-qos --dev kmlight0 --profile cake

# Cap uplink to 80% of real bandwidth (reduces bufferbloat)
sudo khaymali tunnels-qos --dev kmlight0 --profile cake-limit --rate 80mbit

# Classic HTB rate limit + fq_codel classes
sudo khaymali tunnels-qos --dev gre_0 --profile htb --rate 50mbit

# Host sysctl only
sudo khaymali tunnels-qos --profile host

sudo khaymali tunnels-qos --dev kmlight0 --status
sudo khaymali tunnels-qos --dev kmlight0 --clear
```

Profiles: `host` | `low-latency` (fq_codel) | `cake` | `cake-limit` | `htb`.

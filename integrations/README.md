# Integrations

## Linux Tunnel Manager (pure Rust)

`integrations/linux-tunnel-manager` is a pure-Rust companion:

- Classic kernel tunnels (GRE, IPIP, VXLAN, GENEVE, WireGuard, L2TP, ...)
- **Khaymali Light** data plane (Rust)
- Interactive CLI + boot persistence

```bash
cd integrations/linux-tunnel-manager
cargo build --release --bins
sudo ./install.sh
sudo tunnel
```

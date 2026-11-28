# Khaymali Manager Companion (pure Rust)

Companion toolkit for **Khaymali Tunnel**, located at
`integrations/linux-tunnel-manager`.

**Entirely written in Rust** — no Python, no Go.

Provides:
- Interactive management of classic Linux kernel tunnels (GRE, IPIP, VXLAN, GENEVE, WireGuard, L2TPv3, ...)
- **Khaymali Light** — lightweight stamped-UDP TUN tunnel (native Rust data plane)
- Persistence across reboots via systemd oneshot
- Routing / sysctl helpers

## Build

```bash
cd integrations/linux-tunnel-manager
cargo build --release --bins
```

## Install

```bash
sudo ./install.sh
sudo tunnel                 # interactive manager
# or
sudo khaymali-manager
```

## Khaymali Light

```bash
# configured from the manager menu (option 3), or manually:
sudo khaymali-light --config /etc/khaymali-light/config.json
```

Service unit is installed as `khaymali-light.service`.

## Notes

- All previous Python / Go / "Holy" code paths have been removed.
- Protocol id for the light tunnel is `kmlight`.

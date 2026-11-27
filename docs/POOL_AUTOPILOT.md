# Pool, Autopilot and alerts (v0.17.0)

## Pool
```
khaymali entry ... \
  --exit 203.0.113.5:443;w=3 --exit 198.51.100.9:443;w=1 --pool-mode balance
khaymali entry ... --exit A:443;p=0 --exit B:443;p=1;standby --pool-mode failover --failback manual
khaymali pool status | drain B:443 | undrain B:443 | failback
```
Modes: failover (lowest p), balance (random by w), sticky, latency (lowest RTT), least (fewest live links per weight). `max=` caps live links (overflow goes to standby), `drain` stops new links.

## Autopilot
One --exit per carrier the Exit listens on:
```
khaymali entry ... --camo-secret S --camo-sni NAME \
  --exit HOST:443 --exit udp://HOST:444 --exit ktunnel://HOST:445 \
  --autopilot --ap-down 5 --ap-cooldown 30 --ap-per-day 6 --ap-quiet 2-5 \
  --alert-telegram BOT_TOKEN:CHAT_ID
khaymali autopilot            # history
```
Default state file: /var/lib/khaymali/autopilot.state (`--ap-state off` disables).

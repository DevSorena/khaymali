# Khaymali - Install (v0.16.0)

## 1. Abroad server (Exit) - one command
    bash <(curl -fsSL https://raw.githubusercontent.com/DevSorena/khaymali/main/install.sh)
    # menu -> 1 (Setup EXIT)

At the end the Exit prints ONE command. The Entry and Bridge keys are already
generated and allowed on the Exit, so nothing has to be copied back.

## 2. Iran server (Entry) - paste that command
    bash <(curl -fsSL https://raw.githubusercontent.com/DevSorena/khaymali/main/install.sh) --join 'khaymali://v1?...'

It installs everything, tests the path, picks DIRECT or BRIDGE, fixes the clock
(NTP or `ktime` every 10 min), starts the service, and runs `status`.

GitHub blocked on Iran? On the Exit run:  `khaymali-manager push root@IRAN_IP`
(or menu -> p). It copies the binary over SSH and runs the join there.

## 3. Bridge (only when Iran has no international access)
The Entry prints `khaymali-manager join-bridge '...'`. Run it on the Bridge.
A second Bridge for failover: on the Entry, menu 8 -> n.

## Dashboard
    khaymali-tui         # or: khaymali ui     (ASCII mode: khaymali-tui --ascii)
Keys: tab tabs | enter open | space start/stop | R restart | l link | t test | c clock | q quit

## Troubleshooting
* `link_fails` grows and the log says `timestamp skew`: `khaymali-manager fix-clock` on Entry AND Bridge.
* `status` now shows the clock skew and a red line when peers are rejected because of the clock.

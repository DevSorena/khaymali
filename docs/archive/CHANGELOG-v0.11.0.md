# Khaymali v0.11.0 — Release Notes

## Adaptive, multi-mode UDP FEC (`src/udp_transport.rs`)

v0.10.0 used a fixed XOR-parity of 1 packet per 4 data packets. v0.11.0 makes the group size
variable and lets the sender tune it to the measured loss.

| `KHAYMALI_FEC` | parity per data packets | overhead | use when |
|---|---|---|---|
| `off` | none | 0% | clean link |
| `light` | 1 per 8 | 12.5% | rare loss |
| `moderate` (default) | 1 per 4 | 25% | same behaviour as v0.10.0 |
| `aggressive` | 1 per 2 | 50% | heavy loss |
| `auto` | 8 / 4 / 3 / 2, chosen per session | varies | unknown or changing link |

* `auto` counts retransmits vs. data packets per session, smooths them with an EWMA and
  re-evaluates once per second (needs >= 20 data packets in the window). Loss < 1% -> 1/8,
  < 4% -> 1/4, < 10% -> 1/3, otherwise 1/2.
* The receiver needs no setting: each parity packet carries its own group size, and the receiver
  keeps a small sequence-indexed shard cache, so recovery works whatever the arrival order.
* One lost packet per group is recovered without waiting for ARQ; two or more still fall back
  to selective-repeat ARQ.
* New metric: `khaymali_udp_fec_group_size` (current group size, 0 = off). Existing
  `udp_fec_recovered_total` is unchanged.
* Wire format: `k = 4` still emits the exact v0.10.0 parity payload. Any other `k` emits
  `[0xFE][k][lengths...][xor]`.

### Upgrade note
Upgrade **both** sides before setting `KHAYMALI_FEC` to anything other than `moderate`.
A v0.10.0 peer cannot parse parity packets with `k != 4`; it would not crash, but the data it
"recovers" is wrong and the Noise layer then drops the session. With the default (`moderate`)
v0.11.0 and v0.10.0 interoperate.

## Other
* Removed a stray reference to an old project name from a source comment.
* Version bumped to 0.11.0.

## Tests added
`fec_v2_tests` in `src/udp_transport.rs`: round-trip for every k in 2..=16 and every missing
index, legacy-format check for k=4, rejection of 2 losses / wrong k, receiver recovery with
parity-first and data-first arrival order, mode parsing and auto levels, loss estimator.

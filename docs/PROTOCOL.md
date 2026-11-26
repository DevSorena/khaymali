# Khaymali wire protocol (v1)

All integers are big-endian. This document describes version 0.2.

## Layers (outermost first)

```
TCP
 └─ [optional] camouflage records            (Bridge/Entry -> Exit hop only)
     └─ link frames:  u16 length | payload
         └─ Noise_IK transport messages      (end to end, Entry <-> Exit)
             └─ requests / data / datagrams
```

## 1. Link frames
`u16 len | payload` (len ≤ 65535). Handshake messages and Noise transport messages travel in these frames.
Noise transport messages carry at most 16384 plaintext bytes (+16 byte tag). Each direction uses its own
nonce counter starting at 0 (stateless transport state).

## 2. Entry ↔ Exit link: Noise_IK
* Pattern `Noise_IK_25519_ChaChaPoly_BLAKE2s`, prologue `khaymali/link/1`.
* The Entry (initiator) pins the Exit's static public key. The Exit (responder) accepts only initiators
  whose static public key is in its `--allow` list; otherwise it closes without replying.
* After the handshake: `Link` carries application messages.

### Requests (Entry → Exit, first message on a link)
| Byte 0 | Meaning | Rest |
|---|---|---|
| `0x01` | TCP connect | SOCKS5 address `ATYP | addr | port` |
| `0x02` | UDP associate | – |

Reply (Exit → Entry): `0x00` ok, `0x01` failed.

### TCP data
Each message is a chunk of the byte stream (≤ 16384). An **empty message** means end-of-stream for that direction.

### UDP datagrams
One datagram per message: `ATYP | addr | port | payload`. Entry→Exit: destination. Exit→Entry: source.
Idle timeout 120 s. IPv4 only. Fragmented SOCKS5 UDP datagrams are dropped.

### Address encoding (SOCKS5 style)
`0x01 + 4 bytes`, `0x04 + 16 bytes`, or `0x03 + len + name`, followed by a 2-byte port.

## 3. Bridge → Entry authentication
Noise_IK with prologue `khaymali/bridge/1`; the Bridge is the initiator and pins the Entry's public key.
The Entry accepts only keys in `--allow-bridge`. After the two handshake messages the Bridge sends one
encrypted confirmation frame (`khaymali-bridge-ok`, nonce 0); this proves possession of the static key
and defeats replay of a captured first message. The transport state is then discarded and the stream is
spliced raw to the Exit; the Entry immediately starts the Entry↔Exit handshake over it.

## 4. Camouflage (optional)
Configured with a shared secret `S` (≥ 16 bytes).

### Client → server
A TLS record `16 03 01 len` containing a ClientHello (Chrome-family cipher/extension set, GREASE,
SNI = `--camo-sni`, padded to 512 bytes). Authentication tag:

```
nonce  = 16 random bytes
random = nonce || HMAC-SHA256(S, "auth" || nonce || ts_be8)[0..16]
mask   = HMAC-SHA256(S, "ts" || nonce)[0..8]
session_id = (ts_be8 XOR mask) || 24 random bytes
```
`ts` is unix seconds. The timestamp is masked so the field looks random.

### Server decision
1. Read the first TLS record. If it is not a plausible ClientHello → **fallback**.
2. Verify `|now - ts| ≤ 120 s`, the tag (constant-time), and that `nonce` has not been seen (replay cache) → else **fallback**.
3. **Fallback**: connect to `--camo-fallback`, forward everything consumed so far in one write, then relay
   both directions (≤ 5 min). The prober talks to the real site.
4. Valid: send a ServerHello record (TLS_AES_128_GCM_SHA256, x25519 key_share with random bytes, echoing the
   session id), a ChangeCipherSpec record, and 3 random-sized `application_data` records imitating the
   encrypted handshake flight. The client discards them, sends a ChangeCipherSpec record, and both sides
   switch to data records.

### Data records
`17 03 03 plen | real_len(u16) | data | random padding`, with `plen = 2 + real_len + padding` and
padding uniformly in `0..=--camo-pad` (default 48). Link frames are carried inside.

### What camouflage does not do
It imitates, but does not perform, the TLS handshake for authenticated peers; it does not shape traffic
to a profile; JA3/JA4 equivalence is unverified. See README "Known limitations".

## 5. Exit selection (Entry/Bridge)
Each exit has an EWMA RTT and a failure counter. Score = `rtt_ms + 400 × failures`. A failed exit is
backed off for `2^min(failures,6)` seconds. New links go to the best available exit; 15 % of the time to
a random healthy one. A background prober connects to every exit every 20 s.
Exits behind one Entry share one identity key.

## 6. Threat model (summary)
| Observer | Learns |
|---|---|
| Bridge owner / on-path between Entry and Exit | Ciphertext, sizes, timing, endpoints. Not destinations or content |
| Passive DPI on the Bridge→Exit hop with camouflage | A TLS-like flow to the Exit IP/SNI with random padding |
| Active prober sending anything without the secret | The decoy site's real behaviour (minor TCP-close differences possible) |
| Replay of a captured ClientHello | Treated as a probe (decoy) after the first use |
| Holder of an Entry key | Can use the Exit as a proxy: guard these keys |
| Compromised Exit | Sees plaintext destinations/traffic of tunnelled users |

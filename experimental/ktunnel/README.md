# Multi-Flow FakeTLS-Mux (`ktunnel`) — Userspace & Kernel Module

Khaymali v0.9.0 supports **both** a zero-dependency userspace implementation (`ktunnel://HOST:PORT`)
and the Linux kernel module (`k_tcpmux.ko` + `ktun_cc.ko` + `ktun_handshake`).

## 1. Userspace `ktunnel://` Carrier (Works Anywhere, No Root/Headers Needed)
- **Exit:**
  ```bash
  khaymali exit --listen 0.0.0.0:443 --ktunnel-listen 0.0.0.0:8443 --key <HEX> --allow <ENTRY_PUB> --camo-secret <HEX>
  ```
- **Entry / Bridge:**
  ```bash
  khaymali entry --key <HEX> --exit-pub <EXIT_PUB> --exit ktunnel://<EXIT_IP>:8443 --camo-secret <HEX> --camo-sni example.com
  ```

## 2. Linux Kernel Module (`k_tcpmux.ko` + `ktun_cc.ko` + `ktun_handshake`)
```bash
cd experimental/ktunnel
make clean && make
```
Load on server & client (with 32-hex `obfs_secret` for keyed keystream masking):
```bash
insmod ktun_cc.ko
insmod k_tcpmux.ko local_ip_str=<LOCAL_IP> remote_ip_str=<REMOTE_IP> is_server=1 server_port=443 base_client_port=49152 obfs_secret=<32_HEX>
ip link set mux0 up && ip addr add 10.0.0.2/30 dev mux0
./ktun_handshake server 443 49152
```

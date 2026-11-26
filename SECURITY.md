# Security policy

Khaymali Tunnel has **not** been independently audited. Treat it as experimental.

## Reporting a vulnerability
Please do not open a public issue for security problems. Use GitHub's private
"Report a vulnerability" feature on this repository (Security tab), or contact the maintainers privately.
Include: version, configuration (redact keys), steps to reproduce, and impact.

## Scope
In scope: the handshake/authentication logic, the camouflage fallback behaviour (probe handling),
parsing of untrusted input (ClientHello, SOCKS5, framed messages), resource exhaustion.
Out of scope: attacks that require control of the Entry/Exit host, or blocking by IP address.

## Operational advice
* Keep private keys and camouflage secrets in environment files with mode 600, never in shell history.
* One keypair per node; remove a node's public key from the allow-lists to revoke it.
* Keep clocks synchronised (NTP).
* Do not expose the SOCKS5 port beyond loopback.

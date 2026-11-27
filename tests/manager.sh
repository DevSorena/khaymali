#!/usr/bin/env bash
# Offline unit tests for khaymali-manager helpers (no root, no systemd needed).
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
export KHAYMALI_MANAGER_SOURCED=1 KHAYMALI_CONF="$T/etc" KHAYMALI_UNITDIR="$T/units" KHAYMALI_LOG="$T/log" \
       KHAYMALI_BACKUP_DIR="$T/bk" KHAYMALI_BINPATH=/bin/true
mkdir -p "$T/etc" "$T/units"
# shellcheck disable=SC1091
. "$HERE/scripts/khaymali-manager"
systemctl() { return 0; }   # stub: no systemd in CI

PASS=0; FAILN=0
ok()   { PASS=$((PASS+1)); }
bad()  { FAILN=$((FAILN+1)); echo "  FAIL: $1"; }
t()    { local name="$1"; shift; if "$@" >/dev/null 2>&1; then ok; else bad "$name"; fi; }
tn()   { local name="$1"; shift; if "$@" >/dev/null 2>&1; then bad "$name"; else ok; fi; }

t  "valid ipv4"            valid_ipv4 203.0.113.7
tn "ipv4 octet > 255"      valid_ipv4 300.1.1.1
tn "ipv4 garbage"          valid_ipv4 abc
t  "private 10/8"          is_private_ip 10.1.2.3
t  "private 172.16/12"     is_private_ip 172.20.0.1
tn "public not private"    is_private_ip 8.8.8.8

# forwards
SOCKS="127.0.0.1:1080"; BRIDGE_LISTEN="0.0.0.0:4444"; METRICS="127.0.0.1:9090"; EXITS="198.51.100.9:443"
t  "fwd simple"            validate_forward "8443@name=A,target=127.0.0.1:8080"
t  "fwd remap"             validate_forward "8080=80@target=127.0.0.1:80"
t  "fwd udp"               validate_forward "2053/udp@target=127.0.0.1:2053"
tn "fwd collides socks"    validate_forward "1080@target=127.0.0.1:80"
tn "fwd collides bridge"   validate_forward "4444@target=127.0.0.1:80"
tn "fwd loop to exit port" validate_forward "9000@target=198.51.100.9:443"
tn "fwd loop loopback"     validate_forward "9000@target=127.0.0.1:443"
tn "fwd bad spec"          validate_forward "abc"
tn "fwd spaces"            validate_forward "80 @x"
[ "$(fwd_local_ports 2000-2003@target=1.1.1.1 | wc -l)" = 4 ] && ok || bad "fwd range expand"

# config validation (the file is sourced by root => strict format only)
printf 'LISTEN="0.0.0.0:443"\nALLOW="a b"\n# c\n\n' > "$T/c1"; t  "conf valid"  conf_valid "$T/c1"
printf 'LISTEN="x"\n$(rm -rf /)\n' > "$T/c2";            tn "conf injection" conf_valid "$T/c2"
printf 'LISTEN="x"; id\n' > "$T/c3";                      tn "conf chained cmd" conf_valid "$T/c3"
printf 'LISTEN="unterminated\n' > "$T/c4";                tn "conf syntax" conf_valid "$T/c4"

# timers
[ "$(interval_spec 1hour)" = hourly ] && ok || bad "interval 1hour"
tn "interval bogus" interval_spec 5years

# unit generation
save_kv "$(conf entry)" EXIT_PUB "$(printf 'a%.0s' {1..64})" EXITS "198.51.100.9:443" SOCKS "127.0.0.1:1080" POOL 8 METRICS "127.0.0.1:9090" SELF_PUB x
write_env entry "$(printf 'b%.0s' {1..64})" ""
write_unit entry >/dev/null 2>&1
U="$T/units/khaymali-entry.service"
t "unit written"          test -s "$U"
t "unit StartLimit off"   grep -q '^StartLimitIntervalSec=0' "$U"
t "unit hardening"        grep -q '^CapabilityBoundingSet=CAP_NET_BIND_SERVICE' "$U"
t "unit state dir"        grep -q '^StateDirectory=khaymali-entry' "$U"
t "unit adapt-state arg"  grep -q -- '--adapt-state /var/lib/khaymali-entry/adapt.state' "$U"
t "unit runtime preserve" grep -q '^RuntimeDirectoryPreserve=yes' "$U"
[ "$(stat -c %a "$U")" = 644 ] && ok || bad "unit mode 644"
[ "$(stat -c %a "$(envf entry)")" = 600 ] && ok || bad "env mode 600"

# backup / restore safety
backup_conf quiet; B="$(ls "$T"/bk/khaymali-conf-*.tar.gz | head -1)"
t  "backup created"       test -f "$B"
[ "$(stat -c %a "$B")" = 600 ] && ok || bad "backup mode 600"
mkdir -p "$T/evil/etc/x"; echo hi > "$T/evil/etc/x/y"; tar -czf "$T/evil.tgz" -C "$T/evil" etc/x
tar -tzf "$T/evil.tgz" | grep -qvE "^${CONF#/}(/|$)" && ok || bad "foreign archive detected"

# tuning list only contains key=value pairs
tune_pairs | grep -qvE '^[a-z0-9_.]+=.+$' && bad "tune_pairs format" || ok

# v0.16.0
[ "$(list_dedup "k1 k2 k1  k2")" = "k1 k2" ] && ok || bad "dedup keys"
[ "$(list_add "k1" "k1")" = "k1" ] && ok || bad "no duplicate add"
J='khaymali://v1?ep=1.2.3.4:443&pk=aa&sni=s&sec=bb&ek=cc&epk=dd'
[ "$(qparam "$J" ep)" = "1.2.3.4:443" ] && [ "$(qparam "$J" epk)" = dd ] && ok || bad "join params"
tn "join bad scheme" join_check "http://x"
[ "$(lc Bridge)" = bridge ] && ok || bad "case-insensitive mode"
LC_ALL=C grep -q '[^ -~[:space:]]' "$HERE/scripts/khaymali-manager" && bad "manager not ASCII" || ok

echo "manager tests: $PASS passed, $FAILN failed"
[ "$FAILN" = 0 ]

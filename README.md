# Khaymali Tunnel · تانل خایمالی

> تانل ضدفیلترینگ متن‌باز (**MIT**) به زبان **Rust**. نسخهٔ فعلی سورس: **0.22.7**.

رمزنگاری سرتاسری `Noise_IK`، استتار TLS با fallback ایزوله، فوروارد پورت لایه ۴، **Tunneling Suite**، **Pool و Autopilot**، **Cluster Mesh / Load Balancer**، و **Micro-NLP** برای شبکه‌های سخت.

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Rust 1.85](https://img.shields.io/badge/rust-1.85-orange.svg)](rust-toolchain.toml)
[![Crypto](https://img.shields.io/badge/crypto-Noise__IK-blue.svg)](docs/SPEC.md)
[![Platform](https://img.shields.io/badge/platform-Linux%20amd64%20%7C%20arm64-lightgrey.svg)](#نصب)
[![CI](https://github.com/DevSorena/khaymali/actions/workflows/ci.yml/badge.svg)](https://github.com/DevSorena/khaymali/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/DevSorena/khaymali)](https://github.com/DevSorena/khaymali/releases/latest)

[فارسی](#فارسی) · [English](#english) · [CHANGELOG](CHANGELOG.md) · [SPEC](docs/SPEC.md) · [Tunneling Suite](docs/KHAYMALI_TUNNELING_SUITE.md) · [Pool & Autopilot](docs/POOL_AUTOPILOT.md) · [Security](SECURITY.md)

---

## فارسی

### این چیست؟

خایمالی برای مسیری ساخته شده که سرور داخلی (مثلاً ایران‌اکسس) به اینترنت آزاد دسترسی پایدار ندارد، یا روی مرز فیلترینگ و active probing هست.

سه نقش:

```text
کاربر  →  Entry  →  (اختیاری: Bridge)  →  Exit  →  مقصد
         Noise_IK سرتاسری؛ Bridge فقط فوروارد می‌کند و plaintext را نمی‌بیند
```

| نقش | کار |
|-----|-----|
| **Entry** | سمت کاربر / ایران. SOCKS5 محلی و فوروارد پورت |
| **Bridge** | وقتی Entry مستقیم به Exit نمی‌رسد |
| **Exit** | سمت آزاد. ترافیک را به مقصد می‌فرستد |

### امکانات

- رمزنگاری `Noise_IK`، ضد-replay، ضد-SSRF
- استتار TLS (Camo) با fallback به یک سایت decoy
- فوروارد TCP/UDP لایه ۴ با سهمیه و rate limit
- حامل‌ها: TCP، UDP+FEC، WebSocket / WSS، GRE/FOU، SSH، Spoof
- Pool: `failover` · `balance` · `sticky` · `latency` · `least`
- Autopilot: تست مسیر، جابه‌جایی، rollback
- Cluster mesh، load balancer، node fleet
- `harsh_nlp` / TinyNetNlp (پیش‌فرض **shadow**)
- پشتیبان رمزشده (`khaymali backup`) و ربات تلگرام ادمین (`khaymali tgbot`)

### وضعیت ماژول‌ها

| بخش | وضعیت |
|-----|:-----:|
| هسته تونل (Noise، Entry/Bridge/Exit، SOCKS5، L4، Mux) | RC |
| FakeTLS + decoy fallback | RC |
| UDP + FEC، WebSocket، session resume | بتا |
| Pool، Autopilot، carrier swap | بتا |
| Tunneling Suite، Cluster، NLP | بتا (NLP پیش‌فرض shadow) |
| `experimental/ktunnel` | آزمایشی؛ در بیلد پیش‌فرض نیست |

### تازه‌های 0.22.7

جزئیات کامل در [CHANGELOG.md](CHANGELOG.md).

- **Resume:** اثبات AttachReq با HMAC قبل از ledger؛ توکن صفر دیگر پذیرفته نمی‌شود؛ hijack با `session_id` شناخته‌شده رد می‌شود.
- **Replay ledger** زیر فشار پاک نمی‌شود؛ قدیمی‌ترین proofها FIFO خارج می‌شوند.
- **Camo fallback:** درخواست HTTP کوتاه کامل خوانده می‌شود و RST دکو (نه فقط FIN) به کلاینت می‌رسد.

### نصب

پیش‌نیاز: لینوکس amd64 یا arm64، systemd، root، `curl`، ساعت هم‌زمان (±۱۲۰ ثانیه).

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/DevSorena/khaymali/main/install.sh)
```

| فلگ | معنی |
|-----|------|
| `--tune` / `--revert-tune` | تنظیم / برگرداندن sysctl |
| `--verify-attestation` | بررسی attestation |
| `KHAYMALI_BUILD=1` | بیلد از سورس به‌جای باینری |
| `KHAYMALI_NO_MENU=1` | بدون منوی تعاملی |

### راه‌اندازی سریع

```bash
khaymali keygen          # کلید Noise
khaymali secret          # secret مشترک حامل
```

**Exit**

```bash
khaymali exit \
  --listen 0.0.0.0:443 \
  --allow "<ENTRY_PUBLIC>"
```

**Entry** (مستقیم)

```bash
khaymali entry \
  --exit-pub "<EXIT_PUBLIC>" \
  --exit "<EXIT_IP>:443" \
  --socks 127.0.0.1:1080
```

**Bridge** (وقتی مسیر مستقیم نیست)

```bash
khaymali bridge \
  --entry "<ENTRY_IP>:4444" \
  --exit "<EXIT_IP>:443"
```

فوروارد یک سرویس روی Exit:

```bash
--forward "443@name=VLESS,target=127.0.0.1:443,quota=1T,rate=100M"
```

کاربر نهایی به **IP سرور Entry** و پورت فورواردشده وصل می‌شود، یا از SOCKS روی `127.0.0.1:1080`.

راه‌اندازی تعاملی و Join Code: `khaymali-manager` / `khaymali ui`.

### کنترل و عیب‌یابی

```bash
khaymali-tui
khaymali harsh-nlp status
khaymali harsh-nlp mode shadow    # پیش‌فرض؛ active فقط بعد از A/B
khaymali-doctor serve             # روی Exit
khaymali diagnose
```

NLP در حالت active حداکثر ۶ تغییر در دقیقه اعمال می‌کند. اگر موفقیت ≥۱۰ واحد یا goodput ≥۲۵٪ افت کند، تغییر برمی‌گردد و آن نوع اقدام قفل می‌شود. `harsh_nlp` بعد از پسرفت ۱۸۰ ثانیه قفل می‌شود.

### ساخت از سورس

```bash
# Rust 1.85 (rust-toolchain.toml)
cargo build --release --locked
bash scripts/verify_build_and_tests.sh
```

### مدیریت تونل کلاسیک (`khaymali tunnels`)

ابزار مدیریت تونل‌های کلاسیک کرنل، به‌طور کامل به Rust بازنویسی و مستقیم داخل باینری اصلی ادغام شده (نه یک پروژهٔ جدا):

```bash
khaymali tunnels              # منوی تعاملی: ساخت/حذف تونل، فورواردینگ پورت، routing
khaymali tunnels-restore      # بازیابی تونل‌ها بعد از ری‌بوت (systemd)
khaymali tunnels-clean        # حذف رابط‌های موقت
khaymali tunnels-bench        # بنچمارک خودکار (iperf3 یا TCP fallback)
khaymali light                # اجرای Khaymali Light (تونل UDP سبک روی TUN)
```

پروتکل‌های پشتیبانی‌شده: GRE، GRETAP، IPIP، SIT، EoIP، VXLAN، GENEVE، L2TPv3، WireGuard، به‌اضافهٔ Khaymali Light.

ابزارهای QoS روی رابط تونل هم موجود است (`fq_codel`/`CAKE`، DSCP marking) تا تأخیر زیر بار پایین بماند؛ همه از طریق `khaymali tunnels` در دسترس‌اند و هماهنگ با تنظیمات `khaymali ops tune`.

### محدودیت‌های شناخته‌شده

- استتار TLS معادل Reality یا ShadowTLS نیست. شکاف probe ساده مستند است؛ v0.22.7 فاصلهٔ FIN/RST دکو را کم کرده، ولی ادعای «غیرقابل تشخیص» ندارد.
- ممیزی امنیتی مستقل انجام نشده.
- UDP، FEC و Mux زیر بار خیلی سنگین هنوز بتا هستند.
- NLP روی لاگ مصنوعی سنجیده شده؛ دادهٔ برچسب‌خوردهٔ واقعی معیار پذیرش است.

---

## English

Khaymali is an open-source (MIT) censorship-resistant tunnel: **Entry → optional Bridge → Exit**, end-to-end **Noise_IK**. The bridge forwards ciphertext only.

**v0.22.7** hardens session resume (HMAC-bound attach proofs, no empty peer key, no session overwrite, FIFO replay eviction) and makes the TLS-camo decoy mirror a short HTTP probe plus RST, not a bare FIN.

### Install

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/DevSorena/khaymali/main/install.sh)
```

### Minimal roles

```bash
khaymali keygen && khaymali secret

khaymali exit  --listen 0.0.0.0:443 --allow "<ENTRY_PUBLIC>"

khaymali entry --exit-pub "<EXIT_PUBLIC>" --exit "<EXIT_IP>:443" \
               --socks 127.0.0.1:1080

khaymali bridge --entry "<ENTRY_IP>:4444" --exit "<EXIT_IP>:443"
```

Forward: `--forward "443@name=VLESS,target=127.0.0.1:443,quota=1T,rate=100M"`.

Clients use the **Entry** address, or local SOCKS `127.0.0.1:1080`.

### Build

```bash
cargo build --release --locked
```

Pinned toolchain: Rust **1.85**. See [CHANGELOG.md](CHANGELOG.md) and [docs/SPEC.md](docs/SPEC.md).

Network intelligence stays in **shadow** unless you opt in after an A/B run (`RUN_AB=1 bash scripts/verify_build_and_tests.sh`). Do not enable `active` if the clean profile regresses.

### Classic tunnel management (`khaymali tunnels`)

A classic kernel-tunnel management tool, fully rewritten in Rust and merged directly into the main binary (not a separate project):

```bash
khaymali tunnels              # interactive menu: create/remove tunnels, port forwarding, routing
khaymali tunnels-restore      # restore tunnels on boot (systemd)
khaymali tunnels-clean        # remove temporary interfaces
khaymali tunnels-bench        # automatic benchmark (iperf3 or TCP fallback)
khaymali light                # run Khaymali Light (lightweight UDP tunnel over TUN)
```

Supported protocols: GRE, GRETAP, IPIP, SIT, EoIP, VXLAN, GENEVE, L2TPv3, WireGuard, plus Khaymali Light.

QoS helpers on the tunnel interface are also included (`fq_codel`/`CAKE`, DSCP marking) to keep latency low under load; available via `khaymali tunnels` and aligned with `khaymali ops tune`.

### Honest limits

Camouflage is not Reality/ShadowTLS. There is no independent audit. UDP/FEC/mux and the tunneling suite are beta. The kernel module under `experimental/ktunnel` is not in the default build.

## License

[MIT](LICENSE) — DevSorena.

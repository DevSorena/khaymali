# Khaymali Tunnel v0.15.1 · تانل خایمالی

> **تانل سه‌نودی ضدفیلترینگ و متن‌باز (MIT) نوشته‌شده با Rust** — طراحی‌شده برای سرورهای ایران‌اکسس و شبکه‌های محدود، با رمزنگاری سرتاسری `Noise_IK`، استتار TLS با Fallback ایزوله، فوروارد پورت لایه ۴، ابزار تشخیص داخلی (`khaymali doctor`)، هوشمندی شبکه تطبیقی (`TinyNetNlp` v4.3 + کالیبراسیون ریسک + شبیه‌ساز صف)، سرویس‌های `systemd` و داشبورد Grafana.

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Rust 1.75+](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](#ساخت-از-سورس-و-تستها)
[![Crypto](https://img.shields.io/badge/crypto-Noise__IK-blue.svg)](#۱-تانل-خایمالی-چیست-و-چطور-کار-میکند)
[![Platform](https://img.shields.io/badge/platform-Linux%20amd64%20%7C%20arm64-lightgrey.svg)](#۴-نصب-تکخطی)

[راهنمای کامل فارسی](#-راهنمای-فارسی) · [English Guide](#-english-guide) · [محدودیت‌های شناخته‌شده](#۱۱-محدودیتهای-شناختهشده-صادقانه) · [مستند فنی (SPEC)](docs/SPEC.md)

---

# 🇮🇷 راهنمای فارسی


## وضعیت پایداری ماژول‌ها (v0.15.1)

| بخش | وضعیت | توضیح |
| :--- | :---: | :--- |
| هسته تونل (`Noise_IK`، Entry/Bridge/Exit، SOCKS5، L4 Forward، Mux) | **پایدار (RC)** | رمزنگاری سرتاسری، ضد-SSRF و گیت‌های تست امنیتی منفی |
| استتار FakeTLS + Fallback به Decoy | **پایدار (RC)** | دارای شکاف شناخته‌شده پروب HTTP ساده (بخش ۱۱) |
| انتقال UDP + Adaptive XOR-Parity FEC | **بتا** | با برآوردگر واقعی پکت‌لاس و بازیابی ۰-RTT |
| هوشمندی شبکه (`TinyNetNlp` v4.3، کالیبراسیون، `PathIntelligence`) | **بتا (Opt-in)** | پیش‌فرض `shadow`؛ فعال‌سازی با `KHAYMALI_NLP_MODE=active` و `KHAYMALI_PATH_INTEL=active` |
| ماژول کرنل `experimental/ktunnel` | **آزمایشی** | خارج از مسیر پیش‌فرض بیلد |

## هوشمندی شبکه در v0.15.1 (حفاظ اقدام)

NLP به‌طور پیش‌فرض در حالت `shadow` است و فقط گزارش می‌دهد. با `KHAYMALI_NLP_MODE=active` فقط دو پارامتر محدود (اندازه چانک و pacing) را تغییر می‌دهد، آن هم با این حفاظ‌ها:

* حداکثر **۶ تغییر در دقیقه** و هر بار فقط **یک تغییر در حال ارزیابی**.
* قبل از هر تغییر، نرخ موفقیت و goodput ثبت می‌شود. اگر بعد از تغییر نرخ موفقیت **۱۰ واحد** یا goodput **۲۵٪** افت کند، تغییر **خودکار برمی‌گردد** و آن نوع اقدام **۱۰ دقیقه قفل** می‌شود.
* هر اقدام یک خط `[nlp] ...` در لاگ می‌نویسد: دلیل، کلمه‌های مؤثر، مقدار قبل و بعد.
* شمارنده‌ها: `khaymali_nlp_reverts_total`، `khaymali_nlp_rate_limited_total`، `khaymali_nlp_persist_failures_total`.

قبل از روشن کردن active، مقایسه A/B را اجرا کنید (هر پروفایل ۳ بار):

```bash
RUN_AB=1 REPEATS=3 bash scripts/verify_build_and_tests.sh
```

اگر `ab_compare.py` بگوید پروفایل `clean` بدتر شده (کد خروج ۱)، active را روشن نکنید. برای ارتقای مدل، داده برچسب‌خورده دستی بسازید (`scripts/make_annotation_set.py`)؛ برچسب پروفایل، برچسب درست هر خط نیست.

## ۱. تانل خایمالی چیست و چطور کار می‌کند؟

خایمالی برای شرایطی ساخته شده که سرور داخلی شما (مثلاً سرور ایران‌اکسس) به اینترنت آزاد دسترسی مستقیم ندارد یا روی مسیر مرزی، فیلترینگ DPI و پروب فعال (Active Probing) برقرار است.

```text
[کاربر / کلاینت] ──(SOCKS5 / L4 Forward)──► [ENTRY] ◄──(اتصال معکوس)── [BRIDGE] ──► [EXIT] ──► [اینترنت آزاد]
                                              │                                       ▲
                                              └──── رمزنگاری سرتاسری Noise_IK ────────┘
                                                  (Bridge فقط متن رمزشده می‌بیند)
```

این سیستم **سه نقش** دارد:

* **Exit (سرور خارج):** روی سرور خارج نصب می‌شود، رمزنگاری `Noise_IK` را باز می‌کند، سیاست ضد-SSRF را اعمال می‌کند و ترافیک نامعتبر/پروب‌ها را به یک سایت واقعی (**Decoy**) هدایت می‌کند.
* **Entry (سرور ایران یا کنار کاربر):** پورت‌های **L4 Port Forwarding** (برای VLESS/Trojan/گیم) و یک پروکسی **SOCKS5** محلی (`TCP` + `UDP ASSOCIATE`) ارائه می‌دهد و استخری از لینک‌های رمزشده‌ی آماده نگه می‌دارد.
* **Bridge (اختیاری — خط واسط):** اگر سرور Entry اصلاً به Exit راه ندارد، هر ماشینی که هر دو را ببیند (مثل خط خانگی یا سرور واسط) نقش Bridge را می‌گیرد. چون خودش به هر دو طرف وصل می‌شود، پشت NAT بودن یا نداشتن IP استاتیک برایش مهم نیست و هیچ دسترسی به کلیدها یا داده‌ی کاربران ندارد.

> اگر سرور ایران شما مستقیماً به سرور خارج اتصال TCP دارد، نیازی به Bridge نیست (**حالت Direct**).

---

## ۲. امکانات کلیدی

| بخش | قابلیت‌های پیاده‌سازی‌شده |
|---|---|
| **رمزنگاری سرتاسری** | `Noise_IK` (`X25519 / ChaCha20-Poly1305 / BLAKE2s`) با کلیدهای پین‌شده در هر دو طرف |
| **امنیت مسیر Bridge** | ضد-Replay پس از احراز هویت (`±120s` + کش محدود ۴۰۹۶تایی + بستن بی‌صدا)، `READY v2` با راز ۳۲ بایتی و **Channel Binding** دوجهته (`HKDF-SHA256` + `HMAC-SHA256`) + فلگ ضد-Downgrade (`--require-channel-binding`) |
| **استتار و Fallback ایزوله** | ارسال `ClientHello` شبیه مرورگر با برچسب مخفی؛ هدایت پروب‌ها به Decoy واقعی با سهمیه‌ی جداگانه (`256` کل، `24` هر IP، `38` هر پیشوند IPv6 `/64` و IPv4 `/24`)، بدون تایم‌اوت مصنوعی در حالت عادی و آینه‌سازی کامل Half-Close (`FIN`) |
| **فوروارد پورت لایه ۴ (`--forward`)** | فوروارد تک‌پورت (`443`)، تغییر پورت (`8080=80`)، رنج پورت (`2000-2010` تا سقف ۶۴ پورت)، `UDP`، سهمیه‌ی حجم (`quota` با وضعیت خودکار `quota reached`)، محدودیت سرعت (`rate`) و جدول زنده‌ی کاربران متصل |
| **داشبورد و مدیریت** | داشبورد تعاملی TUI مشکی-قرمز (`khaymali-tui`)، منوی کلاسیک (`khaymali-manager`)، وب‌پنل محلیِ فقط‌خواندنی (`khaymali-web`) و Unix Socket Control API (`0600` + `SO_PEERCRED`) |
| **سلامت مسیر و پایش** | `health.rs` با EWMA RTT/Jitter، CUSUM، Hysteresis زمانی و Circuit Breaker با تفکیک `Timeout` از `Reset` + متریک‌های Prometheus (`/metrics`) + دیده‌بان Decoy |
| **سخت‌سازی و ضد-SSRF** | مسدودسازی کامل رنج‌های خصوصی، `0.0.0.0/8`، CGNAT، IPv4-mapped، NAT64، 6to4، Teredo و جلوگیری اتمیک از DNS Rebinding روی TCP و UDP + محدودکننده‌ی نرخ لاگ خطا |
| **ابزار عیب‌یابی** | `khaymali-doctor` (`serve`/`probe`) برای تست واقعی فریز ۱۶KB، PMTU، UDP و SNI روی IP خود Exit + ابزار آفلاین `khaymali diagnose` |

---


### FEC تطبیقی (v0.11.0)

روی حامل `udp://` و `auto://` می‌توان حالت FEC را با متغیر محیطی `KHAYMALI_FEC` روی هر دو سرور تعیین کرد:
`off` · `light` (۱ به ۸) · `moderate` (۱ به ۴، پیش‌فرض) · `aggressive` (۱ به ۲) · `auto` (انتخاب خودکار بر اساس نرخ Loss).
گیرنده نیازی به تنظیم ندارد. قبل از تغییر از `moderate`، هر دو سرور را به v0.11.0 ارتقا دهید.
جزئیات: `CHANGELOG-v0.11.0.md`.

---

## ۳. پیش‌نیازها

* سیستم‌عامل **Linux** (`amd64` یا `arm64`) مجهز به `systemd` و دسترسی `root`
* `curl` (یا `wget`) و `python3` (برای داشبورد TUI، وب‌پنل محلی و `khaymali-doctor` — بدون نیاز به هیچ پکیج `pip`)
* **هماهنگی ساعت سرورها (NTP):** اختلاف ساعت سرورها باید زیر **±۱۲۰ ثانیه** باشد (`timedatectl status`).
* پورت‌های باز در فایروال: پورت تانل روی Exit (مثلاً `443/tcp`) و در حالت Bridge پورت پذیرش Bridge روی Entry (مثلاً `4444/tcp`) + پورت‌های فورواردشده.

---

## ۴. نصب تک‌خطی

روی هر سرور (خارج، ایران، یا بریج) دستور زیر را با دسترسی `root` اجرا کنید:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/<OWNER>/<REPO>/main/install.sh)
```

### گزینه‌های اختیاری نصاب

```bash
# نصب + بهینه‌سازی اختیاری کرنل (BBR و بافر سوکت با بکاپ خودکار)
bash <(curl -fsSL https://raw.githubusercontent.com/<OWNER>/<REPO>/main/install.sh) --tune

# بازگرداندن تنظیمات کرنل به حالت قبل
bash <(curl -fsSL https://raw.githubusercontent.com/<OWNER>/<REPO>/main/install.sh) --revert-tune

# نصب همراه با بررسی امضای GitHub Build Provenance (نیازمند gh CLI)
bash <(curl -fsSL https://raw.githubusercontent.com/<OWNER>/<REPO>/main/install.sh) --verify-attestation

# ساخت مستقیم از سورس (--locked) یا نصب بدون باز کردن منو
KHAYMALI_BUILD=1 bash <(curl -fsSL https://raw.githubusercontent.com/<OWNER>/<REPO>/main/install.sh)
KHAYMALI_NO_MENU=1 bash <(curl -fsSL https://raw.githubusercontent.com/<OWNER>/<REPO>/main/install.sh)
```

### تأیید دستی اصالت فایل ریلیز

```bash
sha256sum -c khaymali-linux-amd64.tar.gz.sha256
gh attestation verify khaymali-linux-amd64.tar.gz --repo <OWNER>/<REPO>
```

پس از نصب، ابزارهای زیر در `/usr/local/bin/` نصب می‌شوند:
`khaymali` · `khaymali-tui` · `khaymali-manager` · `khaymali-doctor` · `khaymali-web`

---

## ۵. آموزش راه‌اندازی گام‌به‌گام

### روش اول: راه‌اندازی سریع با منو و Join Code (پیشنهادی)

1. **ابتدا روی سرور خارج (Exit):** در `khaymali-tui` یا `khaymali-manager` گزینه‌ی **Setup Kharej (Exit)** را بزنید تا کلیدها، **Join Code** و **Check Code ۱۲ کاراکتری** (`XXXX-XXXX-XXXX`) ساخته شوند.
2. **سپس روی سرور ایران (Entry):** گزینه‌ی **Setup Iran (Entry)** را بزنید و **Join Code** را Paste کنید تا کلید، راز استتار، IP و SNI خودکار تنظیم شود؛ سپس کلید عمومی Entry را در `Add peer` روی سرور خارج ثبت کنید.
3. **تأیید امنیتی خارج از باند:** مقدار `check-code` ۱۲ کاراکتری (یا `sha256` کامل ۶۴ هگز) را در دو سرور مقایسه کنید.
   > ⚠️ `Join Code` شامل راز استتار (`KHAYMALI_CAMO_SECRET`) است؛ مثل رمز عبور از آن نگهداری کنید.

---

### روش دوم: راه‌اندازی دستی (CLI)

#### گام ۱ — ساخت کلیدها و راز استتار
```bash
khaymali keygen   # خروجی: private, public, ui-tag, check-code (12 char), sha256
khaymali secret   # خروجی: راز ۳۲ بایتی استتار
```

#### گام ۲ — حالت Direct (ایران مستقیم به خارج وصل می‌شود)

**سرور خارج (Exit):**
```bash
export KHAYMALI_KEY="<EXIT_PRIVATE_HEX>"
export KHAYMALI_CAMO_SECRET="<SHARED_CAMO_SECRET>"

khaymali exit \
  --listen 0.0.0.0:443 \
  --allow "<ENTRY_PUBLIC_HEX>" \
  --camo-fallback "<DECOY_IP>:443" \
  --metrics 127.0.0.1:9090 \
  --control /run/khaymali/exit.sock
```

**سرور ایران (Entry):**
```bash
export KHAYMALI_KEY="<ENTRY_PRIVATE_HEX>"
export KHAYMALI_CAMO_SECRET="<SHARED_CAMO_SECRET>"

khaymali entry \
  --exit-pub "<EXIT_PUBLIC_HEX>" \
  --exit "<EXIT_IP>:443" \
  --camo-sni "<DECOY_HOSTNAME>" \
  --socks 127.0.0.1:1080 \
  --pool 8 \
  --metrics 127.0.0.1:9090 \
  --control /run/khaymali/entry.sock
```

#### گام ۳ — حالت Bridge (برای سرورهای ایران‌اکسس)

1. **سرور خارج (Exit):** مشابه حالت Direct بالا.
2. **سرور ایران (Entry):**
   ```bash
   export KHAYMALI_KEY="<ENTRY_PRIVATE_HEX>"

   khaymali entry \
     --exit-pub "<EXIT_PUBLIC_HEX>" \
     --bridge-listen 0.0.0.0:4444 \
     --allow-bridge "<BRIDGE_PUBLIC_HEX>" \
     --require-channel-binding \
     --socks 127.0.0.1:1080 \
     --control /run/khaymali/entry.sock
   ```
3. **ماشین واسط (Bridge):**
   ```bash
   export KHAYMALI_KEY="<BRIDGE_PRIVATE_HEX>"
   export KHAYMALI_CAMO_SECRET="<SHARED_CAMO_SECRET>"

   khaymali bridge \
     --entry "<ENTRY_IP>:4444" \
     --entry-pub "<ENTRY_PUBLIC_HEX>" \
     --exit "<EXIT_IP>:443" \
     --camo-sni "<DECOY_HOSTNAME>" \
     --pool 8 \
     --control /run/khaymali/bridge.sock
   ```

> برای Failover خودکار بین چند Exit، فلگ `--exit` را تکرار کنید. سایت Decoy را ترجیحاً با TLS 1.3 روی همان هاستینگ/ASN سرور Exit انتخاب کنید.

---

## ۶. فوروارد پورت لایه ۴ (`--forward`)

```bash
khaymali entry \
  --exit-pub "<EXIT_PUBLIC_HEX>" \
  --exit "<EXIT_IP>:443" \
  --camo-sni "<DECOY_HOSTNAME>" \
  --control /run/khaymali/entry.sock \
  --forward "443@name=VLESS,target=127.0.0.1:443,quota=1T,rate=100M,failover=helsinki" \
  --forward "8080=80@name=Mirror,target=127.0.0.1:80,quota=50G" \
  --forward "2053/udp@name=Games,target=127.0.0.1:2053" \
  --forward "2000-2010@name=Pool,target=127.0.0.1"
```

* پشتیبانی از تک‌پورت (`443`)، تغییر پورت (`8080=80`)، UDP (`2053/udp`) و رنج پورت (`2000-2010` تا سقف ۶۴ پورت).
* گزینه‌ها پس از `@`: `name`، `target`، `bind`، `quota` (`K/M/G/T`)، `rate` (بیت بر ثانیه، مثلاً `100M`)، `failover`.

---

## ۷. استفاده توسط کاربر نهایی

1. **حالت فوروارد پورت (VLESS / Trojan / گیم):** کاربر در کلاینت خود (v2rayNG، Sing-box، Streisand و...) آدرس سرور را برابر **IP سرور ایران** و پورت فورواردشده قرار می‌دهد.
2. **حالت SOCKS5 محلی:** تنظیم پروکسی روی `127.0.0.1:1080` و تست با:
   ```bash
   curl --socks5-hostname 127.0.0.1:1080 https://example.com
   ```

---

## ۸. داشبورد TUI، وب‌پنل محلی و Control API

```bash
khaymali-tui                                   # داشبورد زنده مشکی-قرمز
khaymali-tui --demo                            # پیش‌نمایش تعاملی
khaymali-web --listen 127.0.0.1:8088           # وب‌پنل محلی با توکن Bearer
echo '{"method":"status"}' | socat - UNIX-CONNECT:/run/khaymali/entry.sock
echo '{"method":"forwards.list"}' | socat - UNIX-CONNECT:/run/khaymali/entry.sock
echo '{"method":"drain"}' | socat - UNIX-CONNECT:/run/khaymali/entry.sock
curl -s http://127.0.0.1:9090/metrics
```

---

## ۹. تست مسیر و عیب‌یابی (`khaymali-doctor`)

برای اندازه‌گیری واقعی بدون متوقف کردن Exit اصلی، روی یک پورت آزمایشی محدودشده به IP سرور ایران اجرا کنید:

```bash
# روی سرور خارج:
khaymali-doctor serve --listen 0.0.0.0:8443

# روی سرور ایران:
khaymali-doctor probe \
  --exit <EXIT_IP>:8443 \
  --snis www.cloudflare.com,www.microsoft.com,dl.google.com \
  --json > baseline-iran.json
```

برای تحلیل سریع پیام خطا:
```bash
khaymali diagnose "read timeout stalled at 16384 bytes"
```

---

## ۱۰. ساخت از سورس و تست‌ها

پروژه با `rustc 1.75+` ساخته می‌شود. این آرشیو `Cargo.lock` تولیدشده ندارد؛ برای ساخت محلی ابتدا وابستگی‌ها را resolve و lockfile را بازبینی کنید. برای انتشار عمومی، `Cargo.lock` باید commit شود:

```bash
cargo generate-lockfile
cargo build --release --locked
cargo test --release --locked --lib -- --nocapture
cargo test --release --locked --test neg_security -- --nocapture
bash tests/integration.sh target/release/khaymali
sudo bash tests/netem.sh target/release/khaymali
# تست استرس خودکار (تونل لوکال بالا می‌آید): پله‌های ۱۰/۲۵/۵۰/۱۰۰/۲۰۰/۳۰۰ کلاینت هم‌زمان
# تست آشوب سیستم تطبیقی (قطع/وصل Exit با باینری واقعی)
bash tests/chaos.sh target/release/khaymali
bash tests/stress.sh target/release/khaymali 300
# همان تست زیر شرایط بد شبکه (loss، jitter، reorder) و فقط پله‌های سنگین
sudo NETEM=1 KHAYMALI_STEPS="200 300" bash tests/stress.sh target/release/khaymali
sudo STRESS=1 bash tests/netem.sh target/release/khaymali
bash scripts/stress_live_300.sh 127.0.0.1:1080 http://127.0.0.1:8000/index.html 300 --json > baseline.json
python3 scripts/check_baseline_regression.py baseline.json candidate.json
```

---

## ۱۱. محدودیت‌های شناخته‌شده (صادقانه)

* استتار فعلی تقلید TLS است، نه Reality/ShadowTLS کامل؛ اثرانگشت JA3/JA4 به‌صورت رسمی با مرورگر واقعی تأیید نشده است.
* ماسک XOR طول فریم در Channel Binding سخت‌سازی ظاهری پارسر است و اندازه‌ی سگمنت‌های TCP را مخفی نمی‌کند.
* مالتی‌پلکسینگ و Session Resume هنوز پیاده نشده‌اند و UDP روی لینک TCP حمل می‌شود.
* ممیزی امنیتی مستقل انجام نشده است؛ برای موارد حیاتی به آن تکیه نکنید.

---

# 🇬🇧 English Guide

**Khaymali Tunnel** is an open-source (MIT) tunnel written in Rust (`rustc 1.75+`). This source archive does not include a generated `Cargo.lock`; generate and review one before using `--locked`, and commit it for reproducible public releases.

```text
user app ──(SOCKS5 / L4 Forward)──► ENTRY ◄──(reverse dial)── BRIDGE ──(dial out)──► EXIT ──► internet
                                      │                                               ▲
                                      └──────── end-to-end Noise_IK encryption ───────┘
                                                (Bridge only ever sees ciphertext)
```

### One-Line Install
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/<OWNER>/<REPO>/main/install.sh)
```

### Build & Verify from Source
```bash
cargo build --release --locked
cargo test --release --locked --lib -- --nocapture
cargo test --release --locked --test neg_security -- --nocapture
bash tests/integration.sh target/release/khaymali
```

### Documentation & License
* Specification & Negative Test Matrix: [`docs/SPEC.md`](docs/SPEC.md)
* Threat Model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
* Wire Protocol: [`docs/PROTOCOL.md`](docs/PROTOCOL.md)
* Ecosystem Study Matrix: [`docs/ECOSYSTEM_MATRIX.md`](docs/ECOSYSTEM_MATRIX.md)
* Release Guide: [`docs/RELEASE_GUIDE.md`](docs/RELEASE_GUIDE.md)
* License: **MIT** ([`LICENSE`](LICENSE))


## Adaptive recovery (v0.5.0 engineering update)

The recovery policy classifies handshake timeouts, early resets, mid-stream stalls, PMTU failures, intermittent loss and queueing. It uses a two-observation hysteresis and emits bounded recommendations. It is currently advisory; it does not dynamically rewrite frame sizes or silently change security settings. Health selection is based on real transport outcomes, not bare TCP connect/close probes. See `CHANGELOG-v0.5.0-offline.md`.


### NLP Safety Envelope (v0.15.1)

`KHAYMALI_NLP_MODE` defaults to `shadow` (report only). In `active` mode NLP may only change chunk size and pacing, at most 6 times per minute with one change under evaluation at a time. Each change stores a pre-action baseline. If success drops by 10 points or goodput by 25 %, the change is reverted automatically and that action kind is locked for 10 minutes. Every change logs one rate-limited `[nlp]` line with the evidence words. Run `RUN_AB=1 bash scripts/verify_build_and_tests.sh` (3 repetitions per profile) and keep `active` only if `scripts/ab_compare.py` does not report the `clean` profile as worse.

### NLP Runtime Safety (v0.11.5)

TinyNetNlp runs in `shadow` mode by default. Set `KHAYMALI_NLP_MODE=active` only after validating the local replay and loopback tests; use `off` to disable NLP inference. Online learning is disabled unless `KHAYMALI_NLP_ONLINE_LEARNING=1` is explicitly set. See `docs/NLP_RELIABILITY_0.11.5.md` and `RELEASE_AUDIT_FA.md` for action semantics, replay schema, and validation limits.


### Adaptive Network Intelligence (v0.14.0)

The intelligence layer now includes bounded trend projection plus optional labeled Platt calibration,
a deterministic packet/queue digital twin, per-path runtime telemetry for Bridge exits, evidence-aware
path ranking, paired offline experiment comparison, explicit resource budgets, and versioned TinyNetNlp
model artifacts with validation and atomic persistence. Runtime goodput is estimated from completed
stream events; packet loss/retransmission are never fabricated when unavailable. The controller remains
advisory and does not perform route switching or survival fallback. The twin sends no packets. See
[`docs/INTELLIGENCE_0.14.0.md`](docs/INTELLIGENCE_0.14.0.md) and
[`RELEASE_AUDIT_v0.14.0_FA.md`](RELEASE_AUDIT_v0.14.0_FA.md) for API, limits, calibration workflow, and validation steps.
Run `khaymali intelligence-lab --scenario all` for offline twin scenarios; fit a horizon-specific
risk calibrator with `khaymali calibrate-risk TRAIN.tsv HOLDOUT.tsv OUTPUT.model`.

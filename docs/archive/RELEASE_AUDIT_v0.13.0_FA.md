# گزارش تغییرات Khaymali v0.13.0

## قابلیت‌های اضافه‌شده

- Predictive degradation score با روند محدود و افق پیش‌بینی کوتاه؛ خروجی احتمال کالیبره‌شده نیست.
- Adaptive Controller با وضعیت‌های Normal/Watch/Degraded/Critical، تأیید چند مشاهده‌ای و Cooldown.
- Digital Twin قطعی و آفلاین برای شش سناریوی مصنوعی؛ بدون ارسال بسته یا تغییر شبکه میزبان.
- پروفایل مستقل هر Path با EWMA و رتبه‌بندی نسبی؛ ظرفیت رجیستری محدود است.
- Explainable Decision با Evidence Tags و فلگ ثابت `executed=false`.
- `NlpModelRollout` برای آموزش Candidate جدا از مدل فعال، ارزیابی روی Holdout برچسب‌دار، ارتقا و Rollback در حافظه.
- Resource Budget و Experiment Manager با سقف حافظه/تعداد آزمایش.
- اتصال مشاهده‌ای به `AdaptiveRuntime` و خروجی متریک‌های Prometheus.
- اصلاح مسیر نصب سورس برای نبود Cargo.lock و نبود ابزارهای جانبی اختیاری در آرشیو.

## مرزهای عملکردی

- Predictive/Controller به‌تنهایی هیچ Route Switch، Handover یا Survival Fallback اجرا نمی‌کنند.
- Digital Twin شبیه‌ساز بسته‌محور یا مدل دقیق ISP/Kernel نیست.
- Runtime فعلی Goodput و Jitter را در تمام مسیرها اندازه‌گیری نمی‌کند؛ مقدار اندازه‌گیری‌نشده صفر باقی می‌ماند.
- Candidate rollout فقط مدل را در حافظه نگه می‌دارد؛ ذخیره‌سازی پایدار و hot-swap به‌صورت خودکار انجام نمی‌شود.
- پروفایل Runtime فعلی با شناسه `runtime-default` تغذیه می‌شود؛ اتصال داده مستقل هر Exit نیازمند فراخوانی API با شناسه مسیر جداگانه است.

## بررسی‌های انجام‌شده در محیط آماده‌سازی

- Bash syntax: PASS
- Python syntax: PASS
- Cargo.toml parse/version check: PASS
- بررسی توازن delimiter در ماژول‌های جدید و فایل recovery: PASS
- Rust compile / Cargo tests / release build: اجرا نشده؛ Rust و Cargo در محیط آماده‌سازی موجود نبودند.
- Cargo.lock: در این آرشیو تولید نشده است. پیش از انتشار قابل بازتولید، `cargo generate-lockfile` اجرا و خروجی بازبینی و commit شود.

## دستورهای تأیید روی سیستم دارای Rust 1.75+

```bash
cargo generate-lockfile
cargo test --lib intelligence:: -- --nocapture
cargo test --lib
cargo test --test neg_security
cargo build --release
bash scripts/verify_build_and_tests.sh
```

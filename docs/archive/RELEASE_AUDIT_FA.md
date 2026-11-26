# گزارش اصلاحات Khaymali v0.11.5

## اصلاحات انجام‌شده

1. **Rollback کامل NLP**
   - واژگان پایه از واژگان اضافه‌شده در یادگیری آنلاین جدا و هنگام Reset بازیابی می‌شود.
   - Reset وزن‌های Delta، شمارنده یادگیری، پنجره رخدادهای زمانی و برچسب بازخورد معلق را پاک می‌کند.
   - وضعیت آخرین پیش‌بینی و آمار آخرین کلاس نیز در AdaptiveRuntime به حالت خنثی برمی‌گردد.

2. **معنای دقیق اقدام‌ها**
   - `PreemptiveHandover` به `ReduceChunkSize` تغییر نام داده شد؛ این اقدام واقعاً اندازه Chunk را به مقدار محدودشده کاهش می‌دهد و ادعای handover ندارد.
   - تغییر مسیر و ورود به Survival با نام `RecommendExitOrBridge` و `RecommendSurvivalFallback` مشخص شده‌اند؛ این‌ها پیشنهاد هستند و کنترل‌کننده‌های Transport/Fallback مالک اجرای واقعی‌اند.
   - شمارنده اقدام‌های اجراشده از شمارنده پیشنهادها جدا شد.

3. **حالت Shadow پیش‌فرض**
   - NLP به‌صورت پیش‌فرض فقط پیش‌بینی می‌کند.
   - اعمال تنظیمات فقط با `KHAYMALI_NLP_MODE=active` فعال می‌شود.
   - `KHAYMALI_NLP_MODE=off` پردازش NLP را خاموش می‌کند.

4. **اتصال Temporal Detection به Runtime**
   - رخدادهای واقعی `TransportEvent` به توکن‌های ثابت و محدود تبدیل و قبل از طبقه‌بندی وارد پنجره زمانی NLP می‌شوند.
   - اندازه پنجره همچنان محدود است و ورودی دلخواه به آن تزریق نمی‌شود.

5. **یادگیری آنلاین محافظه‌کارانه‌تر**
   - یادگیری آنلاین به‌صورت پیش‌فرض خاموش است.
   - فعال‌سازی آن نیازمند `KHAYMALI_NLP_ONLINE_LEARNING=1` است.
   - علاوه بر این، Runtime باید سیگنال زنده و سالم و streak پایدار مشاهده کند.
   - این شرط‌ها تضمین‌کننده رابطه علت و معلولی نیستند؛ برای استفاده عملی باید baseline قبل از اقدام و پنجره مقایسه بعد از اقدام نیز ثبت شود.

6. **Replay ترکیبی متن و Metrics**
   - دستور `diagnose --stdin-combined` اضافه شد.
   - `eval_nlp_replay.py` فیلد اختیاری `metrics` را اعتبارسنجی می‌کند و آن را به `classify_combined` می‌دهد.
   - تعداد خروجی‌ها، کلاس‌های هدف، نوع داده‌ها و مقادیر Metrics بررسی می‌شوند.
   - لاگ‌های خام harsh بدون برچسب کاذب ذخیره می‌شوند؛ ارزیابی دقت فقط برای رکوردهایی انجام می‌شود که `expected` آن‌ها مستقل و معتبر برچسب‌گذاری شده باشد.
   - آمار Prometheus دیگر به‌اشتباه به‌عنوان LinkMetrics معرفی نمی‌شود.

7. **ثبت LinkMetrics واقعی**
   - آخرین snapshot عددی که Runtime به NLP می‌دهد، به‌صورت شمارنده‌های اتمیک در metrics endpoint منتشر می‌شود.
   - تست harsh این مقادیر را به ساختار `metrics` در JSONL تبدیل می‌کند و بقیه شمارنده‌های Runtime را جداگانه در `runtime_metrics` نگه می‌دارد.

8. **Build و اسکریپت‌های بررسی**
   - نسخه Cargo به `0.11.5` تغییر کرد.
   - اسکریپت Verify دیگر به فایل Manager غایب وابسته نیست.
   - خطاهای Integration به‌جز مورد شناخته‌شده plain-HTTP probe پنهان نمی‌شوند.
   - تست live stress فقط endpointهای loopback را قبول می‌کند و سقف concurrency آن 300 است.

## وضعیت اعتبارسنجی این بسته

- بررسی Syntax اسکریپت‌های Python: انجام شد.
- بررسی Syntax اسکریپت‌های Shell: انجام شد.
- اجرای آزمایشی Replay Evaluator با binary ساختگی و دیتاست نمونه: انجام شد.
- بررسی Guard جلوگیری از مقصد غیر-loopback در live stress: انجام شد.
- **Rust build و cargo test اجرا نشده‌اند**؛ محیط بسته‌بندی فاقد `rustc` و `cargo` است.
- **Cargo.lock در بسته تولید نشده**؛ ساخت lockfile معتبر نیازمند Cargo و حل وابستگی‌هاست. فایل ساختگی به‌جای lockfile معتبر اضافه نشده است.
- تست 200/250/300 کلاینت روی تونل واقعی اجرا نشده است؛ اسکریپت‌ها و محیط loopback آماده‌اند، اما نتیجه Stress واقعی ادعا نمی‌شود.

## فرمان‌های بررسی روی میزبان دارای Rust 1.75

```bash
cargo generate-lockfile
cargo test --lib
cargo test --test neg_security
cargo build --release
bash scripts/verify_build_and_tests.sh
```

برای ارزیابی Replay:

```bash
python3 scripts/eval_nlp_replay.py target/release/khaymali /path/to/replay_dataset.jsonl
```

برای اجرای تست harsh فقط روی سرویس‌های loopback خودتان:

```bash
KHAYMALI_NLP_MODE=shadow bash tests/stress_harsh.sh target/release/khaymali
```

ابتدا Shadow را بررسی کنید. فعال‌کردن تغییرات Runtime نیازمند ارزیابی مستقل و تنظیم صریح `KHAYMALI_NLP_MODE=active` است.

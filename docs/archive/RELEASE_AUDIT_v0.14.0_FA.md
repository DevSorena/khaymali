# گزارش ممیزی Khaymali v0.14.0

## تغییرات تکمیل‌شده در سورس

1. **پیش‌بینی و کالیبراسیون**
   - روند شدت اختلال همچنان یک heuristic است.
   - Platt scaling با حداقل ۳۰ نمونه برچسب‌خورده و حداقل ۵ نمونه از هر کلاس اضافه شد.
   - تا قبل از fit موفق، احتمال پیش‌بینی‌شده `None` است؛ بنابراین امتیاز heuristic به‌عنوان احتمال معرفی نمی‌شود.
   - Brier Score، Log Loss و ECE روی Holdout مستقل محاسبه می‌شوند.
   - دستور `khaymali calibrate-risk TRAIN.tsv HOLDOUT.tsv OUTPUT.model` فرایند آموزش و ارزیابی را در اختیار اپراتور می‌گذارد.

2. **Digital Twin**
   - شبیه‌ساز صف/لینک با ظرفیت لینک، اندازه بسته، ظرفیت صف، تأخیر پایه، loss تصادفی seeded، jitter و outage اضافه شد.
   - خروجی شامل packet delivered/dropped، میانگین و P95 تأخیر، حداکثر صف، goodput و severity است.
   - شبیه‌ساز آفلاین است و بسته واقعی ارسال نمی‌کند.

3. **Per-Path Intelligence**
   - رتبه‌بندی مسیر اکنون goodput، jitter، loss و تعداد شواهد را لحاظ می‌کند.
   - Runtime برای رخدادهای Bridge شناسه Exit را به‌عنوان path ID می‌دهد.
   - پنجره و EWMA هر مسیر مستقل است؛ رجیستری ۶۴ مسیر دارد و LRU eviction انجام می‌شود.

4. **Telemetry واقعی و محدودیت داده**
   - RTT و baseline از رخدادهای ConnectOk ثبت می‌شوند.
   - Jitter از تغییرات متوالی RTT نمونه‌برداری‌شده تخمین زده می‌شود.
   - Goodput از bytes در رخداد StreamOk و فاصله زمانی بین تکمیل Streamها تخمین زده می‌شود.
   - Packet loss و retransmit در همه مسیرها قابل مشاهده نیستند؛ در نبود شمارنده واقعی صفر باقی می‌مانند.

5. **Safe Learning و Persistence**
   - فرمت باینری نسخه‌دار برای مدل پایه و Delta اضافه شد.
   - loader اندازه، ابعاد، وزن‌ها، شمارنده‌ها، مرتب‌بودن vocabulary و قفل‌بودن کلاس Unrelated را بررسی می‌کند.
   - ذخیره‌سازی atomic و با mode `0600` در Unix انجام می‌شود.
   - یادگیری پس از تأیید سلامت ابتدا در مدل Candidate جداگانه انجام می‌شود؛ مدل فعال تا عبور از Holdout تغییر نمی‌کند.
   - `KHAYMALI_NLP_MODEL_PATH` برای load مدل فعال و `KHAYMALI_NLP_CANDIDATE_PATH` برای ذخیره Candidate استفاده می‌شود.
   - دستور `khaymali promote-nlp-candidate HOLDOUT.tsv` فقط در صورت بهبود accuracy و عدم افزایش نامجاز false positive مدل را ارتقا می‌دهد.
   - نسخه قبلی قبل از ارتقا backup می‌شود و `kani.rollback` امکان بازگشت را فراهم می‌کند.
   - اگر persistence پس از آموزش شکست بخورد، مدل در حافظه به snapshot قبل از آموزش برمی‌گردد.
   - Reset نیز تلاش می‌کند baseline را در artifact ذخیره کند.
   - با `kani.reload` مدل در Runtime فعلی بدون restart بارگذاری مجدد می‌شود؛ بارگذاری از مسیر تنظیم‌شده در `KHAYMALI_NLP_MODEL_PATH` انجام می‌شود.

6. **Experiment Manager و Resource Budget**
   - scheduler با انتخاب سناریوهای آزمایش‌نشده و سپس UCB ساده اضافه شد.
   - مقایسه baseline/candidate با seed مشترک انجام می‌شود.
   - سقف شمارش و تخمین حافظه برای observation و experiment اعمال می‌شود.
   - دستور `khaymali intelligence-lab` سناریوهای آفلاین را اجرا می‌کند و هیچ بسته‌ای روی شبکه ارسال نمی‌کند.

## تست‌های اضافه‌شده
- Platt calibration monotonicity و عدم صدور probability بدون fit.
- Packet twin determinism و bounded queue.
- انتخاب سناریوی آزمایش‌نشده.
- مقایسه دو تنظیم با seed مشترک.
- محدودیت سخت بودجه منابع.
- جداسازی داده‌های دو path.
- round-trip و رد artifact خراب.

## وضعیت اعتبارسنجی
- بررسی ZIP و اسکریپت‌های Python/Shell در محیط آماده‌سازی قابل انجام است.
- Rust/Cargo در محیط آماده‌سازی نصب نیست؛ بنابراین `cargo test`, `cargo build --release` و تست فشار واقعی اجرا نشده‌اند.
- این نسخه تا اجرای کامل تست‌ها روی میزبان دارای Rust 1.75+، Release عملیاتی تأییدشده محسوب نمی‌شود.

## مرزهای عملیاتی
- پیش‌بینی احتمال فقط بعد از آموزش calibrator با داده واقعی و برچسب‌خورده معتبر است.
- Digital Twin جایگزین تست netem یا محیط واقعی نیست.
- Goodput اندازه‌گیری‌شده در این نسخه نمونه‌برداری رخدادمحور است، نه نرخ پیوسته NIC.
- مدل NLP در restart از artifact بارگذاری می‌شود؛ hot-swap در workerهای فعال هنوز انجام نمی‌شود.
- Experiment Manager فقط سناریوهای آفلاین تعریف‌شده را مقایسه می‌کند و به شبکه راه دور دست نمی‌زند.

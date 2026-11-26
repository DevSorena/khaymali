# سیستم تطبیقی خیمالی (Adaptive Engine)

> ارتباط با `src/recovery.rs`: `recovery.rs` کنترل‌های **data-plane** را انجام می‌دهد (اندازه‌ی chunk، pacing،
> سقف همروندی). `adapt.rs` لایه‌ی **control-plane** است (timeout، اندازه‌ی استخر، hedge، blackout، الگوها،
> گلوگاه). هر دو از همان نقاط (dial/acquire/pipe) تغذیه می‌شوند و تداخلی در پارامترها ندارند.

ماژول `src/adapt.rs`؛ سه بخش که روی یک پنجره‌ی مشترک از رویدادهای واقعی (dial، acquire، مرگ لینک) کار می‌کنند.
فقط پارامترهای عملکردی را تغییر می‌دهد، هرگز کلید، احراز هویت، allowlist یا سیاست SSRF را. با `--no-adapt` رفتار قبلی و ثابت برمی‌گردد.

## ۱. تصمیم‌گیری در شرایط سخت

| وضعیت | شرط تشخیص | تنظیمات |
|---|---|---|
| normal | عادی | pool=`--pool`، timeout ۱۰ ثانیه |
| degraded | ≥۱۵٪ شکست dial، RTT ≥۲٫۵× پایه، یا مرگ لینک | timeout ۱۵ ثانیه، max-age ≤۹۰ ثانیه |
| hostile | ≥۵۰٪ شکست یا الگوی RST/stall | timeout ۶ ثانیه، **dial دوتایی (hedge)** روی دو Exit، pool×۱٫۵، max-age ≤۴۵ ثانیه |
| blackout | ۳ شکست پشت‌سرهم و صفر موفقیت در ۸ ثانیه اخیر | pool=۲ (فقط probe)، کلاینت‌ها در ≤۸ ثانیه خطا می‌گیرند (نه ۲۰ ثانیه انتظار) |
| recovering | اولین موفقیت بعد از blackout | slow-start: pool=۲، ۴، ۸… تا هدف (بدون هجوم ناگهانی) |

تشدید فوری است، کاهش فقط بعد از ۳ تیک آرام (بدون flapping).

## ۲. ریکاوری و شناسایی الگو

اثر انگشت شکست هر dial: `connect_timeout` (بلک‌هول/قطع کامل)، `handshake_stall` (فریز بعد از اتصال)،
`early_reset` (RST)، `handshake_close`، `refused`، `unreachable`. شکست غالب سبک ریکاوری را تعیین می‌کند
(مثلاً stall ⇒ صبر handshake فقط ۵ ثانیه و hedge؛ refused ⇒ فشار نیاوردن با backoff ≥۲ ثانیه).

الگوهایی که یاد می‌گیرد (و ذخیره می‌کند، پس بعد از restart هم هست):
- **kill-age**: اگر لینک‌ها در سنِ تقریباً ثابتی می‌میرند (مثلاً ~۱۰۰ ثانیه)، لینک‌ها در ۷۵٪ آن سن چرخانده می‌شوند.
  (محدودیت: جریانِ در حال انتقال را نمی‌شود منتقل کرد؛ این الگو برای کوتاه‌جریان‌ها و استخر تازه کمک می‌کند.)
- **outage دوره‌ای**: طول و دوره‌ی قطع‌ها؛ نزدیک پایان پیش‌بینی‌شده probe هر ~۱ ثانیه می‌شود تا برگشت سریع‌تر دیده شود.
- فقط خوشه‌ی فشرده (MAD ≤ ۲۰–۳۵٪) الگو حساب می‌شود؛ مرگ‌های تصادفی الگو نیستند.
- فایل: `/var/lib/khaymali/<role>-adapt.state` (یا `--adapt-state FILE|off`). قدیمی‌تر از ۷ روز نادیده گرفته می‌شود.

## ۳. گلوگاه‌ها

| گلوگاه | تشخیص | اقدام |
|---|---|---|
| `pool_starved` | کلاینت‌ها برای لینک منتظر می‌مانند (≥۳۰۰ms یا timeout) | رشد AIMD تعداد dialerها تا `--pool-max` (پیش‌فرض ۶۴–۱۲۸)، کاهش آهسته بعد از آرام شدن |
| `exit_slow` | RTT handshake ≥۳× پایه | رشد متوقف می‌شود (فشار روی Exit کند نمی‌آورد) |
| `stale_pool` | لینک‌های موجود در استخر مرده‌اند (idle-kill/NAT) | max-age ≤۳۰ ثانیه |
| `socks_saturated` | اتصالات SOCKS ≥۸۵٪ سقف | هشدار و متریک (سقف ثابت است) |

## مشاهده

- متریک‌ها: `khaymali_adapt_condition` (0 normal، 1 degraded، 2 hostile، 3 blackout، 4 recovering)،
  `adapt_pool_target`، `adapt_bottleneck_mask` (1/2/4/8)، `adapt_pattern_*`، `adapt_recoveries_total`،
  `adapt_blackout_seconds_total`، `adapt_hedged_dials_total`.
- Control socket: `{"method":"adapt.status"}`.
- لاگ: خطوط `[adapt] ...` برای هر تغییر وضعیت، الگو و گلوگاه.
- Bridge: موتور تصمیم و backoff الگومحور فعال است؛ تغییر اندازه‌ی استخر ندارد (هر worker یک رله‌ی بلندمدت است).

## تست

```bash
cargo generate-lockfile                         # فقط اگر Cargo.lock هنوز ایجاد نشده است
cargo test --release --locked --lib adapt     # ۲۰ تست واحد قطعی (زمان تزریقی)
bash tests/chaos.sh target/release/khaymali   # قطع/وصل Exit با باینری واقعی
bash tests/stress.sh target/release/khaymali 300
```

## نکات یکپارچه‌سازی با LinkPool / mux

- `acquire` اکنون یک ددلاین کلی برای کل باز کردن اتصال دارد (مسیر mux + fallback تک‌لینک)؛ در blackout ≤۸ ثانیه.
- در blackout از burst-dial به‌ازای هر کلاینت صرف‌نظر می‌شود (فقط dialerهای کوچک probe می‌کنند).
- circuit breaker هر Exit در blackout حداکثر ۴ ثانیه باز می‌ماند (قبلاً تا ۶۴ ثانیه)، تا برگشت مسیر دیرتر دیده نشود.
- حالت «همه‌ی Exitها circuit-open» به‌عنوان شکستِ `circuit_open` ثبت می‌شود و blackout را زنده نگه می‌دارد.
- رشد استخر فقط وقتی انجام می‌شود که کلاینت‌ها واقعاً منتظر لینک مانده‌اند (≥۳۰۰ms)، نه با هر شکست acquire.
- استریم‌های mux فقط «پایان تمیز» گزارش می‌کنند؛ مرگ سخت و سن لینک فقط برای لینک‌های تک‌استریم ثبت می‌شود.

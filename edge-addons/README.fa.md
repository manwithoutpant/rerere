# افزودن محدود TUIC و XHTTP

این بسته برای افزودن دو پروتکل روی ورودی‌های جدا طراحی شده است. نسخهٔ حاضر **پایلوت** است.

**وضعیت اعتبارسنجی:** محیط اجرای محلی در زمان ساخت در دسترس نبود. تلاش‌های GitHub Actions قبل از تخصیص runner و اجرای مراحل خاتمه یافتند؛ نتیجهٔ موفق CI نداریم. علت دقیق توقف از دادهٔ قابل‌دسترسی مشخص نشده است. سازگاری باینری‌ها و اجرای systemd از پیش تأییدشده نیست. نصاب شرط دارد: پیش از ساخت سرویس، آزمایش بومی داده روی خود میزبان باید موفق شود؛ پیش از فعال‌سازی دائمی نیز دو کلاینت بومی باید واقعاً داده دریافت کنند. این کنترل‌ها جای آزمون اینترنت کاربر را نمی‌گیرند.

## محدودهٔ این مرحله

| ورودی | IP | پورت | خروج |
|---|---|---|---|
| XHTTP مستقیم خارج | 89.117.67.71 | 25443/TCP | خروج مستقیم همان سرور |
| TUIC مستقیم خارج | 89.117.67.71 | 25443/UDP | خروج مستقیم همان سرور |
| XHTTP ایران | 5.160.131.169 | 25443/TCP | XHTTP با TLS/H2 به IPv6 خارج |
| TUIC ایران | 5.160.131.169 | 25443/UDP | SOCKS محلی، سپس XHTTP با TLS/H2 به خارج |

روی IPv6 مشخص‌شدهٔ هر میزبان نیز ورودی جدید شنود می‌کند. مسیر ایران به خارج به `[2a09:e683:6:13::a]:25443` با SNI دامنهٔ جدید خارج متصل می‌شود.

TUIC در مسیر کاربر تا ایران QUIC است؛ مسیر بین دو سرور TCP/H2 است. در نتیجه UDP آن مسیر هم ممکن است از تأخیر ناشی از گم‌شدن بسته‌های TCP تأثیر بگیرد. TUIC مستقیم خارج این لایهٔ TCP میانی را ندارد. صفحهٔ وب به‌تنهایی ترافیک را غیرقابل‌شناسایی نمی‌کند.

پورت‌های فعلی، گروه‌های `foreign1`، `germany2-v6`، `newserver-v6`، فایل‌ها و هسته‌های قبلی، SSH، DNS سیستم، sysctl و فایروال خارج از مالکیت نصاب‌اند. انتقال ورودی 443، load balancing و تغییر IP خروجی به مرحلهٔ بعد موکول شده است. استفاده از IP دوم برای ورودی الزاماً IP خروجی را به همان IP تبدیل نمی‌کند.

## پیش‌نیازها

- Linux x86_64، Python 3.11 یا جدیدتر، systemd، curl، openssl و iproute2.
- دست‌کم 384MiB RAM آزاد برای آزمایش کوتاه بومی؛ این آزمون اشباع پهنای باند نیست.
- IPهای مشخص‌شده باید واقعاً روی میزبان مربوطه تخصیص یافته باشند؛ در غیر این صورت نصب متوقف می‌شود.
- برای گواهی خودکار: DNS دامنه در Cloudflare و API token با `Zone / DNS / Edit` و `Zone / Zone / Read` فقط برای همان zone. ایمیل ACME و توکن هنگام اجرا پرسیده می‌شود. توکن در آرگومان فرمان یا لینک خروجی قرار نمی‌گیرد.
- در صورت داشتن گواهی معتبر عمومی، گزینه‌های `--cert /path/fullchain.pem --key /path/privkey.pem` قابل استفاده‌اند. تمدید آن حالت برعهدهٔ ارائه‌کنندهٔ گواهی است؛ گواهی جدید با فرمان renew وارد می‌شود.

دو رکورد **جدید** زیر را با DNS only/ابر خاکستری بسازید. رکوردهای قدیمی را جابه‌جا نکنید. این نام‌های پیشنهادی نیاز به مالکیت شما بر devwork12.ir دارند.

| نوع | نام | مقدار |
|---|---|---|
| A | edge-us.devwork12.ir | 89.117.67.71 |
| A | edge-ir.devwork12.ir | 5.160.131.169 |

فعلاً AAAA جدید نسازید. اتصال IPv6 بین دو سرور به AAAA وابسته نیست. Aها از خارج با `getent ahostsv4 edge-us.devwork12.ir` و `getent ahostsv4 edge-ir.devwork12.ir` قابل بررسی‌اند.

در پنل ارائه‌دهنده، TCP/25443 و UDP/25443 را روی IP دوم هر میزبان باز کنید. TCP/25443 روی IPv6 خارج هم باید از ایران قابل دسترس باشد. نصاب فایروال میزبان را تغییر نمی‌دهد. اگر UFW فعال است، فقط قواعد این ورودی‌ها را اضافه کنید؛ reset/disable لازم نیست. نمونهٔ خارج:

```bash
sudo ufw allow in proto tcp to 89.117.67.71 port 25443 comment edge-addons
sudo ufw allow in proto udp to 89.117.67.71 port 25443 comment edge-addons
sudo ufw allow in proto tcp to 2a09:e683:6:13::a port 25443 comment edge-addons
sudo ufw allow in proto udp to 2a09:e683:6:13::a port 25443 comment edge-addons
```

برای ایران در همین دستورها، IPv4 را با `5.160.131.169` و IPv6 را با `2a00:15c9:0:4::a8` جایگزین کنید. اگر UFW غیرفعال است، برای این نصب آن را فعال نکنید. قواعد دستی فایروال با حذف افزونه خودکار حذف نمی‌شوند.

## ۱. نصب روی سرور خارج 89.117.67.22

در نشست معمولی SSH اجرا کنید؛ فرمان نصب را داخل heredoc یا pipe اجرا نکنید تا پرسش‌های تعاملی ورودی درست داشته باشند. استفاده از tmux موجود مفید است.

```bash
curl -fL --retry 3 --connect-timeout 15 --max-time 180 \
  'https://raw.githubusercontent.com/manwithoutpant/rerere/f89643d85b74a4fbe4458bf88ad529c6b4b2fcd4/edge-addons/setup.sh' \
  -o /root/setup-edge.sh &&
sudo bash /root/setup-edge.sh foreign
```

پیش‌فرض‌ها متعلق به همین میزبان‌اند. گزینه‌های انتهای فرمان جایگزین می‌شوند؛ نمونه: `foreign --domain other.example.com --port 26443`.

ترتیب اجرا: بررسی IP/پورت و وضعیت قبلی، دریافت نسخه‌های ثابت با SHA256، آزمایش مستقل داده، گواهی DNS-01، بررسی بومی کانفیگ، ساخت سرویس‌های جدید، دو آزمون کلاینت واقعی، مقایسهٔ وضعیت قبلی و سپس enable سرویس‌های جدید. در شکست آزمایش بومی، سرویس جدیدی ساخته نمی‌شود. در شکست بعدی، واحدهای جدید حذف و فایل‌های خصوصی عیب‌یابی حفظ می‌شوند. خطای این افزونه نباید با تغییر کانفیگ قدیمی حل شود.

پس از READY:

```bash
sudo python3 /opt/edge-addons/edge_addons.py links
sudo python3 /opt/edge-addons/edge_addons.py bundle --output /root/edge-offline.tar.gz
```

فرمان اول **دو لینک جدید مستقیم** را نشان می‌دهد. دومی بستهٔ آفلاین بدون رمز، توکن و کلید گواهی می‌سازد. فایل اتصال دو سرور:

`/opt/edge-addons/private/peer.json`

این فایل فقط دسترسی XHTTP جدید خارج را دارد. آن را عمومی نکنید و در GitHub یا چت نگذارید.

## ۲. انتقال به ایران

با SFTP در MobaXterm، این دو فایل را از خارج روی رایانه بگیرید و به ایران منتقل کنید:

- `/root/edge-offline.tar.gz` → `/root/edge-offline.tar.gz`
- `/opt/edge-addons/private/peer.json` → `/root/edge-peer.json`

SHA256 بسته هنگام ساخت چاپ می‌شود. پس از انتقال با `sha256sum /root/edge-offline.tar.gz` مقایسه کنید. بستهٔ آفلاین فقط کد و آرشیو باینری‌های ثابت دارد؛ گواهی خصوصی و توکن منتقل نمی‌شوند.

## ۳. نصب روی سرور ایران 94.184.11.98

```bash
sudo tar -xzf /root/edge-offline.tar.gz -C /root &&
sudo chmod 600 /root/edge-peer.json &&
sudo python3 -u /root/edge-offline/edge_addons.py install \
  --role iran --domain edge-ir.devwork12.ir \
  --bind-ip 5.160.131.169 --ipv6 2a00:15c9:0:4::a8 \
  --peer-file /root/edge-peer.json --offline-dir /root/edge-offline
```

دریافت باینری از اینترنت ایران لازم نیست. برای ACME و Cloudflare، نصاب کلاینت موقت از **XHTTP جدید خارج** می‌سازد و HTTPS و پرس‌وجوی DNS لازم را از آن مسیر می‌فرستد. توکن ایران روی خود ایران وارد می‌شود. پورت‌های 80 و 443 برای صدور گواهی اشغال نمی‌شوند.

اگر IPv6/25443 جدید خارج از ایران قابل دسترس نباشد، نصب جلو نمی‌رود. REALITY قبلی خودکار جایگزین آن نمی‌شود؛ همین مسیر جدید باید بررسی شود.

پس از READY:

```bash
sudo python3 /opt/edge-addons/edge_addons.py links
sudo python3 /opt/edge-addons/edge_addons.py check
```

اکنون دو لینک جدید ایران و دو لینک جدید مستقیم خارج دارید. لینک‌های قبلی از مدیرهای قبلی قابل استفاده‌اند.

## کلاینت و اثبات اتصال

- **XHTTP:** کلاینت با Xray سازگار با XHTTP، مانند v2rayN با هستهٔ Xray. پشتیبانی XHTTP را برای Throne/sing-box پیش‌فرض نگیرید.
- **TUIC v5:** sing-box/Throne یا کلاینت سازگار TUIC. اگر URI وارد نشد، outbound در `/opt/edge-addons/private/tuic-client.json` مرجع است. این فایل کانفیگ مستقل با پراکسی محلی 10808 است؛ هم‌زمان با برنامه‌ای که آن پورت را دارد اجرا نشود.
- لینک‌ها TLS معتبر و SNI دامنهٔ خودتان دارند. برای رفع خطا، verification را خاموش نکنید. XHTTP این بسته flow=Vision ندارد.
- چهار پروفایل را در گروه جدا وارد کنید. هنگام آزمون مطمئن شوید قواعد کلاینت درخواست آزمایشی را به همان پروفایل می‌فرستند.

نمونهٔ PowerShell برای اثبات عبور **دادهٔ HTTPS** و تطبیق هش فایل ثابت GitHub؛ پورت SOCKS را با مقدار واقعی کلاینت هماهنگ کنید:

```powershell
$edgeProxy = 'socks5h://127.0.0.1:10808'
$edgeFile = Join-Path $env:TEMP ('edge-' + [guid]::NewGuid().ToString('N') + '.bin')
try {
    curl.exe --fail --location --max-time 45 --noproxy no-bypass.invalid --proxy $edgeProxy `
      'https://raw.githubusercontent.com/manwithoutpant/rerere/cd873bbb7262382e7fa7e630c53fe079edc8b832/edge-addons/test_native.py' `
      --output $edgeFile
    if ($LASTEXITCODE -ne 0) { throw 'HTTPS transfer failed' }
    $edgeHash = (Get-FileHash -LiteralPath $edgeFile -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($edgeHash -ne 'bc8efe99007971121ff0b70dccf87f8ac15cbbcfe645de22c78f1e6241184d84') { throw 'Data hash mismatch' }
    Write-Host 'PASS: verified HTTPS and exact file contents'
    curl.exe --fail --max-time 20 --noproxy no-bypass.invalid --proxy $edgeProxy 'https://api.ipify.org'
} finally {
    Remove-Item -LiteralPath $edgeFile -ErrorAction SilentlyContinue
}
```

ipify فقط مشاهدهٔ IP خروجی است؛ خرابی آن به‌تنهایی خرابی پروتکل را ثابت نمی‌کند. تست هش را برای هر چهار لینک روی اینترنت ثابت و همراه تکرار کنید. تست سرور به‌تنهایی مسیر ویندوز تا ایران، UDP اپراتور یا پایداری طولانی را تأیید نمی‌کند.

آزمون بومی روی پورت‌های آزاد و تصادفی loopback اجرا می‌شود و شامل چهار مسیر XHTTP/TUIC مستقیم و از ایران به خارج، دانلود و آپلود HTTPS با 524288 بایت در هر مسیر و تطبیق هش، بازگشت UDP تصادفی 64 و 1200 بایتی، و رد رمز غلط TUIC است. لاگ در `/opt/edge-addons/private/native-lab.log` ذخیره می‌شود. این شرح **آزمون گنجانده‌شده** است، نه اعلام نتیجهٔ پیشاپیش آن.

## مدیریت و بازگشت

```bash
sudo python3 /opt/edge-addons/edge_addons.py status
sudo python3 /opt/edge-addons/edge_addons.py check
sudo python3 /opt/edge-addons/edge_addons.py links
sudo python3 /opt/edge-addons/edge_addons.py uninstall
```

uninstall فقط واحدهای جدید را stop/disable و فایل‌های unit متعلق به خود را حذف می‌کند. داده‌های جدید به دایرکتوری خصوصی `/opt/edge-addons-removed-TIMESTAMP` منتقل می‌شوند. گروه‌ها و فایل‌های مدیرهای قبلی حذف نمی‌شوند. در خطای نصب هم uninstall دایرکتوری ناقص را کنار می‌گذارد تا نصب دوباره ممکن شود.

Guard ده‌دقیقه‌ای پیش از start تنظیم می‌شود؛ در فعال‌سازی نیمه‌کاره واحدهای جدید متوقف می‌شوند. فایل credential سرویس‌ها پسوند .json دارد. سرویس‌های جدید DynamicUser دارند و تنظیماتشان از systemd credentials خوانده می‌شود.

گواهی Cloudflare با timer جدید روزانه بررسی و نزدیک انقضا تمدید می‌شود. توکن root-only است. در تمدید فقط سرویس وب و TUIC افزونه بازراه‌اندازی می‌شوند. برای گواهی ارائه‌شده:

```bash
sudo python3 /opt/edge-addons/edge_addons.py renew \
  --cert /path/new-fullchain.pem --key /path/new-privkey.pem
```

پورت‌های داخلی فقط loopback هستند: 25444 برای backend XHTTP، 25445 برای SOCKS5 TCP/UDP و 25446 برای HTTP CONNECT. نام سرویس‌ها `edge-addons-xray.service`، `edge-addons-web.service` و `edge-addons-tuic.service` است. Caddy فقط h1/h2 دارد تا UDP/25443 به TUIC برسد.

## نگاه حرفه‌ای و معیار مستقل

۱. **کار اضافهٔ متخصص:** ثبت وضعیت قبلی، تعیین مرز خرابی و بازگشت، و آزمایش جداگانهٔ ورودی کاربر، مسیر بین دو سرور و IP خروجی. درگاه مشترک 443 پیش از اثبات مسیر جدید، نقطهٔ خرابی مشترک می‌سازد.

۲. **مادهٔ خام:** JSON زندهٔ سرویس‌ها، unitها، IP/route، مالکیت پورت، گزارش native client، گواهی و در صورت نیاز metadata بسته‌ها. اسکرین‌شات ping کافی نیست. کلیدها و فایل خصوصی نباید در گزارش عمومی قرار بگیرند.

۳. **روش و ابزار:** ip/ss برای IP و پورت، systemctl و hash فایل برای وضعیت قبلی، بررسی بومی Xray/sing-box/Caddy، OpenSSL و بررسی hostname، کلاینت واقعی و curl و SHA256 برای داده، SOCKS UDP ASSOCIATE و nonce برای UDP، و guard با حذف فقط واحدهای متعلق به افزونه.

۴. **شاهد مستقل:** کلاینت‌های رسمی دادهٔ مرجع را با TLS معتبر و هش درست منتقل کنند؛ UDP عیناً برگردد؛ رمز غلط رد شود؛ PID و هش فایل قبلی هنگام نصب یکسان بماند؛ کاربر انتقال داده را از بیرون سرور روی دو اپراتور تکرار کند. ping یا LISTEN بودن پورت این معیار را برآورده نمی‌کند.

## درخواست بازنویسی‌شده

«فقط TUIC و XHTTP را روی ایران و سرور خارج دارای IP دوم، با واحدها و پورت‌های مستقل اضافه کن. از کانفیگ زنده، مالکیت پورت، مسیر IPv6 و مستندات اصلی شروع کن؛ سرویس‌ها، رمزها، فایروال و هسته‌های قبلی را تغییر نده. کد نسخه‌ثابت در GitHub، نصب آفلاین ایران، چرخهٔ گواهی و حذف محدود به افزونه را تحویل بده. موفقیت را با کلاینت واقعی، TLS معتبر، دانلود و آپلود با هش و بازگشت دادهٔ UDP بسنج و نتیجهٔ CI و محدودیت آزمون اپراتور را صریح گزارش کن. تا اثبات سلامت این مسیرها، تجمیع IP و جابه‌جایی 443 را به مرحلهٔ بعد بسپار.»

## منابع اصلی و نسخه‌ها

- [XHTTP، توضیح نویسندهٔ Xray](https://github.com/XTLS/Xray-core/discussions/4113)
- [نمونهٔ رسمی XHTTP و Caddy/Nginx](https://github.com/XTLS/Xray-examples/tree/main/VLESS-TLS-SplitHTTP-CaddyNginx)
- [TUIC inbound](https://sing-box.sagernet.org/configuration/inbound/tuic/) و [outbound](https://sing-box.sagernet.org/configuration/outbound/tuic/)
- [Caddy reverse_proxy و h2c](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)
- [lego Cloudflare DNS-01](https://go-acme.github.io/lego/dns/cloudflare/)
- Xray v26.3.27، sing-box v1.14.3، Caddy v2.11.7 و lego v5.5.2؛ URL و SHA256 آرشیوها در ASSETS نصاب ثابت‌اند. هستهٔ هیچ سرویس دیگری ارتقا نمی‌یابد.
- commit کد و آزمون: `cd873bbb7262382e7fa7e630c53fe079edc8b832`
- SHA256 نصاب: `f22a64cdcb759ba5f8b797ec2eec6152ded8cd0117635212fbc4e8a757be0f61`
- SHA256 آزمون: `bc8efe99007971121ff0b70dccf87f8ac15cbbcfe645de22c78f1e6241184d84`

[وضعیت Actions](https://github.com/manwithoutpant/rerere/actions/workflows/edge-addons-check.yml)

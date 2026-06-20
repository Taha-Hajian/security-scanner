# 🛡️ اسکنر امنیت وب‌سایت

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-000000?logo=flask&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-3fe0a5)

یک ابزار ساده برای بررسی سریع وضعیت امنیتی هر وب‌سایت. آدرس سایت رو بده، اسکنر مستقیم به سایت وصل می‌شه، فاکتورهای امنیتی‌اش رو بررسی می‌کنه و یک امتیاز امنیتی همراه با جزئیات کامل برمی‌گردونه.

## ✨ امکانات

- ✅ بررسی فعال بودن **HTTPS** و ریدایرکت خودکار از HTTP
- 🔒 اعتبارسنجی **گواهی SSL** (صادرکننده، تاریخ انقضا)
- 🧱 بررسی هدرهای امنیتی: `Strict-Transport-Security`، `Content-Security-Policy`، `X-Frame-Options`، `X-Content-Type-Options`، `Referrer-Policy`، `Permissions-Policy`
- 🍪 بررسی فلگ‌های `Secure` و `HttpOnly` روی کوکی‌ها
- 🕵️ تشخیص افشای نسخه سرور در هدر `Server`
- 📊 امتیاز امنیتی نهایی (۰ تا ۱۰۰) به همراه نتیجه «امن / نیمه‌امن / ناامن»

## 🧠 نحوه عملکرد

تمام بررسی‌ها سمت سرور (Python) انجام می‌شود، نه داخل مرورگر؛ چون مرورگر به دلایل امنیتی (CORS و عدم دسترسی جاوااسکریپت به اطلاعات گواهی SSL) نمی‌تواند این نوع بررسی‌ها را مستقیم انجام دهد. بک‌اند با استفاده از کتابخانه‌های `requests` و `ssl` مستقیماً به سایت هدف وصل می‌شود و نتیجه را به‌صورت JSON به رابط کاربری برمی‌گرداند.

## 🧰 تکنولوژی‌های استفاده‌شده

| بخش | تکنولوژی |
|---|---|
| بک‌اند | Python, Flask |
| فرانت‌اند | HTML, CSS, JavaScript |
| فونت | Vazirmatn |
| دیپلوی | Render |

## 🚀 نصب و اجرا

```bash
git clone https://github.com/Taha-Hajian/security-scanner.git
cd security-scanner
pip install -r requirements.txt
python app.py
```

سپس در مرورگر باز کن:
```
http://127.0.0.1:5000
```

## 📁 ساختار پروژه

```
security-scanner/
├── app.py              # منطق اسکن (HTTPS, SSL, هدرها, کوکی)
├── templates/
│   └── index.html      # رابط کاربری
├── static/
│   └── favicon.svg
├── requirements.txt
└── README.md
```

## 🔗 دمو آنلاین

[https://security-scanner-xxxx.onrender.com](#)

> لینک بالا رو با آدرس واقعی روی Render جایگزین کن.

## 📄 لایسنس

این پروژه تحت لایسنس MIT منتشر شده است.

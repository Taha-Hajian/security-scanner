# -*- coding: utf-8 -*-
"""
اسکنر امنیت وب‌سایت
پروژه درس امنیت شبکه - بررسی HTTPS، گواهی SSL و هدرهای امنیتی یک وب‌سایت
"""

import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

REQUEST_TIMEOUT = 8
USER_AGENT = "Mozilla/5.0 (SecurityScanner-Edu-Project/1.0)"

# تعریف هدرهای امنیتی که بررسی می‌شوند
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "title": "HSTS (اجبار به HTTPS)",
        "desc": "مرورگر را مجبور می‌کند همیشه از HTTPS استفاده کند و هرگز روی HTTP نرود.",
    },
    "X-Frame-Options": {
        "title": "X-Frame-Options",
        "desc": "از قرار گرفتن سایت داخل iframe جلوگیری می‌کند و حمله Clickjacking را خنثی می‌کند.",
    },
    "X-Content-Type-Options": {
        "title": "X-Content-Type-Options",
        "desc": "از حدس زدن نوع فایل توسط مرورگر (MIME Sniffing) جلوگیری می‌کند.",
    },
    "Content-Security-Policy": {
        "title": "Content-Security-Policy (CSP)",
        "desc": "مشخص می‌کند اسکریپت و منابع فقط از کجا مجاز به بارگذاری هستند؛ جلوی XSS را می‌گیرد.",
    },
    "Referrer-Policy": {
        "title": "Referrer-Policy",
        "desc": "کنترل می‌کند چه اطلاعاتی از URL فعلی هنگام رفتن به سایت دیگر ارسال شود.",
    },
    "Permissions-Policy": {
        "title": "Permissions-Policy",
        "desc": "دسترسی به امکاناتی مثل دوربین، میکروفون و موقعیت مکانی را محدود می‌کند.",
    },
}


def normalize_url(raw_url: str) -> str:
    raw_url = raw_url.strip()
    if not re.match(r"^https?://", raw_url, re.IGNORECASE):
        raw_url = "https://" + raw_url
    return raw_url


def check_ssl_certificate(hostname: str, port: int = 443):
    """اتصال مستقیم SSL به دامنه و خواندن اطلاعات گواهی"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=REQUEST_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        days_left = (not_after - datetime.now(timezone.utc)).days

        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))

        return {
            "ok": True,
            "valid": days_left > 0,
            "issuer": issuer.get("organizationName") or issuer.get("commonName") or "نامشخص",
            "subject": subject.get("commonName", hostname),
            "issued_on": not_before.strftime("%Y-%m-%d"),
            "expires_on": not_after.strftime("%Y-%m-%d"),
            "days_left": days_left,
        }
    except ssl.SSLCertVerificationError as e:
        return {"ok": True, "valid": False, "error": "گواهی SSL معتبر نیست: " + str(e)}
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        return {"ok": False, "valid": False, "error": "اتصال SSL برقرار نشد: " + str(e)}


def check_https_redirect(hostname: str):
    """آیا نسخه HTTP سایت به‌صورت خودکار به HTTPS هدایت می‌شود؟"""
    try:
        resp = requests.get(
            f"http://{hostname}",
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )
        return resp.url.startswith("https://")
    except requests.RequestException:
        return False


def check_cookies(resp):
    """بررسی فلگ‌های Secure و HttpOnly روی کوکی‌ها"""
    try:
        raw_cookies = resp.raw.headers.get_all("Set-Cookie") if resp.raw else []
    except Exception:
        raw_cookies = []

    if not raw_cookies:
        return {"present": False}

    all_secure = all("secure" in c.lower() for c in raw_cookies)
    all_httponly = all("httponly" in c.lower() for c in raw_cookies)
    return {"present": True, "count": len(raw_cookies), "secure": all_secure, "httponly": all_httponly}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    raw_url = data.get("url", "")
    if not raw_url:
        return jsonify({"error": "آدرس سایت ارسال نشده است."}), 400

    target_url = normalize_url(raw_url)
    hostname = urlparse(target_url).hostname
    if not hostname:
        return jsonify({"error": "آدرس وارد شده معتبر نیست."}), 400

    checks = []  # هر آیتم: {key, title, desc, passed, detail}

    # ۱. درخواست اصلی به سایت
    try:
        resp = requests.get(
            target_url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )
    except requests.exceptions.SSLError:
        return jsonify({"error": "اتصال HTTPS به این سایت برقرار نشد (گواهی SSL مشکل دارد)."}), 200
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "اتصال به سایت برقرار نشد. آدرس را بررسی کنید."}), 200
    except requests.exceptions.Timeout:
        return jsonify({"error": "سایت در زمان مناسب پاسخ نداد (Timeout)."}), 200
    except requests.RequestException as e:
        return jsonify({"error": f"خطا در اتصال: {e}"}), 200

    final_is_https = resp.url.startswith("https://")
    headers = resp.headers

    # ۲. HTTPS فعال است؟
    checks.append(
        {
            "key": "https",
            "title": "استفاده از HTTPS",
            "desc": "ارتباط بین کاربر و سایت رمزنگاری شده است.",
            "passed": final_is_https,
            "detail": resp.url,
        }
    )

    # ۳. ریدایرکت HTTP -> HTTPS
    redirect_ok = check_https_redirect(hostname) if final_is_https else False
    checks.append(
        {
            "key": "redirect",
            "title": "ریدایرکت اجباری به HTTPS",
            "desc": "نسخه http سایت به‌طور خودکار به https هدایت می‌شود.",
            "passed": redirect_ok,
            "detail": "ریدایرکت برقرار است" if redirect_ok else "ریدایرکت یافت نشد یا سایت اصلاً https ندارد",
        }
    )

    # ۴. گواهی SSL
    ssl_info = check_ssl_certificate(hostname) if final_is_https else {"ok": False}
    if final_is_https and ssl_info.get("ok") is not False:
        ssl_valid = ssl_info.get("valid", False)
        if ssl_valid:
            detail = f"صادر شده توسط {ssl_info['issuer']} | انقضا: {ssl_info['expires_on']} ({ssl_info['days_left']} روز مانده)"
        else:
            detail = ssl_info.get("error", "گواهی نامعتبر است")
        checks.append(
            {
                "key": "ssl_cert",
                "title": "اعتبار گواهی SSL",
                "desc": "گواهی باید معتبر، تأیید شده و منقضی نشده باشد.",
                "passed": bool(ssl_valid),
                "detail": detail,
            }
        )
    else:
        checks.append(
            {
                "key": "ssl_cert",
                "title": "اعتبار گواهی SSL",
                "desc": "گواهی باید معتبر، تأیید شده و منقضی نشده باشد.",
                "passed": False,
                "detail": "سایت از HTTPS استفاده نمی‌کند یا اتصال SSL برقرار نشد.",
            }
        )

    # ۵. هدرهای امنیتی
    for header_name, meta in SECURITY_HEADERS.items():
        present = header_name in headers
        checks.append(
            {
                "key": header_name,
                "title": meta["title"],
                "desc": meta["desc"],
                "passed": present,
                "detail": headers.get(header_name, "این هدر در پاسخ سایت وجود ندارد"),
            }
        )

    # ۶. افشای اطلاعات سرور
    server_header = headers.get("Server", "")
    server_leaks_version = bool(re.search(r"\d", server_header))
    checks.append(
        {
            "key": "server_header",
            "title": "عدم افشای نسخه سرور",
            "desc": "هدر Server نباید نسخه دقیق نرم‌افزار سرور را فاش کند.",
            "passed": not server_leaks_version,
            "detail": server_header if server_header else "هدر Server ارسال نشده (خوب است)",
        }
    )

    # ۷. کوکی‌ها
    cookie_info = check_cookies(resp)
    if cookie_info.get("present"):
        checks.append(
            {
                "key": "cookie_secure",
                "title": "فلگ Secure روی کوکی‌ها",
                "desc": "کوکی فقط باید روی اتصال HTTPS ارسال شود.",
                "passed": cookie_info["secure"],
                "detail": f"{cookie_info['count']} کوکی بررسی شد",
            }
        )
        checks.append(
            {
                "key": "cookie_httponly",
                "title": "فلگ HttpOnly روی کوکی‌ها",
                "desc": "از خواندن کوکی توسط جاوااسکریپت (و حملات XSS) جلوگیری می‌کند.",
                "passed": cookie_info["httponly"],
                "detail": f"{cookie_info['count']} کوکی بررسی شد",
            }
        )

    passed_count = sum(1 for c in checks if c["passed"])
    total_count = len(checks)
    score = round((passed_count / total_count) * 100) if total_count else 0

    if score >= 80:
        verdict = "secure"
        verdict_fa = "امن"
    elif score >= 50:
        verdict = "warning"
        verdict_fa = "نیمه‌امن"
    else:
        verdict = "danger"
        verdict_fa = "ناامن"

    return jsonify(
        {
            "url": resp.url,
            "hostname": hostname,
            "score": score,
            "passed": passed_count,
            "total": total_count,
            "verdict": verdict,
            "verdict_fa": verdict_fa,
            "checks": checks,
        }
    )


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)

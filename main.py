#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HackMind v1.0.0 - the localhost hacker AI
=========================================

A free, offline, no-API-key "DigAI-style" assistant that runs in your browser
and helps you hack things A to Z: website recon, admin panel discovery, port
scanning, DNS / subdomain enumeration, SSL inspection, Instagram intel and
login-form brute forcing.

    python3 main.py                   -> opens http://127.0.0.1:8000
    python3 main.py -p 9000           -> custom port
    python3 main.py --host 0.0.0.0    -> expose on your LAN (phone -> PC)

Optional free offline AI brain (no API key):
    curl -fsSL https://ollama.com/install.sh | sh
    ollama pull llama3.2

License: MIT
"""

from __future__ import annotations

import argparse
import concurrent.futures
import os
import re
import socket
import ssl
import threading
import time
import webbrowser
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import dns.resolver
import requests
from bs4 import BeautifulSoup
from flask import Flask, Response, jsonify, request

try:
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass

# ------------------------------------------------------------------ config

APP_NAME = "HackMind"
VERSION = "1.0.0"
TAGLINE = "the localhost hacker AI"

HOST = os.environ.get("HACKMIND_HOST", "127.0.0.1")
PORT = int(os.environ.get("HACKMIND_PORT", "8000"))
OLLAMA_URL = os.environ.get("HACKMIND_OLLAMA", "http://127.0.0.1:11434")
MODEL = os.environ.get("HACKMIND_MODEL", "llama3.2")

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
})

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# ------------------------------------------------------------------ helpers

def norm_url(raw):
    raw = (raw or "").strip()
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    return raw


def host_of(url):
    return urlparse(norm_url(url)).hostname or ""


def bar(title=""):
    line = "-" * 58
    return (title + "\n" + line) if title else line


def fetch(url, timeout=15, allow_redirects=True):
    t0 = time.time()
    r = SESSION.get(url, timeout=timeout, verify=False,
                    allow_redirects=allow_redirects)
    return {
        "status": r.status_code,
        "reason": r.reason,
        "headers": {k: v for k, v in r.headers.items()},
        "text": r.text,
        "final_url": r.url,
        "ms": int((time.time() - t0) * 1000),
        "bytes": len(r.content),
    }


# ------------------------------------------------------------------ detection

TECH_SIGS = [
    (r"wp-content|wp-includes|wp-json", "WordPress"),
    (r"__NEXT_DATA__|/_next/", "Next.js"),
    (r"csrf-token", "Rails/Django CSRF"),
    (r"laravel|XSRF-TOKEN", "Laravel"),
    (r"cdn\.shopify\.com", "Shopify"),
    (r"sites/default/files|drupal", "Drupal"),
    (r"joomla|com_content", "Joomla"),
    (r"ng-version=", "Angular"),
    (r"data-v-[0-9a-f]{8}", "Vue.js"),
    (r"_reactRootContainer|react-dom", "React"),
    (r"jquery", "jQuery"),
    (r"bootstrap(\.min)?\.(css|js)", "Bootstrap"),
    (r"googletagmanager|gtag\(", "Google Tag Manager"),
    (r"woocommerce", "WooCommerce"),
    (r"magento|mage/cookies", "Magento"),
    (r"phpmyadmin", "phpMyAdmin"),
    (r"graphql", "GraphQL"),
    (r"firebase", "Firebase"),
    (r"cloudflare", "Cloudflare"),
]

SERVER_SIGS = [
    (r"nginx", "nginx"), (r"apache", "Apache"), (r"cloudflare", "Cloudflare"),
    (r"iis", "IIS"), (r"gunicorn", "Gunicorn"), (r"express", "Express"),
    (r"litespeed", "LiteSpeed"), (r"openresty", "OpenResty"),
    (r"werkzeug", "Werkzeug (Flask)"),
]

SEC_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
]


def detect_tech(body, headers):
    found = set()
    for pat, name in TECH_SIGS:
        if re.search(pat, body, re.I):
            found.add(name)
    server = (headers.get("Server", "") + " " +
              headers.get("X-Powered-By", ""))
    for pat, name in SERVER_SIGS:
        if re.search(pat, server, re.I):
            found.add(name)
    return sorted(found)


def extract_forms(html, base):
    soup = BeautifulSoup(html, "html.parser")
    out = []
    for f in soup.find_all("form"):
        action = f.get("action") or ""
        out.append({
            "action": urljoin(base, action) if action else base,
            "method": (f.get("method") or "get").upper(),
            "fields": [i.get("name") for i in
                       f.find_all(["input", "select", "textarea"])
                       if i.get("name")],
        })
    return out


# ------------------------------------------------------------------ commands

ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/login", "/administrator", "/wp-admin",
    "/wp-login.php", "/login", "/login.php", "/signin", "/user/login",
    "/account/login", "/dashboard", "/panel", "/cpanel", "/phpmyadmin",
    "/pma", "/webmail", "/adminer.php", "/manager/html", "/console",
    "/api", "/graphql", "/.env", "/.git/config", "/.htaccess",
    "/robots.txt", "/sitemap.xml", "/server-status", "/actuator",
    "/swagger-ui.html", "/api/docs", "/backup", "/db.php",
]

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "smb", 587: "smtp",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    2082: "cpanel", 2083: "cpanel-ssl", 3000: "dev", 3306: "mysql",
    3389: "rdp", 5000: "dev", 5432: "postgres", 5900: "vnc",
    6379: "redis", 8000: "http-alt", 8080: "http-alt", 8443: "https-alt",
    8888: "http-alt", 9000: "http-alt", 27017: "mongodb",
}

DEFAULT_WORDS = [
    "admin", "admin123", "password", "123456", "12345678", "123456789",
    "12345", "root", "test", "qwerty", "letmein", "welcome", "welcome1",
    "password123", "admin@123", "admin1234", "abc123", "111111", "123123",
    "changeme", "secret", "master", "guest", "user", "login", "pass",
    "pass123", "toor", "administrator", "superuser", "default",
]


def scan_site(raw):
    url = norm_url(raw)
    lines = []
    try:
        r = fetch(url, timeout=20)
    except Exception as e:
        return {"ok": False, "kind": "error", "title": "Scan failed",
                "output": "could not reach %s\n%s" % (url, e)}

    soup = BeautifulSoup(r["text"], "html.parser")
    title = (soup.title.string.strip()
             if soup.title and soup.title.string else "-")
    tech = detect_tech(r["text"], r["headers"])
    forms = extract_forms(r["text"], r["final_url"])

    admin_links = sorted({
        urljoin(r["final_url"], a.get("href"))
        for a in soup.find_all("a", href=True)
        if re.search(r"admin|login|signin|dashboard|panel|cpanel|portal",
                     (a.get("href") or "") + " " + (a.string or ""), re.I)
    })[:12]

    missing = [h for h in SEC_HEADERS if h not in r["headers"]]

    lines.append("target     : " + url)
    lines.append("final url  : " + r["final_url"])
    lines.append("status     : %d %s" % (r["status"], r["reason"]))
    lines.append("time       : %d ms" % r["ms"])
    lines.append("size       : %d bytes" % r["bytes"])
    lines.append("title      : " + (title[:80] or "-"))
    lines.append("server     : " + r["headers"].get("Server", "-"))
    lines.append("powered-by : " + r["headers"].get("X-Powered-By", "-"))
    lines.append("tech       : " + (", ".join(tech) or "none detected"))

    lines.append("")
    lines.append(bar("SECURITY HEADERS"))
    if missing:
        lines.append("missing : " + ", ".join(missing))
    else:
        lines.append("all present")

    lines.append("")
    lines.append(bar("FORMS"))
    if forms:
        for i, f in enumerate(forms, 1):
            lines.append("#%d %s %s" % (i, f["method"], f["action"]))
            lines.append("   fields: " + (", ".join(f["fields"]) or "-"))
    else:
        lines.append("no forms found")

    lines.append("")
    lines.append(bar("ADMIN / LOGIN LINKS"))
    lines.extend("  " + l for l in admin_links) if admin_links else \
        lines.append("  none found")

    lines.append("")
    lines.append(bar("QUICK FILE CHECKS"))
    for p in ("/robots.txt", "/sitemap.xml", "/.env", "/.git/config"):
        try:
            rr = fetch(urljoin(r["final_url"], p), timeout=10)
            flag = "  <== EXPOSED" if (p in ("/.env", "/.git/config")
                                       and rr["status"] == 200) else ""
            lines.append("  %-14s %s%s" % (p, rr["status"], flag))
        except Exception:
            lines.append("  %-14s err" % p)

    verdict = []
    if "WordPress" in tech:
        verdict.append("WordPress detected -> try /wp-json/wp/v2/users for user "
                       "enumeration and /wp-login.php with admin/admin123.")
    if any(f["fields"] and any("pass" in (n or "").lower()
                               for n in f["fields"]) for f in forms):
        verdict.append("A login form exists -> run: crack " + url)
    if missing:
        verdict.append("%d security headers missing." % len(missing))
    if not verdict:
        verdict.append("Recon complete. Run 'admin %s' next." % url)

    lines.append("")
    lines.append(bar("ANALYSIS"))
    lines.append(" ".join(verdict))

    return {"ok": True, "kind": "scan",
            "title": "Recon - " + host_of(url),
            "output": "\n".join(lines)}


def admin_scan(raw):
    base = "https://" + host_of(raw)
    lines = ["base: " + base, ""]

    def one(p):
        try:
            rr = fetch(base + p, timeout=10, allow_redirects=False)
            return p, rr["status"], rr["bytes"]
        except Exception:
            return p, 0, 0

    with concurrent.futures.ThreadPoolExecutor(12) as ex:
        results = list(ex.map(one, ADMIN_PATHS))

    live = [x for x in results if x[1] in (200, 301, 302, 401, 403)]
    for p, st, size in sorted(live, key=lambda x: x[1]):
        tag = {200: "OPEN", 401: "AUTH", 403: "FORBIDDEN",
               301: "REDIRECT", 302: "REDIRECT"}.get(st, "")
        lines.append("  %-4d %-28s %-9s %d bytes" % (st, p, tag, size))

    if not live:
        lines.append("  no common paths responded")

    lines.append("")
    lines.append(bar("ANALYSIS"))
    lines.append("%d of %d paths responded. 200 = open, 401/403 = protected "
                 "(needs a password), 30x = redirect." % (len(live), len(ADMIN_PATHS)))
    if any(x[1] in (401, 403) for x in live):
        lines.append("Protected panels found -> run: crack " + base)

    return {"ok": True, "kind": "admin", "title": "Admin panel scan - " + base,
            "output": "\n".join(lines)}


def grab_banner(ip, port, timeout=1.2):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((ip, port))
        if port in (80, 8000, 8080, 8888, 3000, 5000):
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        data = s.recv(256)
        s.close()
        return data.decode("utf-8", "ignore").split("\n")[0].strip()[:64]
    except Exception:
        return ""


def port_scan(raw):
    host = host_of(raw) or raw.strip()
    try:
        ip = socket.gethostbyname(host)
    except Exception as e:
        return {"ok": False, "kind": "error", "title": "Port scan failed",
                "output": "cannot resolve %s\n%s" % (host, e)}

    def check(p):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.8)
        try:
            if s.connect_ex((ip, p)) == 0:
                return p, grab_banner(ip, p)
        finally:
            s.close()
        return None

    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(80) as ex:
        found = [x for x in ex.map(check, sorted(COMMON_PORTS)) if x]

    lines = ["host : %s (%s)" % (host, ip),
             "scan : %d common TCP ports in %.2fs" % (len(COMMON_PORTS),
                                                      time.time() - t0),
             ""]
    if found:
        for p, banner in sorted(found):
            lines.append("  %-6d %-14s %s" % (p, COMMON_PORTS[p], banner))
    else:
        lines.append("  no open ports found (host may block ICMP/filter)")

    lines.append("")
    lines.append(bar("ANALYSIS"))
    risky = [p for p, _ in found if p in (21, 23, 3306, 5432, 6379, 27017, 5900, 445)]
    if risky:
        lines.append("Risky exposed services: " + ", ".join(map(str, risky)) +
                     " (check default creds / no-auth).")
    else:
        lines.append("No obviously risky services exposed.")

    return {"ok": True, "kind": "ports", "title": "Port scan - " + host,
            "output": "\n".join(lines)}


def dns_lookup(raw):
    domain = host_of(raw) or raw.strip()
    lines = ["domain: " + domain, ""]
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
        try:
            ans = dns.resolver.resolve(domain, rtype, lifetime=8)
            vals = [str(r).strip('"') for r in ans]
            lines.append(rtype.ljust(6) + ": " + ", ".join(vals[:6]))
        except Exception:
            lines.append(rtype.ljust(6) + ": -")

    lines.append("")
    lines.append(bar("ANALYSIS"))
    txt = "\n".join(lines)
    if "v=spf1" not in txt:
        lines.append("No SPF record -> email spoofing may be possible.")
    if "google-site-verification" in txt:
        lines.append("Google verification TXT present.")

    return {"ok": True, "kind": "dns", "title": "DNS - " + domain,
            "output": "\n".join(lines)}


def subdomain_finder(raw):
    domain = host_of(raw) or raw.strip()
    try:
        r = SESSION.get("https://crt.sh/",
                        params={"q": "%." + domain, "output": "json"},
                        timeout=30)
        names = set()
        for row in r.json():
            for n in str(row.get("name_value", "")).split("\n"):
                n = n.strip().lower().lstrip("*.")
                if n.endswith(domain):
                    names.add(n)
        names = sorted(names)
    except Exception as e:
        return {"ok": False, "kind": "error", "title": "Subdomain lookup failed",
                "output": str(e)}

    lines = ["domain: " + domain,
             "source: crt.sh certificate transparency",
             "found : %d" % len(names), ""]
    lines.extend("  " + n for n in names[:120])
    if len(names) > 120:
        lines.append("  ... %d more" % (len(names) - 120))

    return {"ok": True, "kind": "subs", "title": "Subdomains - " + domain,
            "output": "\n".join(lines)}


def ssl_info(raw):
    host = host_of(raw) or raw.strip()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=12) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                cipher = ss.cipher()
    except Exception as e:
        return {"ok": False, "kind": "error", "title": "SSL failed",
                "output": str(e)}

    lines = ["host      : " + host,
             "subject   : " + str(cert.get("subject")),
             "issuer    : " + str(cert.get("issuer")),
             "valid from: " + cert.get("notBefore", "-"),
             "valid to  : " + cert.get("notAfter", "-"),
             "cipher    : " + str(cipher), ""]
    sans = cert.get("subjectAltName", [])
    lines.append("SANs (%d):" % len(sans))
    lines.extend("  " + v for _, v in sans[:40])

    return {"ok": True, "kind": "ssl", "title": "TLS - " + host,
            "output": "\n".join(lines)}


def ip_info(raw):
    host = host_of(raw) or raw.strip()
    try:
        ip = socket.gethostbyname(host)
        r = SESSION.get("http://ip-api.com/json/" + ip, timeout=12)
        j = r.json()
    except Exception as e:
        return {"ok": False, "kind": "error", "title": "IP lookup failed",
                "output": str(e)}

    lines = ["host    : " + host,
             "ip      : " + ip,
             "country : %s (%s)" % (j.get("country"), j.get("countryCode")),
             "region  : " + str(j.get("regionName")),
             "city    : " + str(j.get("city")),
             "isp     : " + str(j.get("isp")),
             "org     : " + str(j.get("org")),
             "as      : " + str(j.get("as")),
             "coords  : %s, %s" % (j.get("lat"), j.get("lon"))]

    return {"ok": True, "kind": "ip", "title": "IP intel - " + host,
            "output": "\n".join(lines)}


def insta_profile(raw):
    user = raw.strip().lstrip("@").split("/")[-1]
    if not user:
        return {"ok": False, "kind": "error", "title": "Instagram",
                "output": "no username given"}

    data = None
    try:
        r = SESSION.get(
            "https://www.instagram.com/api/v1/users/web_profile_info/",
            params={"username": user},
            headers={"x-ig-app-id": "936619743392459",
                     "Accept": "application/json"}, timeout=15)
        if r.status_code == 200 and r.text.lstrip().startswith("{"):
            u = r.json().get("data", {}).get("user")
            if u:
                data = {
                    "username": u.get("username"),
                    "name": u.get("full_name"),
                    "followers": u.get("edge_followed_by", {}).get("count"),
                    "following": u.get("edge_follow", {}).get("count"),
                    "posts": u.get("edge_owner_to_timeline_media", {}).get("count"),
                    "private": u.get("is_private"),
                    "verified": u.get("is_verified"),
                    "business": u.get("is_business_account"),
                    "bio": (u.get("biography") or "").replace("\n", " ")[:200],
                    "id": u.get("id"),
                }
    except Exception:
        pass

    if not data:
        try:
            r = SESSION.get("https://www.instagram.com/%s/" % user, timeout=15)
            if "Sorry, this page isn't available" in r.text:
                return {"ok": True, "kind": "insta", "title": "Instagram - @" + user,
                        "output": "@%s does not exist." % user}
            soup = BeautifulSoup(r.text, "html.parser")
            og = soup.find("meta", property="og:description")
            desc = og.get("content", "") if og else ""
            fol = re.search(r"([\d.,]+[KMB]?)\s+Followers", desc)
            data = {"username": user, "followers": fol.group(1) if fol else "?",
                    "bio": desc[:200], "name": "-", "private": "?",
                    "verified": "?", "posts": "?", "following": "?",
                    "business": "?", "id": "-"}
        except Exception as e:
            return {"ok": False, "kind": "error", "title": "Instagram failed",
                    "output": str(e)}

    lines = ["username  : @" + str(data["username"]),
             "full name : " + str(data["name"]),
             "followers : " + str(data["followers"]),
             "following : " + str(data["following"]),
             "posts     : " + str(data["posts"]),
             "private   : " + str(data["private"]),
             "verified  : " + str(data["verified"]),
             "business  : " + str(data["business"]),
             "user id   : " + str(data["id"]),
             "",
             bar("BIO"),
             str(data["bio"]) or "-",
             "",
             bar("ANALYSIS")]
    if data.get("private") is True:
        lines.append("Account is private -> only follower count + bio are public.")
    else:
        lines.append("Account is public -> posts and tags are scrapeable.")
    lines.append("Password brute force needs a real session; use instagrapi "
   
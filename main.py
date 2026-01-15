#!/usr/bin/env python3
#!/usr/bin/env python3                                          # kArmas-ZAP FULL MODE + AUTH + JS (LOCAL/REMOTE) + REQ/RESP VIEWER
# Passive + Active Audit Framework
# Made in l0v3 bY kArmasec

import requests
import ssl
import socket
import sys
import json
import sqlite3
import re
import threading
import argparse
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from flask import Flask, jsonify
from colorama import Fore, Style, init

init(autoreset=True)
requests.packages.urllib3.disable_warnings()

# ─── OPTIONAL PLAYWRIGHT ─────────────────────────────────────────────────────
JS_LOCAL_AVAILABLE = False
try:
    from playwright.sync_api import sync_playwright
    JS_LOCAL_AVAILABLE = True
except Exception:
    JS_LOCAL_AVAILABLE = False

# ─── GLOBALS ─────────────────────────────────────────────────────────────────
visited = set()
findings = []

BASE_HEADERS = {"User-Agent": "kArmas-ZAP-FULL/1.2"}
SESSION_HEADERS = BASE_HEADERS.copy()

# ─── HEADER SAFETY ───────────────────────────────────────────────────────────
def sanitize_headers(headers):
    clean = {}
    for k, v in headers.items():
        try:
            v.encode("latin-1")
            clean[k] = v
        except UnicodeEncodeError:
            clean[k] = v.encode("utf-8", "ignore").decode("latin-1", "ignore")
    return clean                                                
# ─── DATABASE ────────────────────────────────────────────────────────────────
db = sqlite3.connect("karmas_zap_full.db", check_same_thread=False)
cur = db.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS findings (
    type TEXT, target TEXT, severity TEXT, details TEXT
)
""")
cur.execute("""
CREATE TABLE IF NOT EXISTS traffic (
    ts INTEGER, method TEXT, url TEXT, status INTEGER,
    req_headers TEXT, resp_headers TEXT, resp_size INTEGER
)
""")
db.commit()

def store_finding(t, target, sev, det):
    findings.append({"type": t, "target": target, "severity": sev, "details": det})
    cur.execute("INSERT INTO findings VALUES (?,?,?,?)", (t, target, sev, det))
    db.commit()

def store_traffic(method, url, status, req_h, resp_h, size):
    cur.execute(
        "INSERT INTO traffic VALUES (?,?,?,?,?,?,?)",
        (int(time.time()), method, url, status, json.dumps(req_h), json.dumps(resp_h), size)
    )
    db.commit()

# ─── HTTP WITH LOGGING ───────────────────────────────────────────────────────
def http_get(url):
    r = requests.get(url, headers=SESSION_HEADERS, timeout=12, verify=False)
    store_traffic(
        "GET", url, r.status_code,
        dict(SESSION_HEADERS), dict(r.headers), len(r.content)
    )
    return r

# ─── HTTP CRAWLER ────────────────────────────────────────────────────────────
def http_crawl(url, base):
    if url in visited:
        return
    visited.add(url)
    
    try:
        r = http_get(url)
    except Exception:
        return
    
    # Use html.parser — lxml not needed and often missing on Termux
    soup = BeautifulSoup(r.text, "html.parser")
    
    parsed = urlparse(url)
    if parsed.query:
        store_finding("Params", url, "INFO", ",".join(parse_qs(parsed.query).keys()))
    
    for tag in soup.find_all(["a", "form"], href=True):
        link = urljoin(base, tag["href"])
        if base in link and link not in visited:
            http_crawl(link, base)

# ─── JS CRAWLER (LOCAL OR REMOTE) ────────────────────────────────────────────
def js_crawl(start_url, base, remote_ws=None):
    try:
        with sync_playwright() as p:
            if remote_ws:
                print(Fore.CYAN + "[*] Connecting to REMOTE headless browser")
                browser = p.chromium.connect_over_cdp(remote_ws)
            else:
                if not JS_LOCAL_AVAILABLE:
                    raise RuntimeError("Local Playwright not available")
                print(Fore.CYAN + "[*] Using LOCAL headless browser")
                browser = p.chromium.launch(headless=True)
            
            context = browser.new_context(extra_http_headers=SESSION_HEADERS)
            page = context.new_page()                           
            def on_response(resp):
                try:
                    store_traffic(
                        resp.request.method,
                        resp.url,
                        resp.status,
                        dict(resp.request.headers),
                        dict(resp.headers),
                        int(resp.headers.get("content-length", "0"))
                    )
                except Exception:
                    pass

            page.on("response", on_response)

            page.goto(start_url, wait_until="networkidle", timeout=20000)
            html = page.content()
            soup = BeautifulSoup(html, "html.parser")  # again — html.parser

            for tag in soup.find_all(["a", "form"], href=True):
                link = urljoin(base, tag["href"])
                if base in link and link not in visited:
                    visited.add(link)
                    store_finding("JS-Link", link, "INFO", "Discovered via JS")

            browser.close()
            return
    except Exception as e:
        store_finding("JS", start_url, "LOW", f"JS failed, fallback HTTP: {str(e)}")
        http_crawl(start_url, base)

# ─── VULNERABILITY CHECKS ────────────────────────────────────────────────────
def headers_check(url):
    r = http_get(url)
    important = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "Referrer-Policy"
    ]
    missing = [h for h in important if h.lower() not in [k.lower() for k in r.headers]]
    if missing:
        store_finding("Header", url, "MEDIUM", f"Missing: {', '.join(missing)}")

def cookie_check(url):
    r = http_get(url)
    for c in r.cookies:
        issues = []
        if not c.secure:
            issues.append("Secure")
        # Fixed: real way to check HttpOnly
        if not c.has_nonstandard_attr("HttpOnly"):
            issues.append("HttpOnly")
        if issues:
            store_finding("Cookie", c.name, "MEDIUM", ",".join(issues))

def tls_check(host):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as s:
            with ctx.wrap_socket(s, server_hostname=host):
                pass
    except Exception:
        store_finding("TLS", host, "HIGH", "TLS missing or broken")

def dom_xss_heuristic(url):
    r = http_get(url)
    if re.search(r"(innerHTML|document\.write|eval\()", r.text, re.IGNORECASE):
        store_finding("DOM-XSS", url, "MEDIUM", "Potential JS sink detected")

def verify_auth(url):
    r = http_get(url)
    if r.status_code in (401, 403):
        store_finding("Auth", url, "HIGH", "Auth failed or expired")
    else:
        store_finding("Auth", url, "INFO", "Authenticated access OK")

# ─── DASHBOARD ───────────────────────────────────────────────────────────────
app = Flask(__name__)

@app.route("/")
def api_findings():
    return jsonify(findings)

@app.route("/traffic")
def api_traffic():
    rows = cur.execute(
        "SELECT ts,method,url,status,req_headers,resp_headers,resp_size FROM traffic"
    ).fetchall()
    out = []
    for row in rows:
        out.append({
            "ts": row[0],
            "method": row[1],
            "url": row[2],
            "status": row[3],
            "req_headers": json.loads(row[4]),
            "resp_headers": json.loads(row[5]),
            "resp_size": row[6]
        })
    return jsonify(out)

def run_dashboard():
    app.run(host="127.0.0.1", port=8081, debug=False, use_reloader=False)

# ─── ARGUMENTS ───────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(description="kArmas-ZAP FULL MODE")
    p.add_argument("target")
    p.add_argument("--cookie")
    p.add_argument("--auth")
    p.add_argument("--js", action="store_true", help="Enable JS crawling")
    p.add_argument("--remote-ws", help="Remote CDP WS (ws://host:9222)")
    return p.parse_args()

def build_headers(args):
    h = BASE_HEADERS.copy()
    if args.cookie:
        h["Cookie"] = args.cookie
    if args.auth:
        if ":" in args.auth:
            k, v = args.auth.split(":", 1)
            h[k.strip()] = v.strip()
    return sanitize_headers(h)

# ─── MAIN ────────────────────────────────────────────────────────────────────
def main():
    global SESSION_HEADERS

    args = parse_args()
    target = args.target.rstrip("/")
    base = target
    host = urlparse(target).hostname
    SESSION_HEADERS = build_headers(args)
    
    print(Fore.GREEN + "[*] kArmas-ZAP FULL MODE (JS + Remote + Traffic)")
    print(Fore.CYAN + f"[*] Target: {target}")
    
    if args.js:
        js_crawl(target, base, remote_ws=args.remote_ws)
    else:
        http_crawl(target, base)

    verify_auth(target)
    headers_check(target)
    cookie_check(target)
    tls_check(host)
    dom_xss_heuristic(target)

    print(Fore.GREEN + f"[✓] Scan complete – {len(findings)} findings")
    print(Fore.CYAN + "[*] Dashboard:")
    print(Fore.CYAN + "    Findings  → http://127.0.0.1:8081/")
    print(Fore.CYAN + "    Traffic   → http://127.0.0.1:8081/traffic")

    threading.Thread(target=run_dashboard, daemon=True).start()
    input(Fore.YELLOW + "Press ENTER to exit..." + Style.RESET_ALL)

if __name__ == "__main__":
    main()

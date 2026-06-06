#!/usr/bin/env python3
"""CyberShield Working Tests - Attacks Pi's local HTTP server"""
import requests
import socket
import time

G = '\033[92m'; R = '\033[91m'; Y = '\033[93m'; C = '\033[96m'; X = '\033[0m'

PI = "10.42.0.1:8080"  # Pi's HTTP server

def attack(name, method, path, data=None):
    print(f"{Y}[>] {name}{X}...", end=" ")
    try:
        url = f"http://{PI}{path}"
        if method == "GET":
            requests.get(url, timeout=3)
        else:
            requests.post(url, data=data, timeout=3)
        print(f"{G}OK{X}")
    except Exception as e:
        print(f"{R}FAIL ({str(e)[:30]}){X}")
    time.sleep(0.3)

print(f"""
{C}╔══════════════════════════════════════════╗
║   CYBERSHIELD WORKING TEST SUITE        ║
║   Target: Pi HTTP Server ({PI})     ║
╚══════════════════════════════════════════╝{X}
""")

# URL Phishing - Use query params with URLs
print(f"\n{C}═══ URL PHISHING ═══{X}")
attack("Phishing URL", "GET", "/?url=http://evil-phishing.com/login")
attack("Malware URL", "GET", "/?url=http://malware-download.xyz/payload.exe")
attack("Fake Bank", "GET", "/?url=http://fake-bank.com/verify")

# SQL Injection
print(f"\n{C}═══ SQL INJECTION ═══{X}")
attack("Basic SQLi", "POST", "/login", {"username": "admin' OR '1'='1' --"})
attack("Union SQLi", "POST", "/login", {"id": "' UNION SELECT * FROM users --"})
attack("Blind SQLi", "POST", "/login", {"id": "1' AND 1=1 --"})

# XSS
print(f"\n{C}═══ XSS ═══{X}")
attack("Script XSS", "GET", "/?q=<script>alert('xss')</script>")
attack("IMG XSS", "GET", "/?q=<img src=x onerror=alert(1)>")
attack("SVG XSS", "GET", "/?q=<svg onload=alert(1)>")

# Command Injection
print(f"\n{C}═══ COMMAND INJECTION ═══{X}")
attack("CMDi Semicolon", "POST", "/exec", {"cmd": "; ls -la"})
attack("CMDi Pipe", "POST", "/exec", {"cmd": "| cat /etc/shadow"})
attack("CMDi Subshell", "POST", "/exec", {"cmd": "$(whoami)"})

# Path Traversal
print(f"\n{C}═══ PATH TRAVERSAL ═══{X}")
attack("Unix Traversal", "GET", "/?file=../../../etc/passwd")
attack("Windows Traversal", "GET", "/?file=..\\..\\windows\\system32")
attack("Encoded Traversal", "GET", "/?file=%2e%2e%2fetc/passwd")

# SSTI
print(f"\n{C}═══ SSTI ═══{X}")
attack("SSTI Basic", "GET", "/?name={{7*7}}")
attack("SSTI Config", "GET", "/?name={{config}}")

# Port Scan
print(f"\n{C}═══ PORT SCANNING (DPI) ═══{X}")
ports = [22, 80, 443, 8080, 3389]
for port in ports:
    try:
        s = socket.socket(); s.settimeout(0.2)
        s.connect(("10.42.0.1", port)); s.close()
    except: pass
print(f"{G}  Port scan complete{X}")

print(f"""
{G}╔══════════════════════════════════════════╗
║   ALL ATTACKS SENT!                      ║
║   Check Pi terminal NOW!                  ║
╚══════════════════════════════════════════╝{X}
""")
#!/usr/bin/env python3
"""Test XSS Detection"""
import requests, time
G = '\033[92m'; R = '\033[91m'; Y = '\033[93m'; C = '\033[96m'; X = '\033[0m'

payloads = [
    ("Script", "<script>alert('xss')</script>"),
    ("IMG", "<img src=x onerror=alert(1)>"),
    ("SVG", "<svg onload=alert(1)>"),
    ("JavaScript", "javascript:alert(document.cookie)"),
    ("IFrame", "<iframe src=javascript:alert(1)>"),
    ("Body", "<body onload=alert(1)>"),
]

print(f"{C}═══ XSS ATTACKS ═══{X}\n")
for name, p in payloads:
    print(f"{Y}[>] {name}{X}...", end=" ")
    try:
        requests.get("http://httpbin.org/get", params={"q": p}, timeout=5)
        print(f"{G}OK{X}")
    except: print(f"{R}FAIL{X}")
    time.sleep(0.5)
print(f"\n{C}Check Pi terminal for alerts!{X}")
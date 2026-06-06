#!/usr/bin/env python3
"""Test URL Phishing Detection"""
import requests, time
G = '\033[92m'; R = '\033[91m'; Y = '\033[93m'; C = '\033[96m'; X = '\033[0m'

urls = [
    "http://evil-phishing.com/login",
    "http://fake-bank.com/verify",
    "http://malware-download.xyz/payload.exe",
    "http://paypa1-secure.com/login",
    "http://suspicious-login.net/account",
]

print(f"{C}═══ URL PHISHING ATTACKS ═══{X}\n")
for url in urls:
    print(f"{Y}[>] {url.split('/')[2]}{X}...", end=" ")
    try:
        requests.get(url, timeout=5)
        print(f"{G}OK{X}")
    except: print(f"{R}FAIL{X}")
    time.sleep(0.5)
print(f"\n{C}Check Pi terminal for alerts!{X}")
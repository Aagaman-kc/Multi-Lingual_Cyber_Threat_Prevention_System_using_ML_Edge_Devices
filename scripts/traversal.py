#!/usr/bin/env python3
"""Test Path Traversal Detection"""
import requests, time
G = '\033[92m'; R = '\033[91m'; Y = '\033[93m'; C = '\033[96m'; X = '\033[0m'

payloads = [
    ("Unix", "../../../etc/passwd"),
    ("Windows", "..\\..\\..\\windows\\system32"),
    ("Encoded", "%2e%2e%2fetc/passwd"),
    ("Deep", "....//....//etc/shadow"),
]

print(f"{C}═══ PATH TRAVERSAL ═══{X}\n")
for name, p in payloads:
    print(f"{Y}[>] {name}{X}...", end=" ")
    try:
        requests.get("http://httpbin.org/get", params={"file": p}, timeout=5)
        print(f"{G}OK{X}")
    except: print(f"{R}FAIL{X}")
    time.sleep(0.5)
print(f"\n{C}Check Pi terminal for alerts!{X}")
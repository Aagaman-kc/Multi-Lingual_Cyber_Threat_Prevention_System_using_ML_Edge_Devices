#!/usr/bin/env python3
"""Test SSTI Detection"""
import requests, time
G = '\033[92m'; R = '\033[91m'; Y = '\033[93m'; C = '\033[96m'; X = '\033[0m'

payloads = ["{{7*7}}", "{{config}}", "{{self}}", "{{request}}"]

print(f"{C}═══ SSTI ATTACKS ═══{X}\n")
for p in payloads:
    print(f"{Y}[>] {p}{X}...", end=" ")
    try:
        requests.get("http://httpbin.org/get", params={"name": p}, timeout=5)
        print(f"{G}OK{X}")
    except: print(f"{R}FAIL{X}")
    time.sleep(0.5)
print(f"\n{C}Check Pi terminal for alerts!{X}")
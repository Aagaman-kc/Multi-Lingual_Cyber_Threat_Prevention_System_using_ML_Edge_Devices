#!/usr/bin/env python3
"""Test SQL Injection Detection"""
import requests, time
G = '\033[92m'; R = '\033[91m'; Y = '\033[93m'; C = '\033[96m'; X = '\033[0m'

payloads = [
    ("Basic", "admin' OR '1'='1' --"),
    ("Union", "' UNION SELECT * FROM users --"),
    ("Blind", "1' AND 1=1 --"),
    ("Stacked", "1; DROP TABLE users --"),
    ("Comment", "' OR 1=1 #"),
    ("Time-based", "1'; SELECT SLEEP(5) --"),
]

print(f"{C}═══ SQL INJECTION ATTACKS ═══{X}\n")
for name, p in payloads:
    print(f"{Y}[>] {name}{X}...", end=" ")
    try:
        requests.post("http://httpbin.org/post", data={"q": p}, timeout=5)
        print(f"{G}OK{X}")
    except: print(f"{R}FAIL{X}")
    time.sleep(0.5)
print(f"\n{C}Check Pi terminal for alerts!{X}")
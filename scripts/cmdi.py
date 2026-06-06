#!/usr/bin/env python3
"""Test Command Injection Detection"""
import requests, time
G = '\033[92m'; R = '\033[91m'; Y = '\033[93m'; C = '\033[96m'; X = '\033[0m'

payloads = [
    ("Semicolon", "; ls -la /etc/passwd"),
    ("Pipe", "| cat /etc/shadow"),
    ("Subshell", "$(whoami)"),
    ("Backtick", "`id`"),
    ("AND", "ping 127.0.0.1 && rm -rf /"),
]

print(f"{C}═══ COMMAND INJECTION ═══{X}\n")
for name, p in payloads:
    print(f"{Y}[>] {name}{X}...", end=" ")
    try:
        requests.post("http://httpbin.org/post", data={"cmd": p}, timeout=5)
        print(f"{G}OK{X}")
    except: print(f"{R}FAIL{X}")
    time.sleep(0.5)
print(f"\n{C}Check Pi terminal for alerts!{X}")
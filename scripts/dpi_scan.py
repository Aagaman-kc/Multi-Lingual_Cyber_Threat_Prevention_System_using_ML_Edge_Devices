#!/usr/bin/env python3
"""Test Port Scanning Detection (DPI)"""
import socket
G = '\033[92m'; Y = '\033[93m'; C = '\033[96m'; X = '\033[0m'

PI_IP = "10.42.0.1"
ports = [22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 8080, 8443]

print(f"{C}═══ PORT SCANNING (DPI) ═══{X}\n")
print(f"{Y}Scanning {PI_IP}...{X}")
for port in ports:
    try:
        s = socket.socket(); s.settimeout(0.2)
        s.connect((PI_IP, port)); s.close()
        print(f"  Port {port}: OPEN")
    except: pass
print(f"\n{G}Port scan complete!{X}")
print(f"{C}Check Pi terminal for DPI alerts!{X}")
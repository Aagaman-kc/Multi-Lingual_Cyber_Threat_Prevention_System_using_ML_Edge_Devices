#!/usr/bin/env python3
"""Test Email Phishing Detection - Send to Pi Gateway"""
import socket
import time

G = '\033[92m'; R = '\033[91m'; Y = '\033[93m'; C = '\033[96m'; X = '\033[0m'

PI_IP = "10.42.0.1"  # Pi's hotspot gateway

# First start SMTP listener on Pi
print(f"{C}═══ EMAIL PHISHING ATTACKS ═══{X}\n")
print(f"{Y}First, start SMTP listener on Pi:{X}")
print(f"  ssh pi@10.42.0.1")
print(f"  python3 -c \"from aiosmtpd.controller import Controller; c=Controller(Controller, hostname='0.0.0.0', port=2525); c.start(); input('Running...')\"")
print(f"\nOr use netcat:")
print(f"  nc -l -p 2525\n")

input(f"{Y}Press Enter after starting listener on Pi...{X}")

emails = [
    ("Account Suspended", "security@paypal.com", "URGENT: Your Account Has Been Suspended!",
     "Dear User, your account has been locked. Verify immediately: http://phishing-bank.com/verify"),
    ("Password Expired", "it@company.com", "Password Expires in 1 Hour",
     "Your password has expired. Click here to reset: http://fake-reset.com/reset"),
    ("Prize Winner", "prizes@lottery.com", "You Won $1,000,000!",
     "Congratulations! Claim your prize now: http://scam-prize.com/claim"),
    ("Security Alert", "alert@bank.com", "Suspicious Login Detected",
     "We detected a login from Russia. Verify: http://phishing-login.com/verify"),
    ("Invoice Scam", "billing@company.com", "Your Invoice #12345",
     "Your invoice is ready. Download: http://malware-download.xyz/invoice.pdf"),
]

for name, sender, subject, body in emails:
    print(f"{Y}[>] {name}{X}...", end=" ")
    try:
        s = socket.socket(); s.settimeout(3)
        s.connect((PI_IP, 2525))
        msg = f"From: {sender}\r\nTo: victim@test.com\r\nSubject: {subject}\r\n\r\n{body}\r\n.\r\n"
        s.send(msg.encode())
        s.close()
        print(f"{G}OK{X}")
    except Exception as e:
        print(f"{R}FAIL - {str(e)[:30]}{X}")
    time.sleep(0.5)

print(f"\n{C}Check Pi terminal for email alerts!{X}")
import subprocess
import platform
import logging
import threading
import time
import re
import os
from datetime import datetime, timedelta
from urllib.parse import urlparse
import socket

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PreventionEngine:
    """Prevention Engine - Multi-layered threat blocking"""

    def __init__(self, db_manager=None, simulation_mode=False):
        self.db_manager = db_manager
        self.simulation_mode = simulation_mode
        self.blocked_ips = {}
        self.blocked_urls = {}
        self.blocked_senders = {}
        self.sinkholed_domains = []
        self.block_lock = threading.Lock()
        self.is_linux = platform.system() == 'Linux'

        if not self.is_linux and not simulation_mode:
            logger.warning("Not running on Linux - enabling simulation mode")
            self.simulation_mode = True

        self.block_durations = {'critical': None, 'high': 24, 'medium': 6, 'low': 1}
        self.stats = {
            'total_blocked': 0, 'active_blocks': 0, 'permanent_blocks': 0,
            'temporary_blocks': 0, 'urls_blocked': 0, 'emails_blocked': 0,
            'domains_sinkholed': 0, 'last_block_time': None
        }
        self.cleanup_thread = None
        self.running = False
        logger.info(f"Prevention engine initialized (simulation={simulation_mode})")

    def start(self):
        self.running = True
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()
        logger.info("Prevention engine started")

    def stop(self):
        self.running = False
        logger.info("Prevention engine stopped")

    # ============================================================
    # IP BLOCKING
    # ============================================================
    def block_ip(self, ip_address, reason, severity='high', duration_hours=None):
        if self._is_private_ip(ip_address):
            logger.info(f"Skipping block for private IP: {ip_address}")
            return False
        if ip_address in self.blocked_ips:
            return True
        if duration_hours is None:
            duration_hours = self.block_durations.get(severity, 6)
        expires_at = datetime.now() + timedelta(hours=duration_hours) if duration_hours else None

        try:
            if self.is_linux and not self.simulation_mode:
                os.system(f"sudo iptables -A INPUT -s {ip_address} -j DROP 2>/dev/null")
                os.system(f"sudo iptables -A FORWARD -s {ip_address} -j DROP 2>/dev/null")
                success = True
            else:
                success = True
                logger.info(f"[SIMULATION] Blocked IP: {ip_address}")

            if success:
                with self.block_lock:
                    self.blocked_ips[ip_address] = {
                        'reason': reason, 'severity': severity,
                        'blocked_at': datetime.now().isoformat(),
                        'expires_at': expires_at.isoformat() if expires_at else None,
                        'duration_hours': duration_hours, 'permanent': duration_hours is None
                    }
                self.stats['total_blocked'] += 1
                self.stats['active_blocks'] += 1
                if duration_hours is None: self.stats['permanent_blocks'] += 1
                else: self.stats['temporary_blocks'] += 1
                self.stats['last_block_time'] = datetime.now().isoformat()
                if self.db_manager: self.db_manager.block_ip(ip_address, reason, duration_hours)
                logger.warning(f"🛑 BLOCKED IP: {ip_address} | {reason}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error blocking IP {ip_address}: {e}")
            return False

    def unblock_ip(self, ip_address):
        if ip_address not in self.blocked_ips: return True
        try:
            if self.is_linux and not self.simulation_mode:
                os.system(f"sudo iptables -D INPUT -s {ip_address} -j DROP 2>/dev/null")
                os.system(f"sudo iptables -D FORWARD -s {ip_address} -j DROP 2>/dev/null")
            with self.block_lock: del self.blocked_ips[ip_address]
            self.stats['active_blocks'] -= 1
            if self.db_manager: self.db_manager.unblock_ip(ip_address)
            logger.info(f"Unblocked IP: {ip_address}")
            return True
        except Exception as e:
            logger.error(f"Error unblocking IP {ip_address}: {e}")
            return False

    # ============================================================
    # URL / DOMAIN BLOCKING
    # ============================================================
    def block_domain(self, domain, reason):
        """Block a domain - blocks HTTP content and adds DNS sinkhole"""
        logger.info(f"Blocking domain: {domain} ({reason})")
        self._block_http_content(domain, reason)
        self.sinkhole_domain(domain)
        return True

    def block_url(self, url, reason):
        """Block a full URL"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path
            if not domain: return False
            return self.block_domain(domain, reason)
        except Exception as e:
            logger.error(f"Error blocking URL {url}: {e}")
            return False

    def _block_http_content(self, pattern, reason):
        """Block HTTP traffic containing a specific pattern using os.system"""
        try:
            rules = [
                f"sudo iptables -A FORWARD -p tcp --sport 80 -m string --string '{pattern}' --algo bm -j DROP 2>/dev/null",
                f"sudo iptables -A FORWARD -p tcp --sport 443 -m string --string '{pattern}' --algo bm -j DROP 2>/dev/null",
                f"sudo iptables -A FORWARD -p tcp --dport 80 -m string --string '{pattern}' --algo bm -j DROP 2>/dev/null",
            ]
            for rule in rules:
                os.system(rule)

            with self.block_lock:
                self.blocked_urls[pattern] = {'reason': reason, 'blocked_at': datetime.now().isoformat()}
            self.stats['urls_blocked'] += 1
            logger.warning(f"🔗 BLOCKED CONTENT: '{pattern}' | {reason}")
            return True
        except Exception as e:
            logger.error(f"Error blocking content '{pattern}': {e}")
            return False

    def unblock_content(self, pattern):
        """Remove content-based block"""
        try:
            rules = [
                f"sudo iptables -D FORWARD -p tcp --sport 80 -m string --string '{pattern}' --algo bm -j DROP 2>/dev/null",
                f"sudo iptables -D FORWARD -p tcp --sport 443 -m string --string '{pattern}' --algo bm -j DROP 2>/dev/null",
                f"sudo iptables -D FORWARD -p tcp --dport 80 -m string --string '{pattern}' --algo bm -j DROP 2>/dev/null",
            ]
            for rule in rules:
                os.system(rule)
            with self.block_lock:
                if pattern in self.blocked_urls: del self.blocked_urls[pattern]
            logger.info(f"Unblocked content: {pattern}")
            return True
        except Exception as e:
            logger.error(f"Error unblocking content: {e}")
            return False

    # ============================================================
    # DNS SINKHOLE
    # ============================================================
    def sinkhole_domain(self, domain):
        """Redirect domain to 127.0.0.1 via /etc/hosts"""
        try:
            if domain in self.sinkholed_domains:
                return True
            with open('/etc/hosts', 'r') as f:
                if domain in f.read():
                    self.sinkholed_domains.append(domain)
                    return True
            with open('/etc/hosts', 'a') as f:
                f.write(f"127.0.0.1  {domain}\n")
                f.write(f"127.0.0.1  www.{domain}\n")
            self.sinkholed_domains.append(domain)
            self.stats['domains_sinkholed'] += 1
            logger.warning(f"🏴‍☠️ SINKHOLED: {domain} → 127.0.0.1")
            return True
        except Exception as e:
            logger.error(f"Sinkhole error: {e}")
            return False

    def remove_sinkhole(self, domain):
        """Remove a domain from sinkhole"""
        try:
            with open('/etc/hosts', 'r') as f:
                lines = f.readlines()
            with open('/etc/hosts', 'w') as f:
                for line in lines:
                    if domain not in line:
                        f.write(line)
            if domain in self.sinkholed_domains:
                self.sinkholed_domains.remove(domain)
            return True
        except:
            return False

    # ============================================================
    # SMART BLOCK - Decision Engine
    # ============================================================
    def smart_block(self, result, source_ip, context):
        module = result.get('module', '')
        label = result.get('label', '')
        confidence = result.get('confidence', 0)

        if module == 'url':
            url = self._extract_url(context)
            if url:
                domain = self._extract_domain(url)
                if domain:
                    self.block_domain(domain, f"{label} URL (conf: {confidence:.0%})")
                    return 'URL', domain

        elif module == 'app_attack':
            if not self._is_loopback(source_ip):
                self.block_ip(source_ip, f"{label} attack (conf: {confidence:.0%})", 'critical')
                return 'IP', source_ip

        elif module == 'dpi':
            if not self._is_loopback(source_ip):
                self.block_ip(source_ip, f"Anomaly: {label}", 'high')
                return 'IP', source_ip

        elif module == 'email':
            email_data = context if isinstance(context, dict) else {}
            sender = email_data.get('sender', '')
            subject = email_data.get('subject', '')
            body = email_data.get('body', str(context))
            urls = re.findall(r'https?://[^\s<>"\']+', str(body))
            if sender:
                self.block_smtp_sender(sender, f"Phishing (conf: {confidence:.0%})")
            for url in urls:
                domain = self._extract_domain(url)
                if domain:
                    self.sinkhole_domain(domain)
            return 'EMAIL', sender if sender else 'unknown'

        return None, None

    # ============================================================
    # SMTP BLOCKING
    # ============================================================
    def block_smtp_sender(self, sender, reason):
        try:
            for port in ['25', '465', '587', '2525']:
                os.system(f"sudo iptables -A FORWARD -p tcp --dport {port} -m string --string '{sender}' --algo bm -j DROP 2>/dev/null")
            with self.block_lock:
                self.blocked_senders[sender] = {'reason': reason, 'blocked_at': datetime.now().isoformat()}
            self.stats['emails_blocked'] += 1
            logger.warning(f"📧 BLOCKED EMAILS from: {sender}")
            return True
        except Exception as e:
            logger.error(f"SMTP block error: {e}")
            return False

    # ============================================================
    # HELPERS
    # ============================================================
    def _extract_url(self, ctx):
        if isinstance(ctx, str):
            if '{' in ctx:
                try:
                    import ast
                    d = ast.literal_eval(ctx)
                    if isinstance(d, dict): return d.get('url', d.get('full_url', ''))
                except: pass
            return ctx
        if isinstance(ctx, dict): return ctx.get('url', ctx.get('full_url', ''))
        return str(ctx)

    def _extract_domain(self, url):
        try:
            parsed = urlparse(url)
            return parsed.netloc or parsed.path.split('/')[0]
        except:
            return url.replace('http://', '').replace('https://', '').split('/')[0]

    def _is_private_ip(self, ip):
        """Check if IP is private - ALLOWS blocking on local networks"""
        try:
            parts = [int(x) for x in ip.split('.')]
            # 10.0.0.0/8 - Hotspot network - ALLOW blocking
            if parts[0] == 10:
                return False
            # 172.16.0.0/12
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return False
            # 192.168.0.0/16 - Home network - ALLOW blocking
            if parts[0] == 192 and parts[1] == 168:
                return False
            # 127.0.0.0/8 - Loopback only - skip
            if parts[0] == 127:
                return True
            return False
        except:
            return False

    def _is_loopback(self, ip):
        """Check if IP is loopback only"""
        try:
            parts = [int(x) for x in ip.split('.')]
            return parts[0] == 127
        except:
            return True

    def _cleanup_loop(self):
        while self.running:
            try:
                now = datetime.now()
                expired = []
                with self.block_lock:
                    for ip, info in self.blocked_ips.items():
                        if info.get('expires_at') and now >= datetime.fromisoformat(info['expires_at']):
                            expired.append(ip)
                for ip in expired: self.unblock_ip(ip)
                time.sleep(60)
            except: time.sleep(60)

    def get_blocked_ips(self):
        with self.block_lock: return dict(self.blocked_ips)

    def get_blocked_urls(self):
        with self.block_lock: return dict(self.blocked_urls)

    def get_statistics(self):
        return self.stats.copy()

    def flush_all_blocks(self):
        if self.is_linux and not self.simulation_mode:
            os.system("sudo iptables -F 2>/dev/null")
            os.system("sudo iptables -t nat -F 2>/dev/null")
        with self.block_lock:
            self.blocked_ips.clear()
            self.blocked_urls.clear()
            self.blocked_senders.clear()
        self.stats['active_blocks'] = 0
#!/usr/bin/env python3
"""
CyberShield - Raspberry Pi Detection Node
sudo python3 run_remote.py -i wlan0 -s http://192.168.10.73:5000
"""

import sys
import os
import time
import logging
import requests
import subprocess
import re
from datetime import datetime
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from capture_layer.packet_capture import PacketCapture
from detection_engine.url_scanner.url_classifier import URLDetector
from detection_engine.email_phishing.email_classifier import EmailDetector
from detection_engine.app_layer_detector.payload_analyzer import AppAttackDetector
from detection_engine.dpi_model.anomaly_detector import DPIDetector
from detection_engine.url_scanner.url_extractor import URLExtractor
from detection_engine.email_phishing.email_extractor import EmailExtractor
from detection_engine.scoring_engine import ScoringEngine
from detection_engine.prevention_engine import PreventionEngine
from data_layer.database.db_manager import Database

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

SERVER_URL = "http://192.168.10.73:5000"
API_KEY = "cybershield-secret-key"
PI_NAME = "Pi-Gateway"

# Pi's own IPs - never block these
PI_OWN_IPS = ['127.0.0.1', '10.42.0.1', '192.168.10.95', '0.0.0.0', 'localhost']

WHITELIST_DOMAINS = [
    'gstatic.com', 'googleapis.com', 'google.com', 'googleusercontent.com',
    'facebook.com', 'fbcdn.net', 'instagram.com', 'discord.gg',
    'snapchat.com', 'brave.com', 'microsoft.com', 'microsoftpersonalcontent.com',
    'notion.so', 'openai.com', 'cloudflare.com', 'github.com',
    'vscode-cdn.net', 'deepseek.com', 'sentry.io', 'revenuecat.com',
    'splunkcloud.com', 'datadoghq.com', 'tiktokpangle.us', 'pangle.io',
    'pglstatp.com', 'capcutapi.com', 'xiaomi.net', 'miui.com',
    'mediatek.com', 'sourceforge.net', 'softonic.com', 'uptodown.com',
    'doubleclick.net', 'app-measurement.com', 'crashlytics.com',
    '3gppnetwork.org', 'identrust.com', 'cdnjs.cloudflare.com',
    'volccdn.com', 'gvt2.com', 'gcp.gvt2.com', 'local', 'arpa',
    'googlevideo.com', 'whatsapp.net', 'msftconnecttest.com',
    'windows.com', 'githubcopilot.com', 'discord.media', 'azure.com',
    'freedownloadmanager.org', 'visualstudio.com', 'vscode-unpkg.net',
    'exp-tas.com', 'tiktokv.com', 'tiktokcdn.com', 'appsflyersdk.com',
    'fastly-edge.com', 'windowsupdate.com', 'microsoft.com',
    'kaspersky.com', 'kaspersky-labs.com', 'digicert.com', 'akamaized.net',
    'akamai.net', 'msn.com', 'xboxlive.com', 'skype.com',
    'office.com', 'azureedge.net', 'azure.com', 'worldlink.com.np'
]


class PiDetectionNode:
    def __init__(self, interface='wlan0'):
        self.interface = interface
        self.stats = {
            'pkts': 0, 'urls': 0, 'emails': 0, 'payloads': 0, 'flows': 0,
            'alerts': 0, 'sent': 0, 'blocked': 0, 'urls_blocked': 0, 'emails_blocked': 0
        }
        self.dpi_alert_count = {}
        self.pps_history = []
        self._last_pps_alert = 0
        self._rate_limit_applied = False

        logger.info("=" * 50)
        logger.info(" INITIALIZING PI DETECTION NODE")
        logger.info("=" * 50)

        self.db = Database('threats_local.db')
        logger.info("+ Local backup DB")

        self.url_det = URLDetector('models/url/rf_url_model.pkl', 'models/url/feature_columns.pkl', 'models/url/label_encoder.pkl')
        self.email_det = EmailDetector('models/email/phishing_model.pkl')
        self.app_det = AppAttackDetector('models/app_attack/web_attack_rf.pkl', 'models/app_attack/tfidf_vectorizer.pkl', 'models/app_attack/label_encoder.pkl')
        self.dpi_det = DPIDetector('models/dpi/dpi_rf_pipeline.pkl')
        logger.info("+ 4 ML Models loaded")

        self.url_extractor = URLExtractor()
        self.email_extractor = EmailExtractor()

        self.scorer = ScoringEngine()
        self.blocker = PreventionEngine(db_manager=self.db, simulation_mode=False)
        self.blocker.start()
        logger.info("+ Scoring & Prevention ready")

        self.capture = PacketCapture(interface=interface, promiscuous=True)
        self.capture.register_callback('http_request', self._on_http)
        self.capture.register_callback('smtp_data', self._on_email)
        self.capture.register_callback('flow_stats', self._on_flow)
        self.capture.register_callback('dns_query', self._on_dns)

        logger.info(f"+ Capture ready on {interface}")
        logger.info(f"+ Server: {SERVER_URL}")
        logger.info("=" * 50)

    # ============================================================
    # ALERT SENDING
    # ============================================================
    def _send(self, data):
        try:
            data['api_key'] = API_KEY
            data['pi_name'] = PI_NAME
            r = requests.post(f"{SERVER_URL}/api/remote_alert", json=data, timeout=3)
            if r.status_code == 200:
                self.stats['sent'] += 1
                return True
        except:
            pass
        return False

    def _extract_url_from_context(self, ctx):
        if isinstance(ctx, dict):
            return ctx.get('url', ctx.get('full_url', ''))
        return str(ctx)

    def _extract_domain(self, url):
        try:
            parsed = urlparse(url)
            return parsed.netloc or parsed.path.split('/')[0]
        except:
            return url.replace('http://', '').replace('https://', '').split('/')[0]

    def _is_whitelisted(self, domain):
        return any(w in domain.lower() for w in WHITELIST_DOMAINS)

    def _is_pi_ip(self, ip):
        """Check if this is the Pi's own IP"""
        return ip in PI_OWN_IPS

    # ============================================================
    # DoS DETECTION
    # ============================================================
    def _get_syn_stats(self):
        """Get SYN vs ESTABLISHED connection counts"""
        try:
            result_syn = subprocess.run(['ss', '-tn', 'state', 'syn-recv'],
                                      capture_output=True, text=True, timeout=3)
            syn_count = len([l for l in result_syn.stdout.split('\n') if '10.42.0.' in l or '192.168.' in l])

            result_est = subprocess.run(['ss', '-tn', 'state', 'established'],
                                      capture_output=True, text=True, timeout=3)
            est_count = len([l for l in result_est.stdout.split('\n') if '10.42.0.' in l or '192.168.' in l])

            return syn_count, est_count
        except:
            return 0, 0

    def _block_top_attacker(self):
        """Find and block the IP generating most SYN traffic"""
        blocked = None
        try:
            result = subprocess.run(['ss', '-tn', 'state', 'syn-recv'],
                                  capture_output=True, text=True, timeout=5)
            ip_counts = {}
            target_ports = {}
            for line in result.stdout.split('\n'):
                matches = re.findall(r'(\d+\.\d+\.\d+\.\d+):(\d+)', line)
                for ip, port in matches:
                    if self._is_pi_ip(ip):
                        continue
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
                    target_ports[port] = target_ports.get(port, 0) + 1

            if ip_counts:
                top_ip = max(ip_counts, key=ip_counts.get)
                count = ip_counts[top_ip]
                top_port = max(target_ports, key=target_ports.get) if target_ports else 'unknown'
                if count > 5:
                    logger.warning(f" 🛑 DoS Attack! Attacker: {top_ip} | SYN: {count} | Port: {top_port}")
                    self.blocker.block_ip(top_ip, f"DoS on port {top_port} ({count} SYN)", 'critical')
                    self.stats['blocked'] += 1
                    if top_port.isdigit():
                        self._apply_rate_limit(port=int(top_port))
                    return top_ip
        except Exception as e:
            logger.error(f"Error finding attacker: {e}")

        # Fallback: Check ALL connections
        if not blocked:
            try:
                result = subprocess.run(['ss', '-tn'], capture_output=True, text=True, timeout=5)
                ip_counts = {}
                for line in result.stdout.split('\n'):
                    matches = re.findall(r'(\d+\.\d+\.\d+\.\d+):\d+', line)
                    for ip in matches:
                        if self._is_pi_ip(ip):
                            continue
                        ip_counts[ip] = ip_counts.get(ip, 0) + 1
                if ip_counts:
                    top_ip = max(ip_counts, key=ip_counts.get)
                    count = ip_counts[top_ip]
                    if count > 20:
                        logger.warning(f" 🛑 Blocking {top_ip} ({count} total connections)")
                        self.blocker.block_ip(top_ip, f"DoS: {count} connections", 'critical')
                        self.stats['blocked'] += 1
                        return top_ip
            except Exception as e:
                logger.error(f"Fallback failed: {e}")

        # Emergency: Global rate limit
        if not blocked:
            logger.warning(" 🛑 Emergency rate limit applied!")
            os.system("sudo iptables -A INPUT -p tcp -m limit --limit 10/second -j ACCEPT 2>/dev/null")
            os.system("sudo iptables -A INPUT -p tcp -j DROP 2>/dev/null")
            self._rate_limit_applied = True
        return blocked

    def _apply_rate_limit(self, port=None):
        if self._rate_limit_applied:
            return
        ports = [port] if port else [22, 53, 80, 443, 8000, 8080, 8443]
        for p in ports:
            os.system(f"sudo iptables -A INPUT -p tcp --dport {p} -m limit --limit 50/second -j ACCEPT 2>/dev/null")
            os.system(f"sudo iptables -A INPUT -p tcp --dport {p} -j DROP 2>/dev/null")
        os.system("sudo iptables -A INPUT -p tcp -m connlimit --connlimit-above 100 -j DROP 2>/dev/null")
        self._rate_limit_applied = True
        logger.warning(" 🛑 Rate limiting applied")

    def _remove_rate_limit(self, port=None):
        if not self._rate_limit_applied:
            return
        ports = [port] if port else [22, 53, 80, 443, 8000, 8080, 8443]
        for p in ports:
            os.system(f"sudo iptables -D INPUT -p tcp --dport {p} -m limit --limit 50/second -j ACCEPT 2>/dev/null")
            os.system(f"sudo iptables -D INPUT -p tcp --dport {p} -j DROP 2>/dev/null")
        os.system("sudo iptables -D INPUT -p tcp -m connlimit --connlimit-above 100 -j DROP 2>/dev/null")
        self._rate_limit_applied = False
        logger.info("Rate limit removed")

    # ============================================================
    # THREAT PROCESSING
    # ============================================================
    def _process_threat(self, result, ip, ctx):
        self.stats['alerts'] += 1
        assessment = self.scorer.evaluate_threat(result, source_ip=ip)
        self.db.insert_alert(
            module=result['module'], detection_type=result['label'],
            confidence=result['confidence'], source_ip=ip,
            details=str(ctx)[:500], action_taken=assessment['action'],
            is_blocked=1 if assessment['action'] == 'block_immediately' else 0
        )
        blocked_type, blocked_target = None, None
        if assessment['action'] in ['block_immediately', 'block_after_confirm']:
            if result['module'] == 'url':
                blocked_type, blocked_target = self.blocker.smart_block(result, ip, ctx)
                if blocked_type == 'URL': self.stats['urls_blocked'] += 1
            elif result['module'] == 'app_attack':
                blocked_type, blocked_target = self.blocker.smart_block(result, ip, ctx)
                if blocked_type == 'IP': self.stats['blocked'] += 1
            elif result['module'] == 'dpi':
                blocked_type, blocked_target = self.blocker.smart_block(result, ip, ctx)
                if blocked_type == 'IP': self.stats['blocked'] += 1
        alert_data = {
            'module': result['module'], 'type': result['label'],
            'confidence': result['confidence'], 'severity': assessment['severity'],
            'source_ip': ip, 'details': str(ctx)[:300], 'action': assessment['action'],
            'blocked_type': blocked_type, 'blocked_target': str(blocked_target) if blocked_target else None,
            'timestamp': datetime.now().isoformat()
        }
        if result['module'] == 'url':
            url = self._extract_url_from_context(ctx)
            if url:
                alert_data['phishing_url'] = url
                alert_data['phishing_domain'] = self._extract_domain(url)
        self._send(alert_data)
        block_emoji = {'URL': '🔗', 'IP': '🛑', 'EMAIL': '📧'}.get(blocked_type, '')
        logger.info(f" 📤 {block_emoji} [{result['module']}] {result['label']} ({result['confidence']:.0%}) from {ip}")

    # ============================================================
    # PACKET HANDLERS
    # ============================================================
    def _on_http(self, http_data):
        self.stats['pkts'] += 1
        urls = self.url_extractor.extract_urls_from_http(http_data)
        for url_info in urls:
            url = url_info.get('url', '')
            domain = self._extract_domain(url)
            if self._is_whitelisted(domain):
                continue
            if self.url_extractor.should_scan_url(url):
                self.stats['urls'] += 1
                result = self.url_det.predict(url)
                if result['label'] not in ['benign', 'legitimate'] and result['confidence'] > 0.8:
                    self._process_threat(result, http_data.get('source_ip'), url_info)
        body = http_data.get('body', '')
        uri = http_data.get('uri', '')
        payload_to_check = body if body else uri
        if payload_to_check:
            self.stats['payloads'] += 1
            result = self.app_det.detect(payload_to_check)
            if result['label'] not in ['benign', 'normal'] and result['confidence'] > 0.7:
                self._process_threat(result, http_data.get('source_ip'), http_data)

    def _on_email(self, email_data):
        if email_data.get('type') != 'email':
            return
        self.stats['emails'] += 1
        text = f"{email_data.get('subject', '')} {email_data.get('body', '')}"
        result = self.email_det.predict(text)
        if result['label'] == 'phishing':
            self._process_threat(result, email_data.get('source_ip'), email_data)

    def _on_flow(self, flow_data):
        self.stats['flows'] += 1
        if flow_data.get('data'):
            features = flow_data['data'].copy()
            features.pop('src_ip', None); features.pop('dst_ip', None)
            features.pop('src_port', None); features.pop('dst_port', None)
            result = self.dpi_det.predict(features)
            if result['label'] == 'anomaly' and result['confidence'] > 0.7:
                src_ip = flow_data.get('metadata', {}).get('src_ip', 'unknown')
                self.dpi_alert_count[src_ip] = self.dpi_alert_count.get(src_ip, 0) + 1
                count = self.dpi_alert_count[src_ip]
                self.db.insert_alert(
                    module='dpi', detection_type='anomaly',
                    confidence=result['confidence'], source_ip=src_ip,
                    details=f'DPI anomaly #{count}',
                    action_taken='blocked' if count >= 3 else 'log_only',
                    is_blocked=1 if count >= 3 else 0
                )
                if count >= 3:
                    logger.warning(f" 🛑 [dpi] anomaly #{count} from {src_ip} - BLOCKING!")
                    self._process_threat(result, src_ip, flow_data)
                elif count >= 2:
                    logger.warning(f" ⚠️ [dpi] anomaly #{count} from {src_ip} - warning")
                else:
                    logger.info(f" 📊 [dpi] anomaly #{count} from {src_ip} (log only)")

    def _on_dns(self, data):
        try:
            if data.get('suspicious'):
                domain = data.get('domain', '')
                if domain and not self._is_whitelisted(domain):
                    logger.warning(f"Suspicious DNS: {domain}")
        except:
            pass

    # ============================================================
    # MAIN LOOP
    # ============================================================
    def start(self):
        self.capture.start()
        logger.info(f"Listening on {self.interface} → {SERVER_URL}")
        try:
            while True:
                time.sleep(10)
                s = self.capture.get_statistics()
                total_pps = s.get('packets_per_second', 0)
                self.pps_history.append(total_pps)
                if len(self.pps_history) > 6:
                    self.pps_history.pop(0)
                avg_pps = sum(self.pps_history) / len(self.pps_history) if self.pps_history else 0

                syn_count, est_count = self._get_syn_stats()
                total_conn = syn_count + est_count
                syn_ratio = syn_count / total_conn if total_conn > 0 else 0

                logger.info(f"Pkts:{s['total_packets']} HTTP:{s['http_packets']} "
                           f"DNS:{s['dns_packets']} | PPS:{total_pps:.0f} | "
                           f"SYN:{syn_count} EST:{est_count} | "
                           f"Alerts:{self.stats['alerts']} Blocked:{self.stats['blocked']}")

                # SMART DoS Detection
                if avg_pps > 150 and syn_ratio > 0.5 and syn_count > 10:
                    if time.time() - self._last_pps_alert > 15:
                        self._last_pps_alert = time.time()
                        logger.warning(f" 🛑 DoS ATTACK! PPS:{avg_pps:.0f} SYN:{syn_count} Ratio:{syn_ratio:.2f}")
                        
                        attacker_ip = self._block_top_attacker() or 'network'
                        
                        self.db.insert_alert(
                            module='dpi', detection_type='dos_attack',
                            confidence=min(0.7 + syn_ratio, 0.95),
                            source_ip=attacker_ip,
                            details=f'DoS: {avg_pps:.0f} PPS, SYN ratio: {syn_ratio:.2f}',
                            action_taken='block_immediately', is_blocked=1
                        )
                        
                        # SEND TO DASHBOARD
                        self._send({
                            'module': 'dpi', 'type': 'dos_attack',
                            'confidence': min(0.7 + syn_ratio, 0.95),
                            'severity': 'critical',
                            'source_ip': attacker_ip,
                            'details': f'DoS Attack: {avg_pps:.0f} PPS, {syn_count} SYN',
                            'action': 'block_immediately',
                            'blocked_type': 'IP',
                            'blocked_target': attacker_ip,
                            'timestamp': datetime.now().isoformat()
                        })
                        self.stats['alerts'] += 1
                        self.stats['blocked'] += 1
                        
                elif avg_pps > 150 and syn_ratio < 0.5:
                    logger.info(f" 📺 High traffic (streaming): {avg_pps:.0f} PPS - ignoring")

                if avg_pps < 100 and self._rate_limit_applied:
                    self._remove_rate_limit()

        except KeyboardInterrupt:
            self.capture.stop()
            self.blocker.stop()
            if self._rate_limit_applied:
                self._remove_rate_limit()
            logger.info("Stopped")


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('-i', '--interface', default='wlan0')
    p.add_argument('-s', '--server', default='http://192.168.10.73:5000')
    args = p.parse_args()
    SERVER_URL = args.server
    PiDetectionNode(interface=args.interface).start()
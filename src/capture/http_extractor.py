from scapy.layers import http, tls
import re
from urllib.parse import urlparse, parse_qs
import json


class HTTPExtractor:
    """
    Extract HTTP/HTTPS request/response data for threat detection
    Extracts URLs, headers, payloads, SNI, and metadata
    """
    
    def __init__(self):
        self.suspicious_headers = [
            'X-Forwarded-For', 'X-Real-IP', 'X-Forwarded-Host'
        ]
        
        self.malicious_user_agents = [
            'sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab',
            'gobuster', 'dirbuster', 'burpsuite', 'acunetix'
        ]
    
    def extract_request(self, packet):
        """Extract HTTP request data from packet"""
        try:
            http_layer = packet[http.HTTPRequest]
            
            method = http_layer.Method.decode() if http_layer.Method else 'UNKNOWN'
            host = http_layer.Host.decode() if http_layer.Host else ''
            uri = http_layer.Path.decode() if http_layer.Path else ''
            user_agent = http_layer.User_Agent.decode() if http_layer.User_Agent else ''
            
            full_url = f"http://{host}{uri}" if host else uri
            
            headers = {}
            if hasattr(http_layer, 'fields'):
                for field in http_layer.fields:
                    try:
                        name = field.decode() if isinstance(field, bytes) else field
                        value = http_layer.fields[field].decode()
                        headers[name] = value
                    except:
                        continue
            
            query_params = {}
            if '?' in uri:
                query_string = uri.split('?')[1] if '?' in uri else ''
                query_params = parse_qs(query_string)
            
            body = ''
            if hasattr(http_layer, 'payload') and http_layer.payload:
                try:
                    body = http_layer.payload.load.decode('utf-8', errors='ignore')
                except:
                    body = str(http_layer.payload)
            
            json_body = None
            if body and body.strip().startswith('{'):
                try:
                    json_body = json.loads(body)
                except:
                    pass
            
            suspicious = False
            suspicious_reasons = []
            
            if any(agent in user_agent.lower() for agent in self.malicious_user_agents):
                suspicious = True
                suspicious_reasons.append(f'Malicious user agent: {user_agent}')
            
            for header in self.suspicious_headers:
                if header in headers:
                    suspicious = True
                    suspicious_reasons.append(f'Suspicious header: {header}')
            
            if self._contains_attack_patterns(uri):
                suspicious = True
                suspicious_reasons.append('Attack patterns in URI')
            
            if body and self._contains_attack_patterns(body):
                suspicious = True
                suspicious_reasons.append('Attack patterns in body')
            
            src_ip = packet['IP'].src if packet.haslayer('IP') else None
            dst_ip = packet['IP'].dst if packet.haslayer('IP') else None
            src_port = packet['TCP'].sport if packet.haslayer('TCP') else None
            dst_port = packet['TCP'].dport if packet.haslayer('TCP') else None
            
            return {
                'type': 'http_request',
                'method': method,
                'host': host,
                'uri': uri,
                'full_url': full_url,
                'headers': headers,
                'user_agent': user_agent,
                'query_params': query_params,
                'body': body,
                'json_body': json_body,
                'content_type': headers.get('Content-Type', ''),
                'content_length': len(body),
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'source_port': src_port,
                'destination_port': dst_port,
                'suspicious': suspicious,
                'suspicious_reasons': suspicious_reasons,
                'is_https': False,
                'timestamp': packet.time
            }
        except Exception as e:
            # Try HTTPS/TLS extraction
            return self._extract_tls_sni(packet)
    
    def extract_response(self, packet):
        """Extract HTTP response data from packet"""
        try:
            http_layer = packet[http.HTTPResponse]
            
            status_code = http_layer.Status_Code.decode() if http_layer.Status_Code else '000'
            reason = http_layer.Reason.decode() if http_layer.Reason else ''
            
            body = ''
            if hasattr(http_layer, 'payload') and http_layer.payload:
                try:
                    body = http_layer.payload.load.decode('utf-8', errors='ignore')
                except:
                    body = str(http_layer.payload)
            
            return {
                'type': 'http_response',
                'status_code': int(status_code) if status_code.isdigit() else 0,
                'reason': reason,
                'body': body[:1000],
                'content_length': len(body),
                'source_ip': packet['IP'].src if packet.haslayer('IP') else None,
                'destination_ip': packet['IP'].dst if packet.haslayer('IP') else None,
                'is_https': False,
                'timestamp': packet.time
            }
        except Exception as e:
            # Try HTTPS/TLS
            return self._extract_tls_sni(packet)
    
    def _extract_tls_sni(self, packet):
        """
        Extract SNI (Server Name Indication) from TLS Client Hello
        This works for HTTPS traffic (port 443)
        """
        try:
            if not packet.haslayer('TCP'):
                return None
            
            src_ip = packet['IP'].src if packet.haslayer('IP') else None
            dst_ip = packet['IP'].dst if packet.haslayer('IP') else None
            src_port = packet['TCP'].sport if packet.haslayer('TCP') else None
            dst_port = packet['TCP'].dport if packet.haslayer('TCP') else None
            
            # Try to extract SNI from TLS Client Hello
            sni = None
            if hasattr(packet, 'payload'):
                raw = bytes(packet.payload)
                # TLS Client Hello starts with 0x16 0x03
                if len(raw) > 5 and raw[0] == 0x16 and raw[1] == 0x03:
                    # Try to find SNI extension (type 0x00 0x00)
                    try:
                        # Skip to extensions
                        session_id_length = raw[43]
                        pos = 44 + session_id_length
                        if pos + 2 < len(raw):
                            cipher_suites_length = int.from_bytes(raw[pos:pos+2], 'big')
                            pos += 2 + cipher_suites_length
                            if pos + 1 < len(raw):
                                compression_length = raw[pos]
                                pos += 1 + compression_length
                                if pos + 2 < len(raw):
                                    extensions_length = int.from_bytes(raw[pos:pos+2], 'big')
                                    pos += 2
                                    end_pos = pos + extensions_length
                                    while pos + 4 <= end_pos and pos + 4 < len(raw):
                                        ext_type = int.from_bytes(raw[pos:pos+2], 'big')
                                        ext_len = int.from_bytes(raw[pos+2:pos+4], 'big')
                                        if ext_type == 0x0000:  # SNI extension
                                            sni_data = raw[pos+4:pos+4+ext_len]
                                            if len(sni_data) > 5:
                                                sni_len = int.from_bytes(sni_data[3:5], 'big')
                                                sni = sni_data[5:5+sni_len].decode('utf-8', errors='ignore')
                                            break
                                        pos += 4 + ext_len
                    except:
                        pass
            
            if sni:
                return {
                    'type': 'https_request',
                    'method': 'TLS',
                    'host': sni,
                    'uri': '/',
                    'full_url': f'https://{sni}/',
                    'headers': {},
                    'user_agent': '',
                    'query_params': {},
                    'body': '',
                    'json_body': None,
                    'content_type': '',
                    'content_length': 0,
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'source_port': src_port,
                    'destination_port': dst_port,
                    'suspicious': False,
                    'suspicious_reasons': [],
                    'is_https': True,
                    'sni': sni,
                    'timestamp': packet.time
                }
            
            return None
            
        except Exception as e:
            return None
    
    def _contains_attack_patterns(self, text):
        """Check if text contains common web attack patterns"""
        patterns = [
            # SQL Injection
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
            r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
            r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
            r"((\%27)|(\'))union",
            # XSS
            r"((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)",
            r"<script[^>]*>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            # Command Injection
            r"[;&|]\s*(ls|cat|pwd|id|whoami|uname)",
            r"\$\{.*\}",
            r"`[^`]*`",
            # Path Traversal
            r"\.\.\/",
            r"\.\.\\",
            r"\/etc\/passwd",
            r"C:\\Windows\\System32"
        ]
        
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
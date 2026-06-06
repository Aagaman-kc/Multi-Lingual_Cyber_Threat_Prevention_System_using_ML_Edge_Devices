from scapy.layers import dns
import re
from collections import defaultdict


class DNSExtractor:
    """Extract DNS query/response data for threat detection"""
    
    def __init__(self):
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq',
            '.xyz', '.top', '.club', '.work', '.click'
        ]
        
        self.tunneling_indicators = ['base64', 'encoded', 'tunnel']
        
        # EXPANDED whitelist
        self.whitelist_domains = [
            'gstatic.com', 'googleapis.com', 'google.com', 'googleusercontent.com',
            'facebook.com', 'fbcdn.net', 'instagram.com', 'discord.gg',
            'snapchat.com', 'brave.com', 'microsoft.com', 'notion.so',
            'openai.com', 'cloudflare.com', 'github.com', 'deepseek.com',
            'sentry.io', 'revenuecat.com', 'splunkcloud.com', 'datadoghq.com',
            'tiktokpangle.us', 'pangle.io', 'pglstatp.com', 'capcutapi.com',
            'xiaomi.net', 'miui.com', 'mediatek.com', 'sourceforge.net',
            'softonic.com', 'uptodown.com', 'doubleclick.net', 'app-measurement.com',
            'crashlytics.com', 'volccdn.com', 'gvt2.com', 'identrust.com',
            'cdnjs.cloudflare.com', 'gcp.gvt2.com',
            # Local network
            'local', 'arpa', 'googlevideo.com', 'whatsapp.net',
            'msftconnecttest.com', 'windows.com', 'githubcopilot.com','windowsupdate.com', 'windows.com', 'microsoft.com',
            'kaspersky.com', 'kaspersky-labs.com',
            'digicert.com', 'akamaized.net', 'akamai.net',
            'msn.com', 'xboxlive.com', 'skype.com',
            'office.com', 'azureedge.net', 'azure.com',
            'worldlink.com.np'
        ]
        
        self.domain_query_count = defaultdict(int)
        self.domain_query_times = defaultdict(list)
        self.high_entropy_domains = set()
    
    def _is_whitelisted(self, domain):
        domain_lower = domain.lower()
        return any(w in domain_lower for w in self.whitelist_domains)
    
    def extract_query(self, packet):
        """Extract DNS query data"""
        try:
            dns_layer = packet[dns.DNS]
            
            # FIXED: UTF-8 decode with error handling
            try:
                query_name = dns_layer[dns.DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
            except:
                try:
                    query_name = dns_layer[dns.DNSQR].qname.decode('latin-1', errors='ignore').rstrip('.')
                except:
                    query_name = str(dns_layer[dns.DNSQR].qname).rstrip('.')
            
            query_type = dns_layer[dns.DNSQR].qtype
            
            if self._is_whitelisted(query_name):
                return {
                    'type': 'dns_query',
                    'domain': query_name,
                    'query_type': query_type,
                    'suspicious': False,
                    'suspicious_reasons': [],
                    'source_ip': packet['IP'].src if packet.haslayer('IP') else None,
                    'timestamp': packet.time
                }
            
            self.domain_query_count[query_name] += 1
            self.domain_query_times[query_name].append(packet.time)
            
            suspicious = False
            suspicious_reasons = []
            
            if any(query_name.endswith(tld) for tld in self.suspicious_tlds):
                suspicious = True
                suspicious_reasons.append(f'Suspicious TLD: {query_name.split(".")[-1]}')
            
            if len(query_name) > 100:
                suspicious = True
                suspicious_reasons.append(f'Long domain: {len(query_name)} chars')
            
            if len(query_name) < 50:
                entropy = self._calculate_entropy(query_name)
                if entropy > 3.5:
                    suspicious = True
                    suspicious_reasons.append(f'High entropy: {entropy:.2f}')
                    self.high_entropy_domains.add(query_name)
            
            subdomain_count = query_name.count('.')
            if subdomain_count > 5 and not any(cdn in query_name for cdn in ['cdn', 'static', 'api']):
                suspicious = True
                suspicious_reasons.append(f'Excessive subdomains: {subdomain_count}')
            
            for indicator in self.tunneling_indicators:
                if indicator in query_name.lower():
                    suspicious = True
                    suspicious_reasons.append(f'Suspicious keyword: {indicator}')
            
            return {
                'type': 'dns_query',
                'domain': query_name,
                'query_type': query_type,
                'suspicious': suspicious,
                'suspicious_reasons': suspicious_reasons,
                'entropy': self._calculate_entropy(query_name) if len(query_name) < 50 else 0,
                'query_count': self.domain_query_count[query_name],
                'source_ip': packet['IP'].src if packet.haslayer('IP') else None,
                'destination_ip': packet['IP'].dst if packet.haslayer('IP') else None,
                'timestamp': packet.time
            }
        except Exception as e:
            print(f"Error extracting DNS query: {e}")
            return None
    
    def extract_response(self, packet):
        try:
            dns_layer = packet[dns.DNS]
            query_name = dns_layer[dns.DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
            
            resolved_ips = []
            if dns_layer.an:
                for answer in dns_layer.an:
                    if hasattr(answer, 'rdata'):
                        resolved_ips.append(str(answer.rdata))
            
            return {
                'type': 'dns_response',
                'domain': query_name,
                'resolved_ips': resolved_ips,
                'source_ip': packet['IP'].src if packet.haslayer('IP') else None,
                'destination_ip': packet['IP'].dst if packet.haslayer('IP') else None,
                'timestamp': packet.time
            }
        except Exception as e:
            print(f"Error extracting DNS response: {e}")
            return None
    
    def _calculate_entropy(self, text):
        import math
        if not text:
            return 0
        entropy = 0
        for char in set(text):
            prob = text.count(char) / len(text)
            entropy -= prob * math.log2(prob)
        return entropy
    
    def get_domain_stats(self):
        return {
            'total_unique_domains': len(self.domain_query_count),
            'high_entropy_domains': list(self.high_entropy_domains),
            'most_queried': sorted(self.domain_query_count.items(), key=lambda x: x[1], reverse=True)[:10]
        }
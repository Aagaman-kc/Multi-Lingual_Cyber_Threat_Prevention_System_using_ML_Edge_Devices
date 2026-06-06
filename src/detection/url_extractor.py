import re
from urllib.parse import urlparse
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class URLExtractor:
    """
    Extract and preprocess URLs from captured traffic
    Feeds URLs to the URLDetector ML model
    """
    
    def __init__(self):
        # URL regex pattern (comprehensive)
        self.url_pattern = re.compile(
            r'(?:http|https|ftp)://'
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            r'(?::\d+)?'
            r'(?:/?|[/?]\S+)',
            re.IGNORECASE
        )
        
        # Shortened URL services
        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
            'is.gd', 'buff.ly', 'adf.ly', 'shorte.st', 'bc.vc',
            'tiny.cc', 'tr.im', 'cli.gs', 'u.to', 'v.gd'
        ]
        
        # Known safe domains (EXPANDED whitelist)
        self.whitelist_domains = [
            # Original
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'github.com', 'stackoverflow.com', 'wikipedia.org',
            'youtube.com', 'linkedin.com', 'twitter.com',
            # CDN & API domains
            'gstatic.com', 'googleapis.com', 'googleusercontent.com',
            'facebook.com', 'fbcdn.net', 'instagram.com', 'discord.gg',
            'snapchat.com', 'brave.com', 'notion.so', 'openai.com',
            'cloudflare.com', 'deepseek.com', 'sentry.io',
            'revenuecat.com', 'splunkcloud.com', 'datadoghq.com',
            'tiktokpangle.us', 'pangle.io', 'capcutapi.com',
            'xiaomi.net', 'miui.com', 'mediatek.com', 'sourceforge.net',
            'softonic.com', 'uptodown.com', 'doubleclick.net',
            'crashlytics.com', 'volccdn.com', 'gvt2.com',
            'identrust.com', 'cdnjs.cloudflare.com', 'httpbin.org',
            'neverssl.com', 'httpforever.com'
        ]
        
        self.url_queue = []
    
    def extract_urls_from_http(self, http_data):
        """Extract URLs from HTTP request/response data"""
        urls = []
        
        try:
            if 'full_url' in http_data and http_data['full_url']:
                urls.append({
                    'url': http_data['full_url'],
                    'source': 'http_request',
                    'method': http_data.get('method', 'GET'),
                    'source_ip': http_data.get('source_ip'),
                    'destination_ip': http_data.get('destination_ip'),
                    'user_agent': http_data.get('user_agent', ''),
                    'timestamp': http_data.get('timestamp')
                })
            
            if 'query_params' in http_data:
                for param, values in http_data['query_params'].items():
                    for value in values:
                        found_urls = self._find_urls_in_text(value)
                        for url in found_urls:
                            urls.append({
                                'url': url,
                                'source': 'query_parameter',
                                'parameter': param,
                                'source_ip': http_data.get('source_ip'),
                                'destination_ip': http_data.get('destination_ip'),
                                'timestamp': http_data.get('timestamp')
                            })
            
            if 'body' in http_data and http_data['body']:
                found_urls = self._find_urls_in_text(http_data['body'])
                for url in found_urls:
                    urls.append({
                        'url': url,
                        'source': 'request_body',
                        'source_ip': http_data.get('source_ip'),
                        'destination_ip': http_data.get('destination_ip'),
                        'timestamp': http_data.get('timestamp')
                    })
            
            if 'headers' in http_data:
                location = http_data['headers'].get('Location', '')
                if location:
                    urls.append({
                        'url': location,
                        'source': 'redirect',
                        'source_ip': http_data.get('source_ip'),
                        'destination_ip': http_data.get('destination_ip'),
                        'timestamp': http_data.get('timestamp')
                    })
        
        except Exception as e:
            logger.error(f"Error extracting URLs from HTTP: {e}")
        
        return urls
    
    def extract_urls_from_email(self, email_data):
        """Extract URLs from email data"""
        urls = []
        
        try:
            if 'urls_found' in email_data:
                for url in email_data['urls_found']:
                    urls.append({
                        'url': url,
                        'source': 'email_body',
                        'sender': email_data.get('sender', ''),
                        'subject': email_data.get('subject', ''),
                        'source_ip': email_data.get('source_ip'),
                        'timestamp': email_data.get('timestamp')
                    })
        except Exception as e:
            logger.error(f"Error extracting URLs from email: {e}")
        
        return urls
    
    def extract_urls_from_dns(self, dns_data):
        """Track resolved domains from DNS responses"""
        urls = []
        
        try:
            if dns_data.get('type') == 'dns_response':
                domain = dns_data.get('domain', '')
                resolved_ips = dns_data.get('resolved_ips', [])
                
                for ip in resolved_ips:
                    if self._is_suspicious_ip(ip):
                        urls.append({
                            'url': f"http://{domain}",
                            'source': 'dns_suspicious_resolution',
                            'resolved_ip': ip,
                            'source_ip': dns_data.get('source_ip'),
                            'timestamp': dns_data.get('timestamp')
                        })
        except Exception as e:
            logger.error(f"Error extracting URLs from DNS: {e}")
        
        return urls
    
    def _find_urls_in_text(self, text):
        """Find all URLs in a text string"""
        return self.url_pattern.findall(text)
    
    def _is_suspicious_ip(self, ip):
        """Check if an IP address is suspicious"""
        private_ranges = [
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255'),
            ('192.168.0.0', '192.168.255.255'),
            ('127.0.0.0', '127.255.255.255')
        ]
        
        try:
            parts = [int(x) for x in ip.split('.')]
            ip_int = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
            
            for start, end in private_ranges:
                start_parts = [int(x) for x in start.split('.')]
                end_parts = [int(x) for x in end.split('.')]
                start_int = (start_parts[0] << 24) + (start_parts[1] << 16) + (start_parts[2] << 8) + start_parts[3]
                end_int = (end_parts[0] << 24) + (end_parts[1] << 16) + (end_parts[2] << 8) + end_parts[3]
                
                if start_int <= ip_int <= end_int:
                    return False
            return True
        except:
            return False
    
    def should_scan_url(self, url, source_ip=None):
        """Determine if a URL should be scanned"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            if not domain:
                return False
            
            # Skip whitelisted domains
            for whitelist_domain in self.whitelist_domains:
                if whitelist_domain in domain:
                    return False
            
            if self._is_suspicious_ip(source_ip or ''):
                return True
            
            for shortener in self.url_shorteners:
                if shortener in domain:
                    return True
            
            return True
            
        except Exception as e:
            logger.error(f"Error checking URL {url}: {e}")
            return True
    
    def is_url_shortened(self, url):
        """Check if URL is from a known shortening service"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            for shortener in self.url_shorteners:
                if shortener in domain:
                    return True
            return False
        except:
            return False
    
    def get_urls_from_callback(self, http_data=None, email_data=None, dns_data=None):
        """Unified method to extract URLs from any data source"""
        all_urls = []
        if http_data:
            all_urls.extend(self.extract_urls_from_http(http_data))
        if email_data:
            all_urls.extend(self.extract_urls_from_email(email_data))
        if dns_data:
            all_urls.extend(self.extract_urls_from_dns(dns_data))
        return all_urls
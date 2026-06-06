import re
from email import message_from_string
import time


class SMTPExtractor:
    """
    Extract SMTP/Email data for phishing detection
    Parses email headers, body, and attachments
    """
    
    def __init__(self):
        self.email_buffer = {}
        self.buffer_timestamps = {}  # Track when buffers were created
        self.buffer_timeout = 300    # 5 minutes timeout for incomplete emails
        
        self.phishing_keywords = [
            'urgent', 'verify', 'suspended', 'limited',
            'update your account', 'click here', 'login',
            'password', 'credit card', 'banking',
            'security alert', 'unusual activity'
        ]
        
        self.spoofed_domains = [
            'paypal.com', 'amazon.com', 'google.com',
            'facebook.com', 'apple.com', 'microsoft.com',
            'netflix.com', 'bank', 'irs.gov'
        ]
    
    def _cleanup_stale_buffers(self):
        """Remove stale/incomplete email buffers to prevent memory leaks"""
        now = time.time()
        stale_keys = []
        for conn_id, timestamp in self.buffer_timestamps.items():
            if now - timestamp > self.buffer_timeout:
                stale_keys.append(conn_id)
        for key in stale_keys:
            if key in self.email_buffer:
                del self.email_buffer[key]
            if key in self.buffer_timestamps:
                del self.buffer_timestamps[key]
    
    def extract_data(self, packet):
        """
        Extract SMTP data from packet
        
        Args:
            packet: Scapy packet with SMTP data
        
        Returns:
            dict: Extracted email data or None
        """
        try:
            # Check if this is SMTP traffic
            if not packet.haslayer('TCP') or not packet.haslayer('Raw'):
                return None
            
            # Verify SMTP ports
            src_port = packet['TCP'].sport
            dst_port = packet['TCP'].dport
            smtp_ports = [25, 465, 587, 2525]
            
            if src_port not in smtp_ports and dst_port not in smtp_ports:
                return None  # Not SMTP traffic
            
            # Get raw payload
            raw_data = packet['Raw'].load
            
            try:
                data = raw_data.decode('utf-8', errors='ignore')
            except:
                return None
            
            # Skip empty data
            if not data.strip():
                return None
            
            # Track connection
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            connection_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
            
            # Initialize buffer for this connection
            if connection_id not in self.email_buffer:
                self.email_buffer[connection_id] = []
                self.buffer_timestamps[connection_id] = time.time()
            
            # Update timestamp
            self.buffer_timestamps[connection_id] = time.time()
            
            # Add data to buffer
            self.email_buffer[connection_id].append(data)
            
            # Check if this is a complete email
            full_data = '\n'.join(self.email_buffer[connection_id])
            
            if '\r\n.\r\n' in full_data or '\n.\n' in full_data:
                # Email is complete, parse it
                email_data = self._parse_email(full_data, src_ip, dst_ip)
                
                # Clear buffer
                del self.email_buffer[connection_id]
                del self.buffer_timestamps[connection_id]
                
                return email_data
            
            # Cleanup stale buffers periodically
            if len(self.email_buffer) > 50:
                self._cleanup_stale_buffers()
            
            return None
            
        except Exception as e:
            print(f"Error extracting SMTP data: {e}")
            return None
    
    def _parse_email(self, raw_email, src_ip, dst_ip):
        """Parse raw email data"""
        try:
            msg = message_from_string(raw_email)
            
            subject = msg.get('Subject', '') or ''
            sender = msg.get('From', '') or ''
            recipient = msg.get('To', '') or ''
            date = msg.get('Date', '') or ''
            
            # Extract body
            body = ''
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    if content_type == 'text/plain':
                        try:
                            payload = part.get_payload(decode=True)
                            if payload:
                                body = payload.decode('utf-8', errors='ignore')
                        except:
                            body = str(part.get_payload())
                        break
                    elif content_type == 'text/html' and not body:
                        try:
                            payload = part.get_payload(decode=True)
                            if payload:
                                html_body = payload.decode('utf-8', errors='ignore')
                                body = self._strip_html(html_body)
                        except:
                            pass
            else:
                try:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        body = payload.decode('utf-8', errors='ignore')
                except:
                    body = str(msg.get_payload())
            
            # Extract URLs from body
            urls = self._extract_urls(body)
            urls.extend(self._extract_urls(raw_email))
            urls = list(set(urls))  # Remove duplicates
            
            # Calculate phishing score
            phishing_score = self._calculate_phishing_score(subject, body, sender)
            
            # Check for suspicious sender
            sender_suspicious = False
            sender_lower = sender.lower()
            for domain in self.spoofed_domains:
                if domain in sender_lower and not sender_lower.endswith(f'@{domain}'):
                    sender_suspicious = True
                    break
            
            return {
                'type': 'email',
                'subject': subject,
                'sender': sender,
                'recipient': recipient,
                'date': date,
                'body': body[:5000],
                'body_preview': body[:200] if body else '',
                'urls_found': urls,
                'phishing_score': phishing_score,
                'sender_suspicious': sender_suspicious,
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'has_attachments': msg.is_multipart(),
                'raw_length': len(raw_email)
            }
            
        except Exception as e:
            print(f"Error parsing email: {e}")
            return {
                'type': 'email',
                'raw_content': raw_email[:1000],
                'error': str(e),
                'source_ip': src_ip,
                'destination_ip': dst_ip
            }
    
    def _extract_urls(self, text):
        """Extract URLs from text"""
        if not text:
            return []
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
        urls = re.findall(url_pattern, text)
        return list(set(urls))
    
    def _strip_html(self, html_text):
        """Strip HTML tags from text"""
        if not html_text:
            return ''
        clean = re.compile('<.*?>')
        return re.sub(clean, '', html_text)
    
    def _calculate_phishing_score(self, subject, body, sender):
        """Calculate phishing probability score based on keywords"""
        score = 0
        combined_text = f"{subject} {body}".lower()
        
        for keyword in self.phishing_keywords:
            if keyword in combined_text:
                score += 1
        
        if subject and subject.count('!') > 2:
            score += 2
        
        if subject and len(subject) > 0:
            caps_ratio = sum(1 for c in subject if c.isupper()) / len(subject)
            if caps_ratio > 0.5:
                score += 1
        
        sender_lower = sender.lower() if sender else ''
        for domain in self.spoofed_domains:
            if domain in sender_lower and not sender_lower.endswith(f'@{domain}'):
                score += 3
                break
        
        return min(score, 10)
import re
import logging
from email import message_from_string

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EmailExtractor:
    """
    Extract and preprocess email content for phishing detection
    Prepares text for the mBERT phishing model
    """
    
    def __init__(self):
        # Suspicious patterns for quick pre-screening
        self.urgent_keywords = [
            'urgent', 'immediately', 'alert', 'warning', 'attention',
            'important', 'verify', 'confirm', 'suspend', 'restrict',
            'limited', 'expire', 'deadline', 'within 24 hours',
            'account suspended', 'unusual activity', 'security alert'
        ]
        
        # Financial keywords (common in phishing)
        self.financial_keywords = [
            'bank', 'credit card', 'debit card', 'payment', 'invoice',
            'wire transfer', 'bitcoin', 'cryptocurrency', 'paypal',
            'account balance', 'transaction', 'refund', 'deposit'
        ]
        
        # Spoofed brands
        self.spoofed_brands = [
            'paypal', 'amazon', 'apple', 'microsoft', 'google',
            'facebook', 'netflix', 'dropbox', 'linkedin', 'twitter',
            'instagram', 'whatsapp', 'telegram', 'bank of america',
            'chase', 'wells fargo', 'citibank', 'dhl', 'fedex', 'ups'
        ]
        
        # Max text length for BERT model
        self.max_length = 512
    
    def extract_and_preprocess(self, email_data):
        """
        Extract and preprocess email for ML model
        
        Args:
            email_data: Dict from SMTPExtractor
        
        Returns:
            dict: Preprocessed email data ready for ML model
        """
        try:
            if not email_data:
                return None
            
            # Extract key components
            subject = email_data.get('subject', '')
            body = email_data.get('body', '')
            sender = email_data.get('sender', '')
            
            # Combine subject and body for analysis
            full_text = f"Subject: {subject}\n\n{body}"
            
            # Clean and normalize text
            cleaned_text = self._clean_text(full_text)
            
            # Truncate to BERT's max length
            truncated_text = self._truncate_text(cleaned_text)
            
            # Quick heuristic pre-screening
            heuristic_scores = self._quick_heuristic_check(subject, body, sender)
            
            return {
                'text_for_model': truncated_text,
                'subject': subject,
                'sender': sender,
                'recipient': email_data.get('recipient', ''),
                'has_attachments': email_data.get('has_attachments', False),
                'urls_found': email_data.get('urls_found', []),
                'phishing_score': email_data.get('phishing_score', 0),
                'sender_suspicious': email_data.get('sender_suspicious', False),
                'heuristic_scores': heuristic_scores,
                'source_ip': email_data.get('source_ip'),
                'timestamp': email_data.get('timestamp')
            }
        except Exception as e:
            logger.error(f"Error preprocessing email: {e}")
            return None
    
    def _clean_text(self, text):
        """
        Clean email text for ML processing
        
        Args:
            text: Raw email text
        
        Returns:
            str: Cleaned text
        """
        # Remove excessive whitespace
        text = re.sub(r'\s+', ' ', text)
        
        # Remove email headers that might leak into body
        text = re.sub(r'(Received|From|To|Date|Subject|Message-ID|MIME-Version|Content-Type):.*\n', '', text, flags=re.IGNORECASE)
        
        # Remove base64 encoded blocks
        text = re.sub(r'[A-Za-z0-9+/]{50,}={0,2}', '', text)
        
        # Normalize URLs (replace with [URL] token)
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
        text = re.sub(url_pattern, '[URL]', text)
        
        # Normalize email addresses
        email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
        text = re.sub(email_pattern, '[EMAIL]', text)
        
        # Strip HTML tags if any remain
        clean_html = re.compile('<.*?>')
        text = re.sub(clean_html, '', text)
        
        # Decode HTML entities
        text = text.replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>')
        text = text.replace('&quot;', '"').replace('&#39;', "'").replace('&nbsp;', ' ')
        
        # Remove special characters but keep punctuation
        text = re.sub(r'[^\w\s.,!?;:()\[\]{}\-@#$%^&*+=/\\\'\"<>]', '', text)
        
        return text.strip()
    
    def _truncate_text(self, text):
        """
        Truncate text to BERT's maximum length
        Keeps the most important parts
        
        Args:
            text: Full text
        
        Returns:
            str: Truncated text
        """
        # BERT tokenizer will handle actual tokenization
        # We approximate: ~4 characters per token
        max_chars = self.max_length * 4
        
        if len(text) <= max_chars:
            return text
        
        # Keep beginning (usually has subject/important info)
        # and end (might have call-to-action)
        half_length = max_chars // 2
        beginning = text[:half_length]
        ending = text[-half_length:]
        
        return beginning + " ... " + ending
    
    def _quick_heuristic_check(self, subject, body, sender):
        """
        Quick heuristic check for phishing indicators
        
        Args:
            subject: Email subject
            body: Email body
            sender: Sender address
        
        Returns:
            dict: Heuristic scores
        """
        combined_text = f"{subject} {body}".lower()
        scores = {
            'urgency_score': 0,
            'financial_score': 0,
            'brand_impersonation_score': 0,
            'grammar_score': 0,
            'overall_risk': 'low'
        }
        
        # Check urgency keywords
        for keyword in self.urgent_keywords:
            if keyword in combined_text:
                scores['urgency_score'] += 1
        
        # Check financial keywords
        for keyword in self.financial_keywords:
            if keyword in combined_text:
                scores['financial_score'] += 1
        
        # Check brand impersonation
        sender_lower = sender.lower() if sender else ''
        for brand in self.spoofed_brands:
            if brand in combined_text:
                scores['brand_impersonation_score'] += 1
                # Higher score if sender doesn't match brand
                if brand not in sender_lower:
                    scores['brand_impersonation_score'] += 2
        
        # Normalize scores (0-10)
        scores['urgency_score'] = min(scores['urgency_score'], 10)
        scores['financial_score'] = min(scores['financial_score'], 10)
        scores['brand_impersonation_score'] = min(scores['brand_impersonation_score'], 10)
        
        # Calculate overall risk
        total_score = (scores['urgency_score'] * 0.3 + 
                      scores['financial_score'] * 0.3 + 
                      scores['brand_impersonation_score'] * 0.4)
        
        if total_score >= 7:
            scores['overall_risk'] = 'high'
        elif total_score >= 4:
            scores['overall_risk'] = 'medium'
        else:
            scores['overall_risk'] = 'low'
        
        return scores
    
    def batch_preprocess(self, email_list):
        """
        Preprocess multiple emails at once
        
        Args:
            email_list: List of email data dicts
        
        Returns:
            list: Preprocessed emails
        """
        processed = []
        for email in email_list:
            result = self.extract_and_preprocess(email)
            if result:
                processed.append(result)
        
        return processed


if __name__ == '__main__':
    # Test email extractor
    extractor = EmailExtractor()
    
    test_email = {
        'subject': 'URGENT: Your Account Has Been Suspended!',
        'body': 'Dear user, your account has been suspended due to unusual activity. Click here to verify: http://phishing-login.com/verify',
        'sender': 'security@paypa1.com',
        'recipient': 'user@company.com',
        'urls_found': ['http://phishing-login.com/verify'],
        'phishing_score': 8,
        'sender_suspicious': True,
        'source_ip': '192.168.1.100'
    }
    
    processed = extractor.extract_and_preprocess(test_email)
    print(f"Preprocessed email:")
    print(f"  Text length: {len(processed['text_for_model'])}")
    print(f"  Heuristic scores: {processed['heuristic_scores']}")
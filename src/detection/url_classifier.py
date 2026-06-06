import joblib
import pandas as pd
import re
import math
import string
from urllib.parse import urlparse

# ---------- Global constants (as in your training notebook) ----------
suspicious_keywords = ['login', 'signin', 'verify', 'update', 'banking', 'account', 'secure', 'ebay', 'paypal']
brand_keywords = ['paypal', 'bank', 'amazon', 'google', 'facebook', 'apple', 'microsoft']
bad_tlds = ['xyz', 'top', 'gq', 'ml', 'cf', 'tk', 'club', 'click', 'zip', 'loan', 'work']

def entropy(s):
    """Calculate Shannon entropy of a string."""
    if len(s) == 0:
        return 0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


class URLDetector:
    def __init__(self, model_path, feature_cols_path, label_encoder_path):
        self.model = joblib.load(model_path)
        self.feature_cols = joblib.load(feature_cols_path)   # list of column names in order
        self.le = joblib.load(label_encoder_path)

    def _extract_features(self, url):
        """Return a dictionary of features (keys = self.feature_cols)."""
        parsed = urlparse(url)
        domain = parsed.netloc if parsed.netloc else url
        path = parsed.path
        query = parsed.query
        tld = domain.split('.')[-1] if '.' in domain else ''
        sld = domain.split('.')[0] if '.' in domain else domain

        features = {}

        # A. URL STRUCTURE FEATURES
        features['url_length'] = len(url)
        features['num_digits'] = sum(c.isdigit() for c in url)
        features['num_special_chars'] = sum(c in string.punctuation for c in url)
        features['num_subdomains'] = domain.count('.') - 1 if domain else 0
        features['num_slashes'] = url.count('/')
        features['num_params'] = url.count('?')
        features['num_fragments'] = url.count('#')
        features['url_entropy'] = entropy(url)
        features['num_hyphens'] = domain.count('-')
        features['double_slash_in_path'] = 1 if '//' in path[1:] else 0

        # B. DOMAIN FEATURES
        features['domain_length'] = len(domain)
        features['sld_length'] = len(sld)
        features['tld_length'] = len(tld)
        features['bad_tld_flag'] = 1 if tld in bad_tlds else 0
        features['has_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 0
        features['numeric_domain'] = 1 if domain.replace('.', '').isdigit() else 0
        features['domain_tokens'] = len(sld.split('-')) if sld else 0

        # C. PATH / QUERY FEATURES
        features['path_length'] = len(path)
        features['num_directories'] = path.count('/')
        features['query_length'] = len(query)
        features['has_hex_encoding'] = 1 if re.search(r'%[0-9a-fA-F]{2}', url) else 0
        features['repeated_chars'] = 1 if re.search(r'(.)\1{3,}', url) else 0

        # D. KEYWORD FEATURES
        url_lower = url.lower()
        features['has_suspicious_words'] = 1 if any(word in url_lower for word in suspicious_keywords) else 0
        features['brand_mimic'] = 1 if any(brand in url_lower for brand in brand_keywords) else 0
        features['has_unicode_or_punycode'] = 1 if ('xn--' in url_lower or any(ord(c) > 127 for c in url)) else 0

        # Ensure all expected columns are present (raise error if missing)
        return features

    def predict(self, url):
        feats = self._extract_features(url)
        # Create a DataFrame with the exact column order expected by the model
        df = pd.DataFrame([feats])[self.feature_cols]
        pred_id = self.model.predict(df)[0]
        proba = self.model.predict_proba(df)[0].max()
        label = self.le.inverse_transform([pred_id])[0]
        return {'label': label, 'confidence': proba, 'module': 'url'}
# predict_url.py
# Load the trained model and classify a single URL.

import joblib
import pandas as pd
import re
import string
import math
from urllib.parse import urlparse

# ---------- Feature extraction (must be identical to training) ----------
suspicious_keywords = ['login', 'signin', 'verify', 'update', 'banking', 'account', 'secure', 'ebay', 'paypal']
brand_keywords = ['paypal','bank','amazon','google','facebook','apple','microsoft']
bad_tlds = ['xyz','top','gq','ml','cf','tk','club','click','zip','loan','work']

def entropy(s):
    if len(s) == 0:
        return 0
    probs = [s.count(c)/len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)

def extract_features(url):
    features = {}
    parsed = urlparse(url)
    domain = parsed.netloc if parsed.netloc else url
    path = parsed.path
    query = parsed.query
    tld = domain.split('.')[-1] if '.' in domain else ''
    sld = domain.split('.')[0] if '.' in domain else domain

    features['url_length'] = len(url)
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['num_special_chars'] = sum(c in string.punctuation for c in url)
    features['num_subdomains'] = domain.count('.') - 1
    features['num_slashes'] = url.count('/')
    features['num_params'] = url.count('?')
    features['num_fragments'] = url.count('#')
    features['url_entropy'] = entropy(url)
    features['num_hyphens'] = domain.count('-')
    features['double_slash_in_path'] = int('//' in path[1:])

    features['domain_length'] = len(domain)
    features['sld_length'] = len(sld)
    features['tld_length'] = len(tld)
    features['bad_tld_flag'] = int(tld in bad_tlds)
    features['has_ip'] = int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', domain)))
    features['numeric_domain'] = int(domain.replace('.', '').isdigit())
    features['domain_tokens'] = len(sld.split('-'))

    features['path_length'] = len(path)
    features['num_directories'] = path.count('/')
    features['query_length'] = len(query)
    features['has_hex_encoding'] = int(bool(re.search(r'%[0-9a-fA-F]{2}', url)))
    features['repeated_chars'] = int(bool(re.search(r'(.)\1{3,}', url)))

    features['has_suspicious_words'] = int(any(word in url.lower() for word in suspicious_keywords))
    features['brand_mimic'] = int(any(brand in url.lower() for brand in brand_keywords))
    features['has_unicode_or_punycode'] = int('xn--' in url.lower() or any(ord(c) > 127 for c in url))

    return features

# ---------- Load model and helpers ----------
model = joblib.load('rf_url_model.pkl')
label_encoder = joblib.load('label_encoder.pkl')
feature_columns = joblib.load('feature_columns.pkl')

def predict_url(url: str) -> str:
    """Return category name for a given URL string."""
    feat_dict = extract_features(url)
    # Ensure all features exist (fill missing with 0, just in case)
    for col in feature_columns:
        if col not in feat_dict:
            feat_dict[col] = 0
    # Convert to DataFrame with correct column order
    input_df = pd.DataFrame([feat_dict])
    input_df = input_df[feature_columns]   # reorder
    pred_num = model.predict(input_df)[0]
    return label_encoder.inverse_transform([pred_num])[0]

# ---------- Command‑line interface ----------
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = input("Enter a URL to classify: ")
    category = predict_url(url)
    print(f"\nURL: {url}\nPrediction: {category}")
import joblib
import sys
import os
import pandas as pd
import re
import math
from sklearn.base import BaseEstimator, TransformerMixin

# ============================================================
# Helper functions - must match training exactly
# ============================================================
def entropy(s):
    if len(s) == 0:
        return 0
    prob = [s.count(c)/len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

def extra_features(text):
    features = {}
    features['length'] = len(text)
    features['num_digits'] = sum(c.isdigit() for c in text)
    features['num_special'] = sum(not c.isalnum() and not c.isspace() for c in text)
    features['num_urls'] = len(re.findall(r'https?://\S+|www\.\S+', text))
    features['num_exclamations'] = text.count('!')
    features['num_uppercase_words'] = sum(1 for w in text.split() if w.isupper() and len(w)>1)
    features['entropy'] = entropy(text)
    
    suspicious_en = ['verify','account','login','update','bank','paypal','secure','click','confirm','urgent','password']
    suspicious_ne = ['खाता','प्रमाणित','लगइन','अपडेट','बैंक','सुरक्षित','क्लिक','पुष्टि','अत्यावश्यक','पासवर्ड']
    features['has_suspicious'] = int(any(kw in text.lower() for kw in suspicious_en) or
                                     any(kw in text for kw in suspicious_ne))
    return features

class ExtraFeaturesTransformer(BaseEstimator, TransformerMixin):
    def fit(self, X, y=None):
        return self
    def transform(self, X):
        return pd.DataFrame([extra_features(t) for t in X]).values

# ============================================================
# Register class so pickle can find it from any module
# ============================================================
import __main__
setattr(__main__, 'ExtraFeaturesTransformer', ExtraFeaturesTransformer)

# Also register in detection_engine module
import detection_engine
if hasattr(detection_engine, 'email_phishing'):
    setattr(detection_engine.email_phishing, 'ExtraFeaturesTransformer', ExtraFeaturesTransformer)

# ============================================================
# EmailDetector class
# ============================================================
class EmailDetector:
    def __init__(self, model_path='models/email/phishing_model.pkl'):
        """
        Initialize email phishing detector
        
        Args:
            model_path: Path to the trained pipeline .pkl file
        """
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found: {model_path}")
        
        self.pipeline = joblib.load(model_path)

    def predict(self, email_text):
        """
        Predict if an email is phishing
        
        Args:
            email_text: Email content string
        
        Returns:
            dict: {'label': 'phishing'/'legitimate', 'confidence': float, 'module': 'email'}
        """
        if not isinstance(email_text, str):
            email_text = str(email_text)
        
        try:
            pred = self.pipeline.predict([email_text])[0]
            proba = self.pipeline.predict_proba([email_text])[0].max()
            label = 'phishing' if pred == 1 else 'legitimate'
            return {'label': label, 'confidence': float(proba), 'module': 'email'}
        except Exception as e:
            print(f"[EmailDetector] Error: {e}")
            return {'label': 'legitimate', 'confidence': 0.5, 'module': 'email'}
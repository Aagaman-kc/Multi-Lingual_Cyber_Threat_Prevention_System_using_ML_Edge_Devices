import sys
import os
# Add current directory to path so imports work
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from detection_engine.url_scanner.url_classifier import URLDetector
from detection_engine.email_phishing.email_classifier import EmailDetector
from detection_engine.app_layer_detector.payload_analyzer import AppAttackDetector
from detection_engine.dpi_model.anomaly_detector import DPIDetector
import json

def main():
    print("Loading detectors...")
    url_detector = URLDetector(
        'models/url/rf_url_model.pkl',
        'models/url/feature_columns.pkl',
        'models/url/label_encoder.pkl'
    )
    email_detector = EmailDetector('models/email/final_multilingual_model/')
    app_detector = AppAttackDetector(
        'models/app_attack/web_attack_rf.pkl',
        'models/app_attack/tfidf_vectorizer.pkl',
        'models/app_attack/label_encoder.pkl'
    )
    dpi_detector = DPIDetector('models/dpi/dpi_rf_pipeline.pkl')
    print("All detectors loaded. Running simulation...")

    def handle(item):
        if item['type'] == 'url':
            result = url_detector.predict(item['data'])
        elif item['type'] == 'email':
            result = email_detector.predict(item['data'])
        elif item['type'] == 'payload':
            result = app_detector.detect(item['data'])
        elif item['type'] == 'dpi':
            result = dpi_detector.predict(item['data'])
        else:
            return
        if result['label'] not in ['benign', 'normal', 'legitimate']:
            print(f"[ALERT] {result['module']}: {result['label']} (conf={result['confidence']:.2f})")
        return result

    # Simulate some attacks
    print("Testing malicious URL...")
    handle({'type': 'url', 'data': 'http://evil-phishing.com/login'})
    print("Testing phishing email...")
    handle({'type': 'email', 'data': 'Verify your account at http://fake.com'})
    print("Testing SQL injection...")
    handle({'type': 'payload', 'data': "1' OR '1'='1' --"})
    print("Testing XSS...")
    handle({'type': 'payload', 'data': "<script>alert('xss')</script>"})
    print("Simulation complete. Check database threats.db")

if __name__ == '__main__':
    main()
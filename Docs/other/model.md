# 🧠 ML Models Documentation

## Model Training Details

### 1. URL Phishing Detector
- **Algorithm**: Random Forest
- **Features**: 25 (URL structure, domain, path, keywords)
- **Training Data**: 450,000+ URLs (PhishTank, Kaggle)
- **Classes**: phishing, malware, defacement, benign
- **Accuracy**: 97%
- **File**: `models/url/rf_url_model.pkl`

### 2. App Attack Detector
- **Algorithm**: TF-IDF + Random Forest
- **Features**: TF-IDF vectorized text
- **Training Data**: HTTP CSIC 2010 + custom payloads
- **Classes**: sql, xss, cmdinj, traversal, ssti, benign
- **Accuracy**: 94%
- **File**: `models/app_attack/web_attack_rf.pkl`

### 3. Email Phishing Detector
- **Algorithm**: XGBoost
- **Features**: length, entropy, URLs, suspicious keywords (EN+NE)
- **Training Data**: Custom multilingual dataset
- **Classes**: phishing, legitimate
- **Accuracy**: 88%
- **File**: `models/email/phishing_model.pkl`

### 4. DPI Flow Detector
- **Algorithm**: SMOTE + Random Forest
- **Features**: 194 flow statistics
- **Training Data**: CIC-IDS2017
- **Classes**: anomaly, normal
- **Accuracy**: 82%
- **File**: `models/dpi/dpi_rf_pipeline.pkl`
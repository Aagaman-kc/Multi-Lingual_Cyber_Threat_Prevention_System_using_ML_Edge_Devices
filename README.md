# 🛡️ Multi-Lingual Cyber Threat Prevention System using Machine Learning on Edge Devices

[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![Scikit-learn](https://img.shields.io/badge/Scikit--learn-1.3-orange.svg)](https://scikit-learn.org/)
[![XGBoost](https://img.shields.io/badge/XGBoost-2.0-green.svg)](https://xgboost.ai/)
[![Flask](https://img.shields.io/badge/Flask-Dashboard-black.svg)](https://flask.palletsprojects.com/)
[![Raspberry Pi](https://img.shields.io/badge/Raspberry%20Pi-5-red.svg)](https://www.raspberrypi.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 🚀 Project Highlights

A lightweight AI-powered cybersecurity platform that performs **real-time threat detection on Raspberry Pi 5** using machine learning models optimized for edge deployment.

### Key Achievements

- ✅ Designed and deployed a complete edge-based cyber threat detection system
- ✅ Supports multilingual phishing detection in **English, Nepali (Devanagari), and Hindi**
- ✅ Reduced phishing detection model size from **700 MB (mBERT)** to **1.3 MB (XGBoost)**
- ✅ Reduced inference latency from **70 ms** to **5 ms per email**
- ✅ Achieved **F1 Score = 0.94** on multilingual phishing classification
- ✅ Processes network traffic and application-layer attacks in real time
- ✅ End-to-end alert latency ≈ **120 ms**
- ✅ Successfully deployed on Raspberry Pi 5

---

## 📌 Overview

Traditional Intrusion Detection Systems (IDS), Deep Packet Inspection (DPI) solutions, and phishing detectors are typically designed for English-language environments and often require powerful hardware resources.

This project addresses two key challenges:

### 🌐 Multilingual Threat Detection

Most phishing detection systems struggle with underrepresented languages such as Nepali written in Devanagari script. This system extends detection capabilities beyond English by supporting:

- English
- Nepali (Devanagari)
- Hindi

### ⚡ Edge Deployment

Instead of relying on expensive cloud infrastructure, the system is optimized to run on low-cost edge hardware while maintaining strong detection performance and low latency.

---

## 🏗️ System Architecture

![Architecture](readme_image/arch.jpg)

The platform consists of four independent machine learning engines running in parallel:

| Module                      | Algorithm                      | Purpose                                                                |
| --------------------------- | ------------------------------ | ---------------------------------------------------------------------- |
| Flow-Based DPI              | Random Forest Pipeline         | Detect network anomalies, beaconing, C2 traffic, DoS, and exfiltration |
| URL Scanner                 | Random Forest (200 Trees)      | Detect phishing, malware, defacement, and benign URLs                  |
| Application Attack Detector | TF-IDF + Random Forest + SMOTE | Detect SQLi, XSS, SSTI, Path Traversal, Command Injection              |
| Email Phishing Detector     | TF-IDF + XGBoost               | Detect multilingual phishing emails                                    |

### Pipeline Flow

1. Traffic Capture (Scapy / tcpdump)
2. Feature Extraction
3. Parallel Threat Detection
4. SQLite Alert Storage
5. Real-Time Dashboard Visualization

---

## 📸 Real-World Deployment

![Real-life deployment](readme_image/reallife.jpg)

*Raspberry Pi 5 running the complete detection pipeline with live traffic capture and dashboard monitoring.*

---

## 🎯 Performance Summary

| Module             | Precision | Recall | F1 Score | Inference Time |
| ------------------ | --------- | ------ | -------- | -------------- |
| URL Detector       | 0.96      | 0.96   | 0.964    | 2 ms           |
| Email Detector     | 0.94      | 0.94   | 0.940    | 5 ms           |
| App-Layer Detector | 0.98      | 0.97   | 0.980    | 3 ms           |
| Flow-Based DPI     | 0.97      | 0.95   | 0.966    | 8 ms           |

### System Performance

| Metric               | Value   |
| -------------------- | ------- |
| End-to-End Latency   | ~120 ms |
| CPU Usage @ 100 Mbps | <40%    |
| Memory Usage         | ~800 MB |
| Total Model Size     | ~470 MB |

---

## 📊 Model Evaluation

| URL Detector                                                   | Email Detector                                                     | App-Layer Detector                                             | DPI Detector                                                   |
| -------------------------------------------------------------- | ------------------------------------------------------------------ | -------------------------------------------------------------- | -------------------------------------------------------------- |
| ![URL Confusion Matrix](readme_image/url_confusion_matrix.png) | ![Email Confusion Matrix](readme_image/email_confusion_matrix.png) | ![App Confusion Matrix](readme_image/app_confusion_matrix.png) | ![DPI Confusion Matrix](readme_image/dpi_confusion_matrix.png) |

These results demonstrate strong classification performance across network traffic analysis, phishing detection, malicious URL classification, and web application attack detection.

---

## 📈 Performance Comparison

![Model Performance Comparison](readme_image/model_performance_comparison.png)

---

## 📂 Dataset Distribution

![Dataset Distribution](readme_image/dataset_distribution.png)

| Model                      | Dataset                       |
| -------------------------- | ----------------------------- |
| Flow-Based DPI             | UNSW-NB15                     |
| URL Detection              | URLsdata.csv                  |
| App-Layer Attack Detection | CSIC 2010 + Synthetic Attacks |
| Phishing Email Detection   | Multilingual Email Corpus     |

---

## 🖥️ Real-Time Dashboard

![Web Dashboard](readme_image/web_dashboard.png)

### Dashboard Features

- Live threat monitoring
- Real-time alert feed
- Threat categorization
- Historical attack analytics
- Interactive filtering
- Payload inspection
- Confidence score tracking

---

## 🔬 Skills Demonstrated

### Machine Learning

- Random Forest
- XGBoost
- TF-IDF
- Feature Engineering
- Imbalanced Learning (SMOTE)

### Cybersecurity

- Deep Packet Inspection
- Intrusion Detection
- Phishing Detection
- Web Application Security
- Threat Intelligence

### MLOps & Systems

- Edge AI Deployment
- Raspberry Pi Optimization
- Model Serialization
- Real-Time Inference Pipelines
- Monitoring Dashboards

### Software Engineering

- Python
- Flask
- Socket.IO
- SQLite
- Scapy
- Data Pipelines

---

## 📁 Repository Structure

```text
.
├── notebooks/                     # Jupyter notebooks for training & exploration
├── models/                        # Serialized ML models (.pkl)
│   ├── url/                       # Random Forest URL classifier
│   ├── dpi/                       # DPI pipeline & preprocessing objects
│   ├── app_attack/                # TF-IDF + RF + SMOTE models
│   └── email_phishing/            # Lightweight XGBoost email detector
├── data/                          # Datasets (CSV files)
├── src/                           # Source code for capture, detection, dashboard
├── scripts/                       # Utility scripts (attack simulation, testing)
├── docs/                          # Documentation and images
│   ├── images/                    # Architecture, confusion matrices, plots
│   └── other/                     # Additional documentation
├── requirements.txt
├── README.md
└── LICENSE
```

---

## 🚀 Installation

### Prerequisites
- Python 3.12+
- pip
- (Optional) CUDA for retraining the mBERT baseline

### Step 1: Clone the repository

```bash
git clone https://github.com/your-username/cyber-threat-prevention.git
cd cyber-threat-prevention
```

### Step 2: Create virtual environment

#### Linux/macOS
```bash
python -m venv venv
source venv/bin/activate
```

#### Windows
```powershell
python -m venv venv
venv\Scripts\activate
```

### Step 3: Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 🧪 Usage Examples

### Flow-Based DPI Detection

```python
import joblib
import pandas as pd

pipeline = joblib.load("models/dpi/dpi_rf_pipeline.pkl")
flow_df = pd.read_csv("data/dpi/UNSW_NB15_testing-set.csv")

predictions = pipeline.predict(flow_df)
print(predictions[:10])
```

---

### Malicious URL Detection

```bash
python scripts/predict_URL.py --url "http://suspicious-site.com/login.php"
```

---

### Application-Layer Attack Detection

```python
import joblib

vectorizer = joblib.load("models/app_attack/tfidf_vectorizer.pkl")
model = joblib.load("models/app_attack/web_attack_rf.pkl")
label_encoder = joblib.load("models/app_attack/label_encoder.pkl")

payload = "<script>alert('xss')</script>"
X = vectorizer.transform([payload])

pred = model.predict(X)[0]
print(label_encoder.inverse_transform([pred])[0])
```

---

### Phishing Email Detection

```python
import joblib

pipeline = joblib.load("models/email_phishing/phishing_xgboost_100k.pkl")

email_text = "Urgent: Verify your account immediately to avoid suspension."

pred = pipeline.predict([email_text])[0]

print(pred)  # 0 = legitimate, 1 = phishing
```

---

## 🔄 Full Edge Deployment (Raspberry Pi 5)

```bash
sudo python src/main.py
```

```bash
python src/dashboard/run.py
```

---

## 🤝 Contributors

- Aagaman K.C. (PAS078BEI001)  
- Ajay Panta (PAS078BEI002)  
- Chandra Kamal Singh (PAS078BEI010)  
- Gaurav Bhujel (PAS078BEI014)  

Supervisor: Asst. Prof. Khem Raj Koirala  
Department of Electronics & Computer Engineering  
Pashchimanchal Campus, IOE, Tribhuvan University  

---

## 📄 License

MIT License

---

## 🙏 Acknowledgements

- UNSW Canberra Cyber
- Kaggle datasets
- Scikit-learn community
- XGBoost developers
- Scapy contributors
- Nepal Police Cyber Bureau

---

💡 Built for a safer, more inclusive internet

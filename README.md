# 🔒 Multi-Layer Cyber Threat Detection System

A comprehensive machine learning-based cybersecurity detection framework featuring four specialized detection models for network traffic, malicious URLs, application-layer attacks, and phishing emails. Built for deployment on resource-constrained environments like the Raspberry Pi 4.

---

## 📋 Table of Contents

- [Overview](#overview)
- [System Architecture](#system-architecture)
- [Models](#models)
  - [1. Deep Packet Inspection (DPI)](#1-deep-packet-inspection-dpi)
  - [2. Malicious URL Detection](#2-malicious-url-detection)
  - [3. Application Attack Detection](#3-application-attack-detection)
  - [4. Phishing Email Detection](#4-phishing-email-detection)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Results & Performance](#results--performance)
- [Datasets](#datasets)
- [Future Work](#future-work)
- [License](#license)

---

## 🎯 Overview

This repository contains the core ML models for a multi-layer cyber threat detection system. The project implements four independent but complementary detection engines:

| Module | Algorithm | Purpose |
|--------|-----------|---------|
| **DPI Model** | Random Forest / XGBoost | Network flow anomaly detection (C2, beaconing, port scanning, DoS, exfiltration) |
| **URL Scanner** | Random Forest | Real-time malicious URL classification (phishing, malware, defacement, benign) |
| **App-Layer Detector** | Rule-based + ML | Detection of XSS, SQL Injection, Command Injection, SSTI, Path Traversal |
| **Email Phishing** | mBERT (Multilingual) | Multilingual phishing email detection |

> **Note:** This repository contains the standalone ML models. Raspberry Pi 4 integration, real-time capture layer (Scapy/tcpdump), and the Flask/Socket.IO dashboard will be maintained in a separate integration repository.

---

## 🏗️ System Architecture Overview

```text
┌─────────────────────────────────────────────────────────────┐
│                     RASPBERRY PI 4 (8GB)                   │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │              LAYER 1: CAPTURE LAYER                  │  │
│  │                                                       │  │
│  │  scapy / tcpdump extracts:                            │  │
│  │   • HTTP requests (URI, headers, body)                │  │
│  │   • DNS queries                                       │  │
│  │   • SMTP content                                      │  │
│  │   • Flow metadata (5-tuple, packet size, timing)      │  │
│  └───────────────────────┬───────────────────────────────┘  │
│                          │                                  │
│  ┌───────────────────────▼───────────────────────────────┐  │
│  │            LAYER 2: DETECTION ENGINE                 │  │
│  │                                                       │  │
│  │  ┌─────────────┐   ┌─────────────┐  ┌──────────────┐ │  │
│  │  │ URL Scanner │   │ Email       │  │ App-Layer    │ │  │
│  │  │ (RF Model)  │   │ Phishing    │  │ Attack       │ │  │
│  │  │             │   │ (mBERT)     │  │ Detector     │ │  │
│  │  └──────┬──────┘   └──────┬──────┘  │ (Rule-Based) │ │  │
│  │         │                 │         └──────┬───────┘ │  │
│  │         │                 │                │         │  │
│  │         │                 │     Regex detection for  │  │
│  │         │                 │     XSS, SQLi, Command   │  │
│  │         │                 │     Injection attacks    │  │
│  │         │                 │                │         │  │
│  │  ┌──────▼─────────────────▼────────────────▼───────┐ │  │
│  │  │        Flow-Based DPI (Isolation Forest)        │ │  │
│  │  │                                                  │ │  │
│  │  │ Input Features:                                  │ │  │
│  │  │  • Packet statistics                             │ │  │
│  │  │  • Inter-arrival times                           │ │  │
│  │  │  • Entropy features                              │ │  │
│  │  │  • Flow behaviour patterns                       │ │  │
│  │  │                                                  │ │  │
│  │  │ Output: anomaly score for threats such as:       │ │  │
│  │  │  • C2 communication                              │ │  │
│  │  │  • Beaconing                                     │ │  │
│  │  │  • Port scanning                                 │ │  │
│  │  │  • Data exfiltration                             │ │  │
│  │  │  • DoS attacks                                   │ │  │
│  │  └──────────────────────┬───────────────────────────┘ │  │
│  │                         │                             │  │
│  │             ┌───────────▼───────────┐                │  │
│  │             │ Scoring & Decision    │                │  │
│  │             │ Engine (Risk Fusion)  │                │  │
│  │             └───────────┬───────────┘                │  │
│  └─────────────────────────┼─────────────────────────────┘  │
│                            │                                │
│  ┌─────────────────────────▼─────────────────────────────┐  │
│  │               LAYER 3: DATA LAYER                    │  │
│  │                                                       │  │
│  │  SQLite Database                                      │  │
│  │   • threats                                           │  │
│  │   • urls                                              │  │
│  │   • email_threats                                     │  │
│  │   • app_layer_alerts                                  │  │
│  │   • flow_anomalies                                    │  │
│  └─────────────────────────┬─────────────────────────────┘  │
│                            │                                │
│  ┌─────────────────────────▼─────────────────────────────┐  │
│  │          LAYER 4: PRESENTATION LAYER                 │  │
│  │                                                       │  │
│  │ Flask + Socket.IO Dashboard                           │  │
│  │  • Real-time alerts                                   │  │
│  │  • Threat visualization                               │  │
│  │  • Detection logs                                     │  │
│  │  • Multi-module monitoring                            │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## 🤖 Models

### 1. Deep Packet Inspection (DPI)

**Location:** `Deep_Packet_Inspection_Model/`

Network flow anomaly detection using ensemble methods on the UNSW-NB15 dataset.

**Features:**
- Packet statistics (size, count, protocol)
- Inter-arrival times
- Entropy features
- Flow behavior patterns

**Algorithms:**
- Random Forest Pipeline
- XGBoost Classifier

**Preprocessing Artifacts:**
- `cat_imputer.pkl` — Categorical imputer
- `num_imputer.pkl` — Numerical imputer
- `scaler.pkl` — Feature scaler
- `onehot_encoder.pkl` — One-hot encoder
- `label_encoders.pkl` — Label encoders
- `categorical_cols.pkl` / `numeric_cols.pkl` — Column type mappings

**Datasets:**
- `UNSW_NB15_training-set.csv`
- `UNSW_NB15_testing-set.csv`

---

### 2. Malicious URL Detection

**Location:** `Malicious URL Detection Model/`

Real-time URL classification into four categories: **benign**, **defacement**, **malware**, and **phishing**.

**Model Selection:** Random Forest was selected over K-Nearest Neighbors based on superior cross-validation performance.

**Engineered Features:**
- URL length
- Number of digits
- Number of special characters
- Number of subdomains
- URL entropy
- Lexical patterns

**Artifacts:**
- `rf_url_model.pkl` — Trained Random Forest model
- `feature_columns.pkl` — Feature column names
- `label_encoder.pkl` — Target label encoder

**Scripts:**
- `train_model.py` — Training pipeline
- `predict_URL.py` — Inference script for single URL prediction

**Visualizations:** (located in `plots/`)
- Class distribution
- Feature correlation heatmap
- Histograms for URL features (length, digits, special chars, subdomains, entropy)
- Confusion matrices (Random Forest & KNN)
- Model accuracy comparison

---

### 3. Application Attack Detection

**Location:** `Application_Attack_Detection/`

Multi-class detection of application-layer injection attacks using a hybrid rule-based and machine learning approach.

**Attack Classes:**
- `cmdinj` — Command Injection
- `sql` — SQL Injection
- `ssti` — Server-Side Template Injection
- `traversal` — Path Traversal
- `xss` — Cross-Site Scripting
- `benign` — Normal traffic

**Artifacts:**
- `web_attack_rf.pkl` — Random Forest classifier
- `tfidf_vectorizer.pkl` — TF-IDF vectorizer for payload text
- `label_encoder.pkl` — Attack type label encoder

**Datasets:**
- `clean_payloads.csv` — Preprocessed attack payloads

---

### 4. Phishing Email Detection

**Location:** `Phishing_Email_Detection/`

Multilingual phishing email detection powered by **mBERT** (multilingual BERT).

**Capabilities:**
- Supports multiple languages
- Fine-tuned transformer architecture
- Weighted loss handling for class imbalance

**Artifacts:**
- `final_multilingual_model/` — Saved fine-tuned mBERT model
- `results/` & `results_weighted/` — Training checkpoints

**Datasets:**
- `combined_phishing_dataset_15000.csv` — Combined multilingual dataset

**Visualizations:** (located in `figures/`)
- Confusion matrix
- Label distribution
- Language distribution
- Training curves

---

## 📁 Project Structure

```text
./
├── README.md
├── requirements.txt
├── structure.txt
├── structure_check.py
├── CEAS_08.csv
├── main_note.ipynb
│
├── Application_Attack_Detection/
│   ├── Application_Attack_Detection.ipynb
│   ├── clean_payloads.csv
│   └── Application_Attack_Detection/
│       └── models/
│           ├── label_encoder.pkl
│           ├── tfidf_vectorizer.pkl
│           └── web_attack_rf.pkl
│
├── Deep_Packet_Inspection_Model/
│   ├── UNSW_NB15_testing-set.csv
│   ├── UNSW_NB15_training-set.csv
│   ├── dpi.ipynb
│   ├── note.ipynb
│   ├── dpi_rf_pipeline.pkl
│   ├── dpi_xgboost_model.pkl
│   ├── cat_imputer.pkl
│   ├── num_imputer.pkl
│   ├── categorical_cols.pkl
│   ├── numeric_cols.pkl
│   ├── label_encoders.pkl
│   ├── onehot_encoder.pkl
│   └── scaler.pkl
│
├── Malicious URL Detection Model/
│   ├── URLsdata.csv
│   ├── main.ipynb
│   ├── malicious-url-detection-ml-model.ipynb
│   ├── note.ipynb
│   ├── predict_URL.py
│   ├── train_model.py
│   ├── rf_url_model.pkl
│   ├── feature_columns.pkl
│   ├── label_encoder.pkl
│   └── plots/
│       ├── class_distribution.png
│       ├── confusion_matrix_K-Nearest_Neighbors.png
│       ├── confusion_matrix_Random_Forest.png
│       ├── feature_correlation_heatmap.png
│       ├── hist_num_digits.png
│       ├── hist_num_special_chars.png
│       ├── hist_num_subdomains.png
│       ├── hist_url_entropy.png
│       ├── hist_url_length.png
│       └── model_accuracy_comparison.png
│
├── Phishing_Email_Detection/
│   ├── Phishing detection.ipynb
│   ├── phising_detection.ipynb
│   ├── multilingual_phishing_detection.ipynb
│   ├── note.ipynb
│   ├── combined_phishing_dataset_15000.csv
│   ├── architecture.png
│   ├── citation_for_dataset.png
│   ├── figures/
│   │   ├── confusion_matrix.png
│   │   ├── label_distribution.png
│   │   ├── language_distribution.png
│   │   └── training_curves.png
│   ├── final_multilingual_model/
│   ├── results/
│   │   ├── checkpoint-1314/
│   │   └── checkpoint-1971/
│   └── results_weighted/
│       ├── checkpoint-1314/
│       └── checkpoint-1971/
│
└── torch_gpu_env/
    └── (PyTorch GPU virtual environment)
```

---

## ⚙️ Installation

### Prerequisites

- Python 3.8+
- pip
- (Optional) CUDA-capable GPU for phishing model training

### Step 1: Clone the Repository

```bash
git clone <repository-url>
cd <repository-name>
```

### Step 2: Create a Virtual Environment

It is **strongly recommended** to use a virtual environment to avoid dependency conflicts.

```bash
# Using venv (standard library)
python -m venv venv

# Activate on Linux / macOS
source venv/bin/activate

# Activate on Windows
venv\Scripts\activate
```

For the phishing email model (PyTorch + Transformers), a dedicated environment is provided:

```bash
# Using the pre-configured torch environment
python -m venv torch_gpu_env
source torch_gpu_env/bin/activate  # Linux/macOS
# or
torch_gpu_env\Scripts\activate  # Windows
```

### Step 3: Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**Core dependencies typically include:**
- `scikit-learn`
- `pandas`
- `numpy`
- `xgboost`
- `transformers`
- `torch`
- `scapy` (for future integration layer)
- `flask`, `flask-socketio` (for future dashboard layer)
- `matplotlib`, `seaborn` (for visualization)

---

## 🚀 Usage

### 1. Deep Packet Inspection (DPI)

```python
import joblib
import pandas as pd

# Load preprocessing artifacts and model
rf_pipeline = joblib.load('Deep_Packet_Inspection_Model/dpi_rf_pipeline.pkl')

# Prepare flow features as DataFrame
# Expected columns: packet stats, inter-arrival times, entropy, etc.
flow_df = pd.read_csv('Deep_Packet_Inspection_Model/UNSW_NB15_testing-set.csv')

# Predict
predictions = rf_pipeline.predict(flow_df)
anomaly_scores = rf_pipeline.predict_proba(flow_df)
```

### 2. Malicious URL Detection

**Quick inference using the provided script:**

```bash
python "Malicious URL Detection Model/predict_URL.py" --url "http://suspicious-site.com/login.php"
```

**Or programmatically:**

```python
import joblib
import pandas as pd
from urllib.parse import urlparse

# Load model and artifacts
model = joblib.load('Malicious URL Detection Model/rf_url_model.pkl')
features = joblib.load('Malicious URL Detection Model/feature_columns.pkl')
le = joblib.load('Malicious URL Detection Model/label_encoder.pkl')

# Extract features from URL (implement extract_features() as in train_model.py)
# url_features = extract_features("http://example.com")
# prediction = model.predict([url_features])
# print(le.inverse_transform(prediction))
```

### 3. Application Attack Detection

```python
import joblib

# Load model and vectorizer
vectorizer = joblib.load('Application_Attack_Detection/Application_Attack_Detection/models/tfidf_vectorizer.pkl')
model = joblib.load('Application_Attack_Detection/Application_Attack_Detection/models/web_attack_rf.pkl')
le = joblib.load('Application_Attack_Detection/Application_Attack_Detection/models/label_encoder.pkl')

# Example payload
payload = "<script>alert('xss')</script>"
X = vectorizer.transform([payload])
pred = model.predict(X)
print(f"Detected: {le.inverse_transform(pred)[0]}")
```

### 4. Phishing Email Detection

```python
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

# Load fine-tuned mBERT model
model_path = "Phishing_Email_Detection/final_multilingual_model"
tokenizer = AutoTokenizer.from_pretrained(model_path)
model = AutoModelForSequenceClassification.from_pretrained(model_path)

# Inference
email_text = "Urgent: Verify your account immediately to avoid suspension."
inputs = tokenizer(email_text, return_tensors="pt", truncation=True, padding=True, max_length=512)
with torch.no_grad():
    outputs = model(**inputs)
    prediction = torch.argmax(outputs.logits, dim=-1)

print("Phishing" if prediction.item() == 1 else "Legitimate")
```

---

## 📊 Results & Performance

### Deep Packet Inspection (DPI)

| Metric | Score |
|--------|-------|
| **Accuracy** | **95.17%** |
| **Precision** | **96.95%** |
| **Recall** | **95.45%** |
| **F1-Score** | **96.20%** |
| **AUC** | **99.26%** |

**Detailed Classification Report:**

| Class | Precision | Recall | F1-Score | Support |
|-------|-----------|--------|----------|---------|
| Normal (0) | 0.92 | 0.95 | 0.93 | 18,600 |
| Attack (1) | 0.97 | 0.95 | 0.96 | 32,935 |

---

### Malicious URL Detection

**Random Forest (Selected Model):**

| Metric | Score |
|--------|-------|
| **Accuracy** | **95.92%** |
| **Macro Avg F1** | **93.00%** |
| **Weighted Avg F1** | **96.00%** |

**Detailed Classification Report (Random Forest):**

| Class | Precision | Recall | F1-Score | Support |
|-------|-----------|--------|----------|---------|
| benign | 0.97 | 0.98 | 0.98 | 154,725 |
| defacement | 0.93 | 0.91 | 0.92 | 19,341 |
| malware | 0.97 | 0.89 | 0.93 | 4,742 |
| phishing | 0.91 | 0.87 | 0.89 | 29,070 |

**K-Nearest Neighbors (Baseline):**

| Metric | Score |
|--------|-------|
| **Accuracy** | **93.69%** |

> Random Forest outperformed KNN across all metrics, particularly on minority classes (malware, phishing), justifying its selection for production deployment.

---

### Application Attack Detection

| Metric | Score |
|--------|-------|
| **Accuracy** | **96.89%** |
| **Macro F1** | **81.46%** |
| **Weighted Avg F1** | **98.00%** |

**Detailed Classification Report:**

| Class | Precision | Recall | F1-Score | Support |
|-------|-----------|--------|----------|---------|
| benign | 1.00 | 0.94 | 0.97 | 21,832 |
| cmdinj | 1.00 | 1.00 | 1.00 | 13,899 |
| sql | 0.85 | 0.95 | 0.90 | 546 |
| ssti | 0.02 | 0.85 | 0.03 | 26 |
| traversal | 0.99 | 1.00 | 0.99 | 3,699 |
| xss | 1.00 | 0.99 | 0.99 | 6,626 |

> **Note:** SSTI (Server-Side Template Injection) shows low precision due to extreme class imbalance (only 26 samples), though recall remains high at 85%. Consider data augmentation or synthetic sampling (SMOTE) for this class in future iterations.

---

### Phishing Email Detection (mBERT)

| Feature | Description |
|---------|-------------|
| **Architecture** | Multilingual BERT (mBERT) |
| **Languages Supported** | English, French, German, Spanish, Italian, Portuguese, etc. |
| **Training Strategy** | Fine-tuned with weighted loss for class imbalance |
| **Checkpoints** | `checkpoint-1314`, `checkpoint-1971` |

> Full quantitative metrics are available in the training notebooks (`Phishing detection.ipynb`, `multilingual_phishing_detection.ipynb`).

---

## 📚 Datasets

| Model | Dataset | Source / Description |
|-------|---------|---------------------|
| DPI | UNSW-NB15 | Australian Centre for Cyber Security (ACCS) |
| URL | URLsdata.csv | Aggregated malicious & benign URL dataset |
| App-Attack | clean_payloads.csv | Curated injection attack payloads |
| Phishing | combined_phishing_dataset_15000.csv | Multilingual phishing & legitimate emails (15K samples) |

---

## 🔮 Future Work

- [ ] **Raspberry Pi 4 Integration:** Real-time packet capture via Scapy/tcpdump
- [ ] **Fusion Layer:** Risk scoring engine combining all four model outputs
- [ ] **Dashboard:** Flask + Socket.IO real-time threat visualization
- [ ] **Edge Optimization:** ONNX/TensorRT conversion for sub-100ms inference on Pi 4
- [ ] **SSTI Improvement:** Address class imbalance via synthetic data generation
- [ ] **Model Drift Detection:** Automated retraining pipeline

---

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request for:
- Dataset expansions
- Model architecture improvements
- Additional attack class coverage
- Documentation enhancements

---

## 📄 License

This project is licensed under the MIT License. See `LICENSE` for details.

---

<div align="center">
  <b>Built with ❤️ for a safer internet.</b>
</div>

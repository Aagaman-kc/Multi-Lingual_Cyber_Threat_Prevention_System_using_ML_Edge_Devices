

import os
import pandas as pd
import numpy as np
import re
import string
import math
from urllib.parse import urlparse
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import json

# -------------------- Configuration --------------------
PLOT_DIR = "plots"
os.makedirs(PLOT_DIR, exist_ok=True)

# -------------------- Feature extraction --------------------
suspicious_keywords = ['login', 'signin', 'verify', 'update', 'banking', 'account', 'secure', 'ebay', 'paypal']
brand_keywords = ['paypal','bank','amazon','google','facebook','apple','microsoft']
bad_tlds = ['xyz','top','gq','ml','cf','tk','club','click','zip','loan','work']

def entropy(s):
    if not isinstance(s, str) or len(s) == 0:
        return 0
    probs = [s.count(c)/len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)

def extract_features(url):
    if not isinstance(url, str):
        url = str(url)
    features = {}
    parsed = urlparse(url)
    domain = parsed.netloc if parsed.netloc else url
    path = parsed.path
    query = parsed.query
    tld = domain.split('.')[-1] if '.' in domain else ''
    sld = domain.split('.')[0] if '.' in domain else domain

    # A. URL structure
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

    # B. Domain
    features['domain_length'] = len(domain)
    features['sld_length'] = len(sld)
    features['tld_length'] = len(tld)
    features['bad_tld_flag'] = int(tld in bad_tlds)
    features['has_ip'] = int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', domain)))
    features['numeric_domain'] = int(domain.replace('.', '').isdigit())
    features['domain_tokens'] = len(sld.split('-'))

    # C. Path / query
    features['path_length'] = len(path)
    features['num_directories'] = path.count('/')
    features['query_length'] = len(query)
    features['has_hex_encoding'] = int(bool(re.search(r'%[0-9a-fA-F]{2}', url)))
    features['repeated_chars'] = int(bool(re.search(r'(.)\1{3,}', url)))

    # D. Keywords
    features['has_suspicious_words'] = int(any(word in url.lower() for word in suspicious_keywords))
    features['brand_mimic'] = int(any(brand in url.lower() for brand in brand_keywords))
    features['has_unicode_or_punycode'] = int('xn--' in url.lower() or any(ord(c) > 127 for c in url))

    return features

# -------------------- Load and clean data --------------------
print("Loading URLsdata.csv ...")
df = pd.read_csv('URLsdata.csv', encoding='latin1')

# Clean type column: ensure string, fill NaN, remove control chars
df['type'] = df['type'].astype(str).fillna('').apply(lambda x: re.sub(r'[\x00-\x1F\x7F]', '', x))
df['type'] = df['type'].str.lower().str.strip()

valid_types = ['benign', 'phishing', 'malware', 'defacement']
df = df[df['type'].isin(valid_types)]

# Encode labels
label_encoder = LabelEncoder()
df['label'] = label_encoder.fit_transform(df['type'])

# Extract features
print("Extracting features (this may take several minutes)...")
feature_dicts = df['url'].apply(extract_features)
X = pd.DataFrame(feature_dicts.tolist())
y = df['label']

print(f"Features shape: {X.shape}")
print(f"Class distribution:\n{df['type'].value_counts()}")

# -------------------- Train / test split --------------------
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# -------------------- Train & evaluate models --------------------
models = {
    'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
    'K-Nearest Neighbors': KNeighborsClassifier(n_neighbors=5)
}

results = {}
for name, model in models.items():
    print(f"\nTraining {name}...")
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    results[name] = acc
    print(f"Accuracy: {acc:.4f}")
    print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))

    # Save confusion matrix plot
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(6,5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=label_encoder.classes_,
                yticklabels=label_encoder.classes_)
    plt.title(f'Confusion Matrix - {name}')
    plt.ylabel('True label')
    plt.xlabel('Predicted label')
    plt.tight_layout()
    plt.savefig(os.path.join(PLOT_DIR, f'confusion_matrix_{name.replace(" ", "_")}.png'))
    plt.close()

# Keep the Random Forest model for saving
best_model = models['Random Forest']

# -------------------- Save model & helpers --------------------
joblib.dump(best_model, 'rf_url_model.pkl')
joblib.dump(label_encoder, 'label_encoder.pkl')
joblib.dump(list(X.columns), 'feature_columns.pkl')

# -------------------- Additional plots for report --------------------

# 1) Distribution of URL types (bar plot)
plt.figure(figsize=(6,4))
sns.countplot(x='type', data=df, order=df['type'].value_counts().index)
plt.title('Distribution of URL Types')
plt.xlabel('Type')
plt.ylabel('Count')
plt.tight_layout()
plt.savefig(os.path.join(PLOT_DIR, 'class_distribution.png'))
plt.close()

# 2) Feature correlation heatmap (only numeric)
numeric_df = X.copy()
numeric_df['label'] = y
plt.figure(figsize=(24,12))
sns.heatmap(numeric_df.corr(), annot=True, fmt=".2f", cmap="coolwarm")
plt.title('Feature Correlation Heatmap')
plt.tight_layout()
plt.savefig(os.path.join(PLOT_DIR, 'feature_correlation_heatmap.png'))
plt.close()

# 3) Model accuracy comparison bar chart
plt.figure(figsize=(6,4))
plt.bar(results.keys(), results.values(), color=['skyblue', 'salmon'])
plt.title('Model Accuracy Comparison')
plt.ylabel('Accuracy')
plt.ylim(0,1)
plt.xticks(rotation=15)
plt.grid(axis='y')
plt.tight_layout()
plt.savefig(os.path.join(PLOT_DIR, 'model_accuracy_comparison.png'))
plt.close()

# 4) Distribution of top 5 features (like in notebook)
main_features = ['url_length', 'num_digits', 'num_special_chars', 'num_subdomains', 'url_entropy']
for feature in main_features:
    plt.figure(figsize=(6,4))
    plt.hist(X[feature], bins=40, color='skyblue', edgecolor='black')
    plt.title(f'Distribution of {feature}')
    plt.xlabel(feature)
    plt.ylabel('Frequency')
    plt.tight_layout()
    plt.savefig(os.path.join(PLOT_DIR, f'hist_{feature}.png'))
    plt.close()

# 5) Save evaluation metrics to JSON for later reference
metrics = {
    'accuracy': results['Random Forest'],
    'classification_report': classification_report(y_test, best_model.predict(X_test), target_names=label_encoder.classes_, output_dict=True),
    'class_distribution': df['type'].value_counts().to_dict(),
    'feature_names': list(X.columns)
}
with open('evaluation_metrics.json', 'w') as f:
    json.dump(metrics, f, indent=2)

print("\n✅ All done!")
print(f"   - Model saved as 'rf_url_model.pkl'")
print(f"   - Label encoder saved as 'label_encoder.pkl'")
print(f"   - Feature columns saved as 'feature_columns.pkl'")
print(f"   - Plots saved in '{PLOT_DIR}/' directory")
print(f"   - Metrics saved in 'evaluation_metrics.json'")
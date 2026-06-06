import pandas as pd
import numpy as np
from sklearn.utils import shuffle

# ==========================
# 1. English from Phishing_Email.csv
# ==========================
print("Loading Phishing_Email.csv...")
eng = pd.read_csv("Phishing_Email.csv")
eng = eng.rename(columns={'Email Text': 'text', 'Email Type': 'label'})
eng['label'] = eng['label'].map({'Safe Email': 0, 'Phishing Email': 1})
eng['language'] = 'English'
print(f"English: {len(eng)} samples (0:{sum(eng['label']==0)}, 1:{sum(eng['label']==1)})")

# ==========================
# 2. Hindi from data-augmented.csv
# ==========================
print("Loading data-augmented.csv (Hindi column)...")
hin = pd.read_csv("data-augmented.csv")
hin = hin[['text_hi', 'labels']].rename(columns={'text_hi': 'text', 'labels': 'label'})
hin['label'] = hin['label'].map({'ham': 0, 'spam': 1})
hin = hin.dropna(subset=['text'])
hin['language'] = 'Hindi'
print(f"Hindi: {len(hin)} samples (0:{sum(hin['label']==0)}, 1:{sum(hin['label']==1)})")

# ==========================
# 3. Nepali from three CSV files
# ==========================
print("Loading Nepali datasets...")
nepali_files = [
    "nepali_phishing_dataset.csv",
    "nepali_phishing_dataset_1000.csv",
    "nepali_phishing_dataset_3.csv"
]
nepali_dfs = []
for fname in nepali_files:
    try:
        df_n = pd.read_csv(fname)
        df_n = df_n[['text', 'label']]
        df_n['label'] = df_n['label'].map({'Safe': 0, 'Phishing': 1})
        df_n['language'] = 'Nepali'
        nepali_dfs.append(df_n)
        print(f"  Loaded {fname}: {len(df_n)} samples")
    except FileNotFoundError:
        print(f"  Warning: {fname} not found, skipping")
    except Exception as e:
        print(f"  Error loading {fname}: {e}")

nep = pd.concat(nepali_dfs, ignore_index=True) if nepali_dfs else pd.DataFrame()
if not nep.empty:
    nep = nep.drop_duplicates(subset='text', keep='first')
    print(f"Nepali total: {len(nep)} samples (0:{sum(nep['label']==0)}, 1:{sum(nep['label']==1)})")

# ==========================
# 4. Combine all
# ==========================
df = pd.concat([eng, hin, nep], ignore_index=True)
df = df.drop_duplicates(subset='text', keep='first')
print(f"\nCombined before balancing: {len(df)} samples")

# ==========================
# 5. Add 2% label noise to prevent overfitting
# ==========================
np.random.seed(42)
noise_mask = np.random.random(len(df)) < 0.02
df['label'] = df['label'].astype(int)
df.loc[noise_mask, 'label'] = 1 - df.loc[noise_mask, 'label']
print(f"Added label noise: flipped {noise_mask.sum()} labels ({100*noise_mask.sum()/len(df):.1f}%)")

# ==========================
# 6. Shuffle and save
# ==========================
df = shuffle(df, random_state=42).reset_index(drop=True)
output_file = "final_phishing_dataset.csv"
df[['text', 'label', 'language']].to_csv(output_file, index=False)
print(f"\nSaved {len(df)} samples to {output_file}")
print(f"Final class distribution: 0:{sum(df['label']==0)}, 1:{sum(df['label']==1)}")
print(f"Language distribution:\n{df['language'].value_counts()}")
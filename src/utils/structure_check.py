#!/usr/bin/env python3
"""
Restructure MAJOR_PROJECT into a clean GitHub repository layout.
Run this script from the project root.
"""

import os
import shutil
import glob

# Define new structure
STRUCTURE = {
    "notebooks": [
        "Application_Attack_Detection/*.ipynb",
        "Deep_Packet_Inspection_Model/*.ipynb",
        "Malicious URL Detection Model/*.ipynb",
        "Phishing_Email_Detection/*.ipynb",
        "email_phishing/*.ipynb",
        "*.ipynb",
    ],
    "models/url": [
        "Malicious URL Detection Model/rf_url_model.pkl",
        "Malicious URL Detection Model/feature_columns.pkl",
        "Malicious URL Detection Model/label_encoder.pkl",
    ],
    "models/dpi": [
        "Deep_Packet_Inspection_Model/dpi_rf_pipeline.pkl",
        "Deep_Packet_Inspection_Model/dpi_xgboost_model.pkl",
        "Deep_Packet_Inspection_Model/cat_imputer.pkl",
        "Deep_Packet_Inspection_Model/num_imputer.pkl",
        "Deep_Packet_Inspection_Model/categorical_cols.pkl",
        "Deep_Packet_Inspection_Model/numeric_cols.pkl",
        "Deep_Packet_Inspection_Model/label_encoders.pkl",
        "Deep_Packet_Inspection_Model/onehot_encoder.pkl",
        "Deep_Packet_Inspection_Model/scaler.pkl",
    ],
    "models/app_attack": [
        "Application_Attack_Detection/Application_Attack_Detection/models/*.pkl",
    ],
    "models/email_phishing": [
        "email_phishing/phishing_model.pkl",
        "Phishing_Email_Detection/phishing_xgboost_100k.pkl",
    ],
    "data/url": [
        "Malicious URL Detection Model/URLsdata.csv",
    ],
    "data/dpi": [
        "Deep_Packet_Inspection_Model/UNSW_NB15_training-set.csv",
        "Deep_Packet_Inspection_Model/UNSW_NB15_testing-set.csv",
    ],
    "data/app_attack": [
        "Application_Attack_Detection/clean_payloads.csv",
    ],
    "data/email_phishing": [
        "email_phishing/final_phishing_dataset.csv",
        "email_phishing/data_collection/*.csv",
        "Phishing_Email_Detection/combined_phishing_dataset_15000.csv",
        "Phishing_Email_Detection/expanded_phishing_dataset_100k.csv",
        "CEAS_08.csv",
    ],
    "src/capture": [
        "Pi_prevention/capture_layer/*.py",
        "laptop_server/data_layer/**/*.py",
        "Pi_prevention/data_layer/**/*.py",
    ],
    "src/detection": [
        "Pi_prevention/detection_engine/*.py",
        "Pi_prevention/detection_engine/**/*.py",
    ],
    "src/dashboard": [
        "laptop_server/presentation_layer/*.py",
        "laptop_server/presentation_layer/**/*.py",
        "Pi_prevention/presentation_layer/*.py",
    ],
    "src/utils": [
        "Pi_prevention/config/*.py",
        "laptop_server/*.py",
        "Pi_prevention/*.py",
        "*.py",
    ],
    "scripts": [
        "Test_Attacks/*.py",
        "server/*.py",
        "laptop_server/run_server.py",
        "Pi_prevention/run_remote.py",
        "Pi_prevention/setup.py",
        "Malicious URL Detection Model/predict_URL.py",
        "Malicious URL Detection Model/train_model.py",
    ],
    "docs/images": [
        "Images/*.png",
        "readme_image/*.png",
        "readme_image/*.jpg",
        "Phishing_Email_Detection/*.png",
        "email_phishing/figures/*.png",
        "Malicious URL Detection Model/plots/*.png",
    ],
    "docs/other": [
        "Docs/*.md",
        "*.txt",
        "structure.txt",
    ],
}

# Files/folders to ignore (not moved, and will be added to .gitignore)
IGNORE_PATTERNS = [
    "torch_gpu_env/",
    "__pycache__/",
    "*.pyc",
    ".ipynb_checkpoints/",
    "venv/",
    "env/",
    "results/",
    "results_weighted/",
    "final_multilingual_model_old/",
    "figures_old/",
    "*.log",
    ".DS_Store",
]

def move_file(src, dst):
    """Move a single file, creating parent directories."""
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    print(f"Move: {src} -> {dst}")
    shutil.move(src, dst)

def copy_file(src, dst):
    """Copy a single file, creating parent directories."""
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    print(f"Copy: {src} -> {dst}")
    shutil.copy2(src, dst)

def main():
    # First, create the new directories (but we'll let move/copy create them)
    # We'll process all source patterns
    for target_dir, patterns in STRUCTURE.items():
        for pattern in patterns:
            # Expand glob patterns
            for src in glob.glob(pattern, recursive=True):
                # Determine destination filename
                base = os.path.basename(src)
                dst = os.path.join(target_dir, base)
                # If there's a subfolder structure inside the pattern, preserve it? 
                # For simplicity, we just take basename. 
                # For deeper hierarchy (e.g., models/app_attack/we may want to keep subdir)
                # For now, we flatten. We can improve later.
                move_file(src, dst)

    # Handle top-level files that are not covered yet
    top_files = [
        "requirements.txt",
        "README.md",
        "LICENSE",  # if exists
    ]
    for f in top_files:
        if os.path.exists(f):
            copy_file(f, ".")

    # Remove empty directories that were moved
    # This is optional; we'll just list directories to delete if empty
    dirs_to_clean = [
        "Application_Attack_Detection",
        "Deep_Packet_Inspection_Model",
        "Malicious URL Detection Model",
        "Phishing_Email_Detection",
        "email_phishing",
        "Images",
        "readme_image",
        "laptop_server",
        "Pi_prevention",
        "Test_Attacks",
        "server",
        "Docs",
        "data_collection",  # may be empty after move
    ]
    for d in dirs_to_clean:
        if os.path.exists(d) and not os.listdir(d):
            os.rmdir(d)
            print(f"Removed empty directory: {d}")
        elif os.path.exists(d):
            print(f"Directory not empty, skipping: {d}")

    # Generate .gitignore
    with open(".gitignore", "w") as f:
        f.write("# Virtual environments\n")
        f.write("torch_gpu_env/\n")
        f.write("venv/\n")
        f.write("env/\n")
        f.write("__pycache__/\n")
        f.write("*.pyc\n")
        f.write(".ipynb_checkpoints/\n")
        f.write("results/\n")
        f.write("results_weighted/\n")
        f.write("final_multilingual_model_old/\n")
        f.write("figures_old/\n")
        f.write("*.log\n")
        f.write(".DS_Store\n")
        f.write("# Large data files (optional, keep if needed)\n")
        f.write("# data/*/*.csv\n")
        f.write("# models/*/*.pkl\n")
        f.write("# torch_gpu_env/\n")
        f.write("# etc.\n")

    print("\nRestructuring complete. Review the new layout and adjust any remaining files manually.")
    print("Remember to check if any notebooks need path adjustments.")

if __name__ == "__main__":
    main()
"""
ShieldGuard AI - URL Phishing Classifier Training Pipeline
Trains an ensemble classifier (Random Forest / XGBoost) on lexical & host features.
"""

import numpy as np
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score


def generate_synthetic_url_dataset(num_samples: int = 1000):
    """
    Generates balanced benchmark dataset of feature vectors:
    [url_length, hostname_length, num_dots, num_hyphens, is_ip, entropy, is_typo, is_homo, num_keywords]
    """
    np.random.seed(42)
    X = []
    y = []

    for _ in range(num_samples // 2):
        # Legitimate URLs: shorter, low hyphens, no typos, low entropy
        length = np.random.randint(15, 60)
        host_len = np.random.randint(8, 25)
        dots = np.random.choice([1, 2], p=[0.7, 0.3])
        hyphens = np.random.choice([0, 1], p=[0.8, 0.2])
        is_ip = 0
        entropy = np.random.uniform(2.1, 3.4)
        is_typo = 0
        is_homo = 0
        keywords = np.random.choice([0, 1], p=[0.9, 0.1])
        X.append([length, host_len, dots, hyphens, is_ip, entropy, is_typo, is_homo, keywords])
        y.append(0)  # Safe

    for _ in range(num_samples // 2):
        # Malicious / Phishing URLs: longer, high hyphens, high entropy, keywords, typos
        length = np.random.randint(45, 140)
        host_len = np.random.randint(20, 50)
        dots = np.random.randint(2, 6)
        hyphens = np.random.randint(1, 5)
        is_ip = np.random.choice([0, 1], p=[0.8, 0.2])
        entropy = np.random.uniform(3.8, 4.9)
        is_typo = np.random.choice([0, 1], p=[0.4, 0.6])
        is_homo = np.random.choice([0, 1], p=[0.7, 0.3])
        keywords = np.random.randint(1, 4)
        X.append([length, host_len, dots, hyphens, is_ip, entropy, is_typo, is_homo, keywords])
        y.append(1)  # Phishing

    return np.array(X), np.array(y)


def train():
    print("[*] Generating URL training features...")
    X, y = generate_synthetic_url_dataset(2000)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("[*] Training Random Forest URL Threat Classifier...")
    model = RandomForestClassifier(n_estimators=100, max_depth=8, random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    print("[+] Model Evaluation Report:")
    print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))
    print(f"ROC-AUC Score: {roc_auc_score(y_test, y_prob):.4f}")

    # Save model weights
    with open("backend/ai_models/url_classifier.pkl", "wb") as f:
        pickle.dump(model, f)
    print("[+] Saved model weights to backend/ai_models/url_classifier.pkl")


if __name__ == "__main__":
    train()

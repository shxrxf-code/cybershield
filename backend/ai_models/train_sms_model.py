"""
ShieldGuard AI - SMS / Smishing NLP Classifier Training Pipeline
Trains a TF-IDF + Logistic Regression NLP model for smishing and banking fraud detection.
"""

import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report


DATASET = [
    # Clean messages (0)
    ("Hey are you coming to dinner tonight?", 0),
    ("Your grocery order has been delivered at the front door.", 0),
    ("Call me when you get a chance.", 0),
    ("Meeting is scheduled for 3pm in room B.", 0),
    ("Thanks for the update, see you tomorrow!", 0),
    ("Did you get the presentation slides I sent?", 0),
    ("Happy birthday! Wishing you an amazing year ahead.", 0),
    ("Can you please send me the report file?", 0),

    # Smishing / Phishing / Fraud (1)
    ("URGENT: Your Chase bank account has been suspended. Verify immediately at http://chase-verify-user.xyz", 1),
    ("Congratulations! You won a $1,000 Walmart gift card. Click to claim your prize now: http://tinyurl.com/win99", 1),
    ("Your USPS package is on hold due to missing address fee of $1.50. Pay now: http://usps-redelivery.top", 1),
    ("Security Alert: Unauthorized login attempt detected from Russia. Reset your password immediately.", 1),
    ("Binance Notice: Your account will be locked within 24 hours. Submit KYC at http://binance-kyc-auth.click", 1),
    ("You have an unpaid toll balance of $12.45. Avoid legal fees by paying at http://ezpass-toll-settlement.info", 1),
    ("Crypto Giveaway! Elon Musk is giving away 5,000 BTC. Connect your wallet to claim: http://airdrop-eth.xyz", 1),
    ("Wells Fargo Alert: Suspicious transaction of $849.00 detected. Reply YES or visit http://wf-fraud-check.com", 1)
]


def train():
    texts, labels = zip(*DATASET)
    # Duplicate samples for balance
    texts = texts * 20
    labels = labels * 20

    X_train, X_test, y_train, y_test = train_test_split(texts, labels, test_size=0.25, random_state=42)

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=1000)),
        ("clf", LogisticRegression(C=1.0, random_state=42))
    ])

    print("[*] Training SMS NLP Smishing Pipeline...")
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    print("[+] Model Evaluation Report:")
    print(classification_report(y_test, y_pred, target_names=["Safe", "Smishing"]))

    with open("backend/ai_models/sms_nlp_model.pkl", "wb") as f:
        pickle.dump(pipeline, f)
    print("[+] Saved model weights to backend/ai_models/sms_nlp_model.pkl")


if __name__ == "__main__":
    train()

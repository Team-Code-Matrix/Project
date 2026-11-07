"""
TrustShield ML Phishing Engine - Training Pipeline
Trains and serializes a high-accuracy, low-latency RandomForest classifier
to detect phishing URLs based on 15 deterministic features.
"""
import os
import sys
import json
import time
from typing import Tuple, List, Dict, Any

# Ensure backend root is on path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report

from ml.feature_extractor import FEATURE_NAMES, extract_features, features_to_vector

MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
MODEL_PATH = os.path.join(MODEL_DIR, "trustshield_phishing_model.joblib")
METADATA_PATH = os.path.join(MODEL_DIR, "model_metadata.json")

# Ground Truth Seed Corpus: High-Tenure Legitimate vs. Known Phishing Attacks
LEGITIMATE_SEEDS = [
    "https://www.google.com/search?q=cybersecurity+threat+intelligence",
    "https://github.com/torvalds/linux/commit/12345678",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://en.wikipedia.org/wiki/Computer_security",
    "https://aws.amazon.com/console/dashboard",
    "https://microsoft.com/en-us/windows/security",
    "https://apple.com/iphone-16/specs/",
    "https://paypal.com/myaccount/summary",
    "https://bankofamerica.com/online-banking/overview.go",
    "https://netflix.com/browse/genre/83",
    "https://bbc.com/news/technology-68192837",
    "https://cnn.com/world/security-briefing",
    "https://nih.gov/health-information/clinical-trials",
    "https://nasa.gov/missions/artemis/updates",
    "https://mit.edu/education/programs",
    "https://stanford.edu/academics/departments",
    "https://cloudflare.com/learning/security/what-is-zero-trust/",
    "https://stripe.com/docs/api/charges/create",
    "https://gitlab.com/gitlab-org/gitlab/-/pipelines",
    "https://stackoverflow.com/questions/20708940/calculate-entropy",
    "https://nytimes.com/section/technology",
    "https://reuters.com/business/finance/",
    "https://harvard.edu/programs/undergraduate",
    "https://zoom.us/join/meeting-room",
    "https://slack.com/workspace/general-channel",
    "https://atlassian.com/software/jira",
    "https://linkedin.com/in/security-researcher",
    "https://youtube.com/watch?v=dQw4w9WgXcQ",
    "https://spotify.com/us/premium/",
    "https://reddit.com/r/netsec/comments/sample",
]

PHISHING_SEEDS = [
    "http://login.micros0ft-security-auth.xyz/verify?token=98214",
    "http://paypa1-account-resolution.top/webscr?cmd=_login-run",
    "https://g00gle-drive-shared-doc.cf/auth/login.html",
    "http://metamask-verify-seed-phrase.icu/wallet/restore",
    "https://appleid-support-icloud.tk/verification/index.php",
    "http://185.220.101.45/login/office365/portal.php",
    "http://netflix-billing-update.buzz/session/update-payment",
    "https://bankofamerica-alert-security.live/update/auth",
    "http://chase-urgent-notice.rest/sign-in/verify-identity",
    "https://amazon-order-confirmation-update.xyz/login?session=exp",
    "http://xn--microsft-07a.com/login/auth-check",
    "http://update-chrome-security-patch.top/download/installer.exe",
    "http://bit.ly/secure-account-verify-302-urgent",
    "http://login-helpdesk-corp-support.fit/portal/adfs-login",
    "http://194.26.29.112/admin/credential_harvester.php",
    "https://coinbase-auth-verify-kyc.cam/wallet/sign-in",
    "http://docusign-envelope-review.click/document/sign",
    "http://steamcommunity-gift-trade.work/tradeoffer/new",
    "http://binance-account-freeze-unlock.monster/security/unlock",
    "https://wellsfargo-notice-security.surf/banking/login",
    "http://walmart-claim-gift-card.top/winner/redeem",
    "http://usps-tracking-package-redelivery.live/redelivery/pay-fee",
    "https://dhl-express-customs-duty.sbs/track/shipment-hold",
    "http://fedex-delivery-pending-exception.xyz/address/confirm",
    "http://dropbox-shared-confidential-file.monster/login.php",
    "http://telegram-premium-free-activation.top/bot/auth",
    "http://login.offic365-onedrive-share.cf/login.srf",
    "http://45.142.166.11/secure-banking-login/index.html",
    "https://adobe-acrobat-sign-verify.fit/sign/document",
    "http://login.paypal.com.account-warning-notice.top/cgi-bin/webscr",
]

def generate_synthetic_dataset() -> Tuple[List[Dict[str, float]], List[int]]:
    """
    Constructs a comprehensive, realistic, and balanced dataset of 600+ feature vectors.
    Returns (feature_dicts, labels) where 0 = Legitimate, 1 = Phishing.
    """
    features: List[Dict[str, float]] = []
    labels: List[int] = []

    # 1. Process Seeds
    for url in LEGITIMATE_SEEDS:
        vec = extract_features(url, scan_payload={"domainAgeDays": 3650, "rdapTenureVerified": True})
        features.append(vec)
        labels.append(0)

    for url in PHISHING_SEEDS:
        vec = extract_features(url, scan_payload={"domainAgeDays": 3, "hasPasswordInput": True, "redirectHops": 1})
        features.append(vec)
        labels.append(1)

    # 2. Expand Diverse Legitimate Patterns (300+ samples)
    tlds_legit = ["com", "org", "net", "io", "edu", "gov", "co.uk", "de", "ca", "jp"]
    brands_legit = [
        "google", "microsoft", "github", "amazon", "apple", "netflix", "stripe",
        "cloudflare", "gitlab", "spotify", "reddit", "linkedin", "atlassian",
        "dropbox", "zoom", "salesforce", "adobe", "oracle", "intel", "cisco"
    ]
    paths_legit = [
        "", "about", "contact", "docs/getting-started", "api/v2/items",
        "products/hardware/models", "support/knowledge-base/article/4819",
        "blog/2026/03/quarterly-security-retrospective", "research/papers/transformer-attention",
        "legal/privacy-policy", "pricing/enterprise", "community/forum/topics",
        "catalog/items?category=electronics&sort=price_asc&page=2"
    ]

    for brand in brands_legit:
        for tld in tlds_legit[:3]:
            for path in paths_legit[:5]:
                sub = "www" if np.random.rand() > 0.4 else ("api" if np.random.rand() > 0.5 else "docs")
                url = f"https://{sub}.{brand}.{tld}/{path}" if path else f"https://{sub}.{brand}.{tld}"
                payload = {
                    "domainAgeDays": int(np.random.randint(500, 7500)),
                    "rdapTenureVerified": True,
                    "hasPasswordInput": False,
                    "redirectHops": 0,
                }
                features.append(extract_features(url, payload))
                labels.append(0)

    # Additional educational and government domains
    edu_gov = ["harvard.edu", "mit.edu", "ox.ac.uk", "nasa.gov", "nih.gov", "cdc.gov", "whitehouse.gov", "cisa.gov"]
    for eg in edu_gov:
        for path in ["research/publications", "data/annual-report", "about/leadership", "news/press-release"]:
            url = f"https://www.{eg}/{path}"
            payload = {"domainAgeDays": 6000, "rdapTenureVerified": True, "hasPasswordInput": False}
            features.append(extract_features(url, payload))
            labels.append(0)

    # 3. Expand Diverse Phishing Patterns (300+ samples)
    phish_tlds = ["xyz", "top", "tk", "icu", "buzz", "fit", "rest", "cam", "live", "monster", "sbs", "click", "work"]
    targeted_brands = ["microsoft", "paypal", "google", "apple", "netflix", "amazon", "chase", "bankofamerica", "metamask", "binance", "coinbase"]
    deceptive_prefixes = ["login", "signin", "auth", "secure", "verify", "account", "update", "recovery", "portal", "support-desk", "webscr"]
    phish_substitutions = [
        ("o", "0"), ("l", "1"), ("s", "5"), ("w", "vv"), ("e", "3")
    ]

    for brand in targeted_brands:
        for tld in phish_tlds[:4]:
            # Typosquat brand variant
            typo_brand = brand
            for orig, rep in phish_substitutions:
                if orig in typo_brand:
                    typo_brand = typo_brand.replace(orig, rep, 1)
                    break

            for prefix in deceptive_prefixes[:4]:
                scheme = "http" if np.random.rand() > 0.3 else "https"
                url = f"{scheme}://{prefix}.{typo_brand}-support.{tld}/auth/login.php?session={np.random.randint(1000, 99999)}"
                payload = {
                    "domainAgeDays": int(np.random.randint(1, 14)),
                    "hasPasswordInput": True,
                    "redirectHops": int(np.random.choice([0, 1, 2])),
                    "phishingDetonation": {
                        "domHeuristics": {"passwordInputsCount": 1, "otpFieldsCount": 1},
                        "redirectChain": [{"hop": 1}, {"hop": 2}]
                    }
                }
                features.append(extract_features(url, payload))
                labels.append(1)

    # IP-based credential harvesting
    ip_addrs = ["185.220.101.45", "194.26.29.112", "45.142.166.11", "91.240.118.7", "103.151.125.88", "198.51.100.24"]
    for ip in ip_addrs:
        for path in ["office365/login.html", "banking/signin.aspx", "wallet/seed-phrase.php", "auth/verify.cgi"]:
            url = f"http://{ip}/{path}"
            payload = {"domainAgeDays": 0, "hasPasswordInput": True, "redirectHops": 0}
            features.append(extract_features(url, payload))
            labels.append(1)

    # Punycode / IDN lookalikes
    puny_hosts = ["xn--app-9oa.com", "xn--microsft-07a.com", "xn--gogle-qoa.com", "xn--paypa-vva.com", "xn--chse-pra.com"]
    for ph in puny_hosts:
        url = f"https://{ph}/login/verify-credentials"
        payload = {"domainAgeDays": 5, "hasPasswordInput": True, "redirectHops": 1}
        features.append(extract_features(url, payload))
        labels.append(1)

    # High entropy DGA domains
    for _ in range(30):
        chars = "abcdefghijklmnopqrstuvwxyz0123456789"
        dga_stem = "".join(np.random.choice(list(chars), size=24))
        tld = np.random.choice(phish_tlds)
        url = f"http://{dga_stem}.{tld}/drop/payload.exe"
        payload = {"domainAgeDays": 1, "hasPasswordInput": False, "redirectHops": 1}
        features.append(extract_features(url, payload))
        labels.append(1)

    return features, labels

def train_and_save(model_path: str = MODEL_PATH, metadata_path: str = METADATA_PATH) -> Dict[str, Any]:
    """
    Executes dataset synthesis, feature matrix compilation, train/test split,
    model training, evaluation, and serialization.
    """
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    print("[*] Generating balanced phishing vs. legitimate training dataset...")

    feature_dicts, labels = generate_synthetic_dataset()
    X = np.array([features_to_vector(fd) for fd in feature_dicts], dtype=np.float32)
    y = np.array(labels, dtype=np.int32)

    total_samples = len(y)
    phish_count = int(np.sum(y == 1))
    legit_count = int(np.sum(y == 0))
    print(f"[+] Total samples: {total_samples} ({legit_count} Legitimate, {phish_count} Phishing)")

    # 80/20 train/test split without data leakage
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"[+] Train set: {len(y_train)} samples, Test set: {len(y_test)} samples")

    # Train Tuned Random Forest Classifier
    print("[*] Training RandomForestClassifier (100 estimators, balanced weights)...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    # Evaluate Model on Unseen Test Set
    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    accuracy = float(accuracy_score(y_test, y_pred))
    precision = float(precision_score(y_test, y_pred, zero_division=0))
    recall = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))

    print("\n" + "=" * 60)
    print("  TRUSTSHIELD ML PHISHING MODEL - EVALUATION RESULTS")
    print("=" * 60)
    print(f"  Accuracy:  {accuracy * 100:.2f}%")
    print(f"  Precision: {precision * 100:.2f}%")
    print(f"  Recall:    {recall * 100:.2f}%")
    print(f"  F1-Score:  {f1 * 100:.2f}%")
    print("=" * 60)
    print(classification_report(y_test, y_pred, target_names=["LEGITIMATE", "PHISHING"]))

    # Calculate Feature Importances
    importances = clf.feature_importances_
    feat_importance_dict = {
        name: round(float(imp), 4)
        for name, imp in sorted(zip(FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True)
    }

    # Serialize Model (.joblib)
    joblib.dump(clf, model_path, compress=3)
    print(f"[+] Serialized trained model to: {model_path}")

    # Serialize Metadata (.json)
    metadata = {
        "model_name": "TrustShield-RF-PhishGuard",
        "version": "v1.2.0",
        "algorithm": "RandomForestClassifier",
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_samples": total_samples,
        "train_samples": len(y_train),
        "test_samples": len(y_test),
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "feature_names": FEATURE_NAMES,
        "feature_importances": feat_importance_dict,
    }

    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"[+] Serialized model metadata to: {metadata_path}")

    return metadata

if __name__ == "__main__":
    train_and_save()


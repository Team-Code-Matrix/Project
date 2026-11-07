"""
TrustShield ML Phishing Engine - Predictor & Attribution Service
Loads the serialized RandomForest phishing model and executes real-time
predict_proba inference and feature contribution attribution.
"""
import os
import sys
import json
import time
import threading
from typing import Dict, Any, List, Optional

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import joblib
import numpy as np

from ml.feature_extractor import FEATURE_NAMES, extract_features, features_to_vector

MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
MODEL_PATH = os.path.join(MODEL_DIR, "trustshield_phishing_model.joblib")
METADATA_PATH = os.path.join(MODEL_DIR, "model_metadata.json")

_model_lock = threading.Lock()
_cached_model = None
_cached_metadata: Optional[Dict[str, Any]] = None

def get_model_and_metadata():
    """Thread-safe lazy loader for the trained ML model and metadata."""
    global _cached_model, _cached_metadata
    if _cached_model is not None and _cached_metadata is not None:
        return _cached_model, _cached_metadata

    with _model_lock:
        if _cached_model is not None and _cached_metadata is not None:
            return _cached_model, _cached_metadata

        if not os.path.exists(MODEL_PATH) or not os.path.exists(METADATA_PATH):
            print("[*] Model not found on disk. Initiating automated training...")
            from ml.train_model import train_and_save
            train_and_save(MODEL_PATH, METADATA_PATH)

        try:
            _cached_model = joblib.load(MODEL_PATH)
            with open(METADATA_PATH, "r", encoding="utf-8") as f:
                _cached_metadata = json.load(f)
            print(f"[+] Successfully loaded TrustShield ML model ({_cached_metadata.get('version', 'v1.2.0')})")
        except Exception as e:
            print(f"[!] Error loading model from {MODEL_PATH}: {e}. Retraining...")
            from ml.train_model import train_and_save
            train_and_save(MODEL_PATH, METADATA_PATH)
            _cached_model = joblib.load(MODEL_PATH)
            with open(METADATA_PATH, "r", encoding="utf-8") as f:
                _cached_metadata = json.load(f)

        return _cached_model, _cached_metadata

def format_feature_explanation(name: str, value: float, is_phishing: bool) -> str:
    """Provides human-readable telemetry context for top contributing features."""
    explanations = {
        "domain_age_indicator": f"Domain tenure score: {value:.2f} ({'Recent or unverified registration' if value < 0.3 else 'Established historical tenure'}).",
        "redirect_count": f"Routing chain: {int(value)} redirect hop(s) observed.",
        "digit_to_letter_ratio": f"Alphanumeric variance: {value:.2f} digit-to-letter ratio in hostname/path.",
        "has_form_or_password_input": "Credential intake: Form or password authentication inputs detected.",
        "is_suspicious_tld": "Top-Level Domain: Registered on high-risk, bulletproof, or low-cost abuse TLD.",
        "url_length": f"Lexical length: Long URL footprint ({int(value)} characters).",
        "is_https": "Transport security: Communicating over plaintext HTTP without active TLS encryption." if value == 0 else "Transport security: HTTPS negotiated.",
        "special_char_count": f"Special characters: {int(value)} punctuation/symbol characters in URL token.",
        "shannon_entropy": f"Shannon entropy: {value:.2f} lexical randomness.",
        "is_ip_in_url": "Direct IP resolution: Hostname uses literal IP address instead of registered domain.",
        "brand_keyword_presence": "Brand impersonation: High-value service brand or auth keyword on third-party host.",
        "path_depth": f"Path structure: Deep hierarchical directory nesting ({int(value)} levels).",
        "query_param_count": f"Query parameters: {int(value)} parameter key-value pairs attached.",
        "subdomain_count": f"Subdomain hierarchy: {int(value)} nested subdomain level(s).",
        "is_punycode": "IDN deception: Punycode homograph encoding (xn--) detected.",
    }
    return explanations.get(name, f"{name}: {value}")

def predict_url(url: str, scan_payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Executes ML inference on a URL and returns:
    - prediction: 'PHISHING' or 'LEGITIMATE'
    - confidence: float 0.0 - 1.0
    - phishing_probability: float 0.0 - 1.0
    - legitimate_probability: float 0.0 - 1.0
    - top_contributing_features: list of weighted feature attributions
    - features_extracted: dictionary of 15 extracted features
    - model_version: str
    - algorithm: str
    - timestamp: ISO 8601 string
    """
    model, metadata = get_model_and_metadata()
    features = extract_features(url, scan_payload)
    vector = np.array([features_to_vector(features)], dtype=np.float32)

    probabilities = model.predict_proba(vector)[0]
    legit_prob = float(probabilities[0])
    phish_prob = float(probabilities[1])

    is_phishing = phish_prob >= 0.50
    prediction = "PHISHING" if is_phishing else "LEGITIMATE"
    confidence = phish_prob if is_phishing else legit_prob

    # Feature contribution attribution:
    # Feature importance * normalized signal magnitude
    importances = metadata.get("feature_importances", {})
    contributions = []

    for name in FEATURE_NAMES:
        val = features.get(name, 0.0)
        imp = importances.get(name, 0.05)
        # Normalize continuous features for fair comparison
        norm_val = val
        if name == "url_length":
            norm_val = min(1.0, val / 120.0)
        elif name == "shannon_entropy":
            norm_val = min(1.0, max(0.0, (val - 2.0) / 3.0))
        elif name == "digit_to_letter_ratio":
            norm_val = min(1.0, val * 2.0)
        elif name == "special_char_count":
            norm_val = min(1.0, val / 6.0)
        elif name == "path_depth":
            norm_val = min(1.0, val / 5.0)
        elif name == "query_param_count":
            norm_val = min(1.0, val / 4.0)
        elif name == "domain_age_indicator":
            # For phishing, lower age indicator contributes more risk
            norm_val = 1.0 - val if is_phishing else val
        elif name == "is_https":
            norm_val = 1.0 - val if is_phishing else val

        weight = round(float(imp * norm_val), 4)
        contributions.append({
            "feature": name,
            "value": round(float(val), 4),
            "modelImportance": imp,
            "contributionWeight": weight,
            "explanation": format_feature_explanation(name, val, is_phishing)
        })

    # Sort top contributors
    contributions.sort(key=lambda x: x["contributionWeight"], reverse=True)
    top_contributing = contributions[:5]

    return {
        "prediction": prediction,
        "confidence": round(confidence, 4),
        "phishing_probability": round(phish_prob, 4),
        "legitimate_probability": round(legit_prob, 4),
        "top_contributing_features": top_contributing,
        "features_extracted": features,
        "model_version": metadata.get("version", "v1.2.0"),
        "algorithm": metadata.get("algorithm", "RandomForestClassifier"),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


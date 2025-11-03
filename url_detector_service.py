# ============================================================
# 🔦 URL PHISHING DETECTOR SERVICE (Enhanced Model) - FIXED
# ============================================================

import re
import joblib
import numpy as np
import pandas as pd
import string
from urllib.parse import urlparse
from scipy.sparse import csr_matrix, hstack

# === Updated filenames for enhanced model ===
MODEL_PKL = "url_detector_ENHANCED.pkl"
TFIDF_PKL = "url_tfidf_ENHANCED.pkl"
LE_PKL = "url_label_ENHANCED.pkl"

# --- Lazy-loaded globals ---
_xgb = None
_tfidf = None
_le = None


def _load_models():
    """Load joblib artifacts once (lazy)."""
    global _xgb, _tfidf, _le
    if _xgb is None or _tfidf is None or _le is None:
        print("Loading Enhanced ML models...")
        try:
            _xgb = joblib.load(MODEL_PKL)
            print(f"✓ Enhanced model loaded: {MODEL_PKL}")
            if hasattr(_xgb, 'n_features_in_'):
                print(f"  Model expects {_xgb.n_features_in_} features")
        except Exception as e:
            raise RuntimeError(f"Failed to load model '{MODEL_PKL}': {e}")
        try:
            _tfidf = joblib.load(TFIDF_PKL)
            print(f"✓ TF-IDF vectorizer loaded: {TFIDF_PKL}")
            if hasattr(_tfidf, 'vocabulary_'):
                print(f"  TF-IDF produces {len(_tfidf.vocabulary_)} features")
        except Exception as e:
            raise RuntimeError(f"Failed to load TF-IDF vectorizer '{TFIDF_PKL}': {e}")
        try:
            _le = joblib.load(LE_PKL)
            print(f"✓ Label encoder loaded: {LE_PKL}")
        except Exception as e:
            raise RuntimeError(f"Failed to load label encoder '{LE_PKL}': {e}")
        print("✅ All enhanced model components loaded successfully!\n")


# --- Utility functions ---
def clean_url(url: str) -> str:
    """Normalize URL: remove protocol and www, trim trailing slash."""
    url = str(url).strip()
    url = url.replace("https://", "").replace("http://", "").replace("www.", "")
    if url.endswith("/") and url.count("/") == 1:
        url = url[:-1]
    return url


def extract_advanced_features(url: str) -> dict:
    """Extract EXACT same features as training - 32 features total.
    
    This MUST match your training code exactly!
    """
    url = str(url)
    
    # Parse URL components
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
    except:
        domain = ""
        path = ""
    
    # Calculate length safely
    L = len(url) if len(url) > 0 else 1
    
    # Calculate entropy
    if len(url) > 0:
        entropy = -sum((url.count(c)/L)*np.log2(url.count(c)/L) 
                      for c in set(url) if url.count(c) > 0)
    else:
        entropy = 0
    
    # EXACT feature set from training (32 features)
    features = {
        # Length features
        "url_length": len(url),
        "domain_length": len(domain),
        "path_length": len(path),
        
        # Character composition
        "num_digits": sum(c.isdigit() for c in url),
        "num_letters": sum(c.isalpha() for c in url),
        "num_specials": sum(c in ['@','-','?','=','%','/','&','#','.'] for c in url),
        "digit_ratio": sum(c.isdigit() for c in url) / L,
        "letter_ratio": sum(c.isalpha() for c in url) / L,
        
        # Protocol & security
        "has_https": int("https" in url.lower()),
        "has_http": int("http://" in url.lower()),
        
        # Suspicious keywords
        "has_login": int(any(word in url.lower() for word in ["login", "signin", "account"])),
        "has_secure": int("secure" in url.lower()),
        "has_update": int("update" in url.lower()),
        "has_banking": int(any(word in url.lower() for word in ["bank", "paypal", "payment"])),
        "has_verify": int("verify" in url.lower() or "confirm" in url.lower()),
        
        # Structure features
        "num_dots": url.count('.'),
        "num_hyphens": url.count('-'),
        "num_underscores": url.count('_'),
        "num_slashes": url.count('/'),
        "num_questions": url.count('?'),
        "num_equals": url.count('='),
        "num_ats": url.count('@'),
        "num_ampersands": url.count('&'),
        
        # Domain features
        "num_subdomains": domain.count('.'),
        "has_ip": int(bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url))),
        
        # Entropy (randomness measure)
        "entropy": float(entropy),
        
        # Suspicious patterns
        "has_double_slash": int('//' in url[8:]) if len(url) > 8 else 0,
        "has_port": int(':' in domain) if domain else 0,
        "abnormal_tld": int(url.endswith(('.tk', '.ml', '.ga', '.cf', '.gq'))),
        
        # ⭐ MISSING FEATURES FROM TRAINING - These were in your notebook!
        "uppercase_count": sum(c.isupper() for c in url),
        "consecutive_digits": max([len(x) for x in re.findall(r'\d+', url)] or [0]),
        "consecutive_letters": max([len(x) for x in re.findall(r'[a-zA-Z]+', url)] or [0]),
        "special_char_ratio": sum(c in string.punctuation for c in url) / L,
    }
    
    return features


def _build_feature_vector_for_single_url(url: str, tfidf_obj):
    """Construct combined TF-IDF + numeric features."""
    normalized = clean_url(url)
    
    # Get TF-IDF features
    tfidf_vec = tfidf_obj.transform([normalized])
    tfidf_feature_count = tfidf_vec.shape[1]
    
    # Get numeric features
    features = extract_advanced_features(normalized)
    numeric_df = pd.DataFrame([features])
    numeric_feature_count = numeric_df.shape[1]
    
    # Convert to sparse matrix
    X_numeric = csr_matrix(numeric_df.values)
    
    # Combine features (TF-IDF first, then numeric)
    X = hstack([tfidf_vec, X_numeric], format="csr")
    
    # Verify feature count
    total_features = X.shape[1]
    
    print(f"  TF-IDF features: {tfidf_feature_count}")
    print(f"  Numeric features: {numeric_feature_count}")
    print(f"  Total features: {total_features}")
    
    if hasattr(_xgb, 'n_features_in_'):
        expected = _xgb.n_features_in_
        if total_features != expected:
            raise ValueError(
                f"❌ Feature count mismatch!\n"
                f"   Expected: {expected}\n"
                f"   Got: {total_features}\n"
                f"   Difference: {expected - total_features}\n"
            )
        else:
            print(f"  ✅ Feature count matches model: {expected}")
    
    return X, normalized


def get_risk_assessment(score: int, is_phishing: bool, features: dict) -> dict:
    """Generate detailed risk assessment based on score and features."""
    assessment = {"risk_factors": [], "severity": "low", "recommendation": ""}

    if score >= 70:
        assessment["severity"] = "critical"
        assessment["recommendation"] = "DO NOT PROCEED - This URL is very likely a phishing attempt"
    elif score >= 50:
        assessment["severity"] = "high"
        assessment["recommendation"] = "Avoid entering any personal information on this site"
    elif score >= 30:
        assessment["severity"] = "medium"
        assessment["recommendation"] = "Exercise caution - verify site authenticity before proceeding"
    else:
        assessment["severity"] = "low"
        assessment["recommendation"] = "Site appears safe, but always verify URLs before entering sensitive data"

    if features.get("has_ip"):
        assessment["risk_factors"].append("Uses IP address instead of domain name")
    if features.get("abnormal_tld"):
        assessment["risk_factors"].append("Uses suspicious top-level domain (.tk, .ml, .ga, etc.)")
    if features.get("has_login") or features.get("has_verify") or features.get("has_banking"):
        assessment["risk_factors"].append("Contains suspicious keywords (login, verify, banking)")
    if features.get("num_ats", 0) > 0:
        assessment["risk_factors"].append("Contains @ symbol (domain hiding technique)")
    if features.get("url_length", 0) > 75:
        assessment["risk_factors"].append(f"Unusually long URL ({features['url_length']} characters)")
    if features.get("num_subdomains", 0) > 3:
        assessment["risk_factors"].append(f"Excessive subdomains ({features['num_subdomains']})")
    if features.get("entropy", 0) > 4.5:
        assessment["risk_factors"].append("High entropy (random-looking URL)")
    if not features.get("has_https"):
        assessment["risk_factors"].append("Not using HTTPS protocol")
    if features.get("uppercase_count", 0) > 10:
        assessment["risk_factors"].append(f"Excessive uppercase letters ({features['uppercase_count']})")
    if features.get("consecutive_digits", 0) > 8:
        assessment["risk_factors"].append(f"Long sequence of digits ({features['consecutive_digits']})")

    return assessment


def predict_and_score(url: str) -> dict:
    """Run enhanced model inference and return prediction details."""
    _load_models()
    
    print(f"\n{'='*60}")
    print(f"Analyzing URL: {url}")
    print(f"{'='*60}")
    
    try:
        X, normalized = _build_feature_vector_for_single_url(url, _tfidf)
        
        pred_idx = _xgb.predict(X)[0]
        proba = _xgb.predict_proba(X)[0]

        try:
            pred_label = _le.inverse_transform([pred_idx])[0]
        except Exception:
            classes = list(_le.classes_) if hasattr(_le, "classes_") else []
            pred_label = classes[pred_idx] if pred_idx < len(classes) else str(pred_idx)

        prob_dict = {str(cls): float(p) for cls, p in zip(_le.classes_, proba)}
        phishing_prob = prob_dict.get("phishing", prob_dict.get(pred_label, 0.0))
        phishing_score = int(round(phishing_prob * 100))

        features = extract_advanced_features(normalized)
        risk_assessment = get_risk_assessment(phishing_score, pred_label == "phishing", features)

        print(f"✅ Prediction: {pred_label}")
        print(f"✅ Score: {phishing_score}/100")
        print(f"{'='*60}\n")

        return {
            "url": url,
            "normalized": normalized,
            "prediction": str(pred_label),
            "is_phishing": pred_label == "phishing",
            "score": phishing_score,
            "confidence": float(max(proba)),
            "probabilities": prob_dict,
            "features": features,
            "risk_assessment": risk_assessment
        }
    
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        raise


# --- CLI Testing Block ---
if __name__ == "__main__":
    print("\n" + "="*70)
    print(" "*20 + "ENHANCED URL PHISHING DETECTOR TEST")
    print("="*70 + "\n")

    test_urls = [
        "https://www.google.com/",
        "http://paypal-verify.tk/login",
        "http://192.168.1.1/malware.exe",
        "https://www.amazon.com",
        "http://secure-login-bank.ml/verify",
        "https://dropbox.com"
    ]

    for u in test_urls:
        try:
            r = predict_and_score(u)
            print("=" * 70)
            print(f"URL: {r['url']}")
            print(f"Prediction: {r['prediction']}  |  Is phishing: {r['is_phishing']}")
            print(f"Phishing Score: {r['score']}/100")
            print(f"Confidence: {r['confidence']:.1%}")
            print(f"Risk Level: {r['risk_assessment']['severity'].upper()}")
            if r['risk_assessment']['risk_factors']:
                print("\nRisk Factors:")
                for factor in r['risk_assessment']['risk_factors']:
                    print(f"  • {factor}")
            print(f"\nRecommendation: {r['risk_assessment']['recommendation']}")
        except Exception as e:
            print(f"❌ Error predicting for {u}: {e}\n")

    print("="*70)
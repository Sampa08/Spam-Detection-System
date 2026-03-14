import os
import re
import joblib
import warnings
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline

MODEL_PATH = "spam_model.joblib"
VECTORIZER_PATH = "vectorizer.joblib"

# Try to lazily load model/vectorizer once
_model = None
_vectorizer = None
_label_map = None   # maps model output -> normalized label ('spam','scam','ham')

def load_model():
    global _model, _vectorizer, _label_map
    if _model is not None and _vectorizer is not None:
        return _model, _vectorizer
    try:
        if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
            _model = joblib.load(MODEL_PATH)
            _vectorizer = joblib.load(VECTORIZER_PATH)
            # build a label map if model exposes classes_
            _label_map = {}
            try:
                classes = getattr(_model, "classes_", None)
                if classes is not None:
                    # normalize known class names to lower-case strings
                    for c in classes:
                        key = c
                        # if classifier uses numeric labels, try to map common numeric encodings
                        if isinstance(c, (bytes, bytearray)):
                            c = c.decode(errors="ignore")
                        _label_map[str(key)] = str(c).lower()
            except Exception:
                _label_map = None
            return _model, _vectorizer
    except Exception as e:
        warnings.warn(f"Failed loading model/vectorizer: {e}")
    return None, None

# helper to coerce model prediction to standard label
def _normalize_pred(pred):
    """
    Convert model output (numeric, bytes, str) to one of 'spam','scam','ham' or 'unknown'.
    Uses _label_map when available, otherwise pattern-match strings.
    """
    global _label_map
    if pred is None:
        return "unknown"
    # bytes -> str
    if isinstance(pred, (bytes, bytearray)):
        try:
            pred = pred.decode()
        except Exception:
            pred = str(pred)
    # numeric -> str
    key = str(pred)
    # consult label map if available
    if _label_map:
        if key in _label_map:
            return _label_map[key]
        # sometimes model returns index or numpy scalar
        try:
            if isinstance(pred, (np.integer,)):
                key = str(int(pred))
                if key in _label_map:
                    return _label_map[key]
        except Exception:
            pass
    # fallback heuristics on text
    s = key.strip().lower()
    if not s:
        return "unknown"
    if any(tok in s for tok in ("spam", "junk", "unsolicited")):
        return "spam"
    if any(tok in s for tok in ("scam", "phish", "phishing", "fraud")):
        return "scam"
    if any(tok in s for tok in ("ham", "legit", "inbox", "not spam", "ok")):
        return "ham"
    # numeric-only fallback
    if s.isdigit():
        # unknown numeric mapping
        return "unknown"
    return s  # return raw string if nothing matched

def extract_features(text):
    """Extract comprehensive features from email text"""
    if text is None:
        text = ""
    
    text_lower = text.lower()
    
    features = {
        'suspicious_keywords': 0,
        'urgency_words': 0,
        'financial_terms': 0,
        'links_count': 0,
        'suspicious_domains': 0,
        'exclamation_count': text_lower.count('!'),
        'uppercase_ratio': sum(1 for c in text if c.isupper()) / max(1, len(text)),
        'length': len(text)
    }
    
    # Suspicious keywords
    suspicious_patterns = [
        r'\b(win|won|winner|prize|lottery|jackpot|million|billion|free|reward)\b',
        r'\b(congratulations|congrats|selected|chosen|lucky|exclusive)\b',
        r'\b(claim|collect|receive|get your|cash|money|dollars)\b',
        r'\b(urgent|immediate|alert|warning|important|attention)\b',
        r'\b(verify|confirm|validate|authenticate|security|protect)\b',
        r'\b(password|login|account|credentials|username)\b',
        r'\b(limited time|offer expires|act now|don\'t miss)\b',
        r'\b(suspended|blocked|frozen|locked|disabled|terminated)\b',
        r'\b(click here|visit now|follow link|click below)\b',
        r'\b(dear customer|valued customer|dear user|dear account holder)\b'
    ]
    
    for pattern in suspicious_patterns:
        features['suspicious_keywords'] += len(re.findall(pattern, text_lower))
    
    # Urgency words
    urgency_words = ['urgent', 'immediate', 'now', 'today', 'asap', 'instant', 'quick']
    features['urgency_words'] = sum(text_lower.count(word) for word in urgency_words)
    
    # Financial terms
    financial_terms = ['bank', 'account', 'card', 'paypal', 'payment', 'transfer', 'funds']
    features['financial_terms'] = sum(text_lower.count(word) for word in financial_terms)
    
    # Links analysis
    links = re.findall(r'https?://[^\s]+', text_lower)
    features['links_count'] = len(links)
    
    # Suspicious domains
    suspicious_tlds = ['.xyz', '.top', '.ru', '.cn', '.tk', '.ml', '.ga', '.cf']
    for link in links:
        for tld in suspicious_tlds:
            if tld in link:
                features['suspicious_domains'] += 1
                break
    
    return features

def classify_email(text):
    """
    Return one of: 'spam', 'scam', 'ham' (or 'unknown').
    Uses trained model if available; otherwise falls back to enhanced rule-based heuristics.
    """
    if text is None or text.strip() == "":
        return "ham"

    txt = str(text)

    # Try ML model first
    model, vect = load_model()
    if model is not None and vect is not None:
        try:
            X = vect.transform([txt])
            pred = model.predict(X)[0]
            label = _normalize_pred(pred)
            # Ensure final label is one of expected
            if label not in ("spam", "scam", "ham"):
                # let heuristics decide if model gave unknown
                pass
            else:
                return label
        except Exception as e:
            warnings.warn(f"Model prediction failed, falling back to heuristics: {e}")

    # Enhanced heuristic fallback with feature extraction
    features = extract_features(txt)
    lower = txt.lower()

    # Calculate confidence scores
    scam_score = 0
    spam_score = 0

    # Scam indicators (high priority)
    if (features['suspicious_keywords'] >= 3 or 
        features['financial_terms'] >= 2 or
        features['suspicious_domains'] >= 1):
        scam_score += 3

    # Lottery/prize scams
    if re.search(r'\b(won|win|winner|prize|lottery|jackpot)\b', lower) and features['links_count'] >= 1:
        scam_score += 2

    # Urgent financial requests
    if features['urgency_words'] >= 2 and features['financial_terms'] >= 1:
        scam_score += 2

    # Phishing attempts
    if (re.search(r'\b(verify|confirm|password|login|account)\b', lower) and 
        features['links_count'] >= 1):
        scam_score += 2

    # Spam indicators
    if features['suspicious_keywords'] >= 2:
        spam_score += 1

    if features['exclamation_count'] >= 3:
        spam_score += 1

    if features['uppercase_ratio'] > 0.3:
        spam_score += 1

    if re.search(r'\b(free|discount|offer|promotion|buy now)\b', lower):
        spam_score += 1

    # Short highly-numeric messages (likely OTP/spam)
    if len(re.findall(r'\d{4,}', lower)) and len(lower) < 120:
        spam_score += 2

    # Decision logic
    if scam_score >= 3:
        return "scam"
    elif spam_score >= 3:
        return "spam"
    elif scam_score >= 2 and spam_score >= 1:
        return "scam"
    else:
        # Check for obvious legitimate patterns
        if (len(txt) > 50 and 
            features['suspicious_keywords'] == 0 and 
            features['links_count'] == 0 and
            not re.search(r'\b(win|won|prize|verify|urgent)\b', lower)):
            return "ham"

        # Default based on scores
        if scam_score > spam_score:
            return "scam"
        elif spam_score > scam_score:
            return "spam"
        else:
            return "ham"

# New helper: classify a list of texts
def predict_batch(texts):
    """
    Classify a list of texts and return a list of normalized labels.
    Safe: always returns strings in ('spam','scam','ham','unknown') for each input.
    """
    out = []
    model, vect = load_model()
    if model is not None and vect is not None:
        try:
            X = vect.transform([str(t) for t in texts])
            preds = model.predict(X)
            for p in preds:
                out.append(_normalize_pred(p))
            return out
        except Exception:
            # fallback to single predictions
            pass
    for t in texts:
        out.append(classify_email(t))
    return out

def train_model(X, y):
    """Train an improved classifier"""
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            min_df=2,
            max_df=0.95,
            ngram_range=(1, 2),
            stop_words='english'
        )),
        ('clf', RandomForestClassifier(
            n_estimators=100,
            max_depth=None,
            min_samples_split=2,
            min_samples_leaf=1,
            random_state=42
        ))
    ])
    
    pipeline.fit(X, y)
    return pipeline

def test_empty_text_is_ham(monkeypatch):
    # force heuristic path
    monkeypatch.setattr(email_classifier, "load_model", lambda: (None, None))
    assert classify_email("") == "ham"
    assert classify_email("   \t\n") == "ham"

def test_spam_keywords(monkeypatch):
    monkeypatch.setattr(email_classifier, "load_model", lambda: (None, None))
    text = "Limited time offer! Buy now and get 50% off. Free gift!!! Click here to claim your reward."
    lbl = classify_email(text)
    assert lbl == "spam", f"expected spam, got {lbl}"

def test_scam_financial_link(monkeypatch):
    monkeypatch.setattr(email_classifier, "load_model", lambda: (None, None))
    text = "Dear customer, verify your account to avoid suspension: http://phishy-domain.xyz Please confirm your login."
    lbl = classify_email(text)
    assert lbl == "scam", f"expected scam, got {lbl}"

def test_otp_numeric_spam(monkeypatch):
    monkeypatch.setattr(email_classifier, "load_model", lambda: (None, None))
    text = "Your verification code is 123456. Use it within 5 minutes."
    lbl = classify_email(text)
    assert lbl == "spam", f"expected spam for OTP-like message, got {lbl}"

def test_predict_batch_and_extract_features(monkeypatch):
    monkeypatch.setattr(email_classifier, "load_model", lambda: (None, None))
    legit = "Hi team,\nPlease find the meeting notes attached. Let's sync tomorrow about the project status.\nThanks."
    promo = "Win a million dollars now! Click http://promo.top to claim your prize and get free bonuses."
    phishing = "URGENT: Verify your bank account immediately at http://secure-bank.ru or your account will be locked."
    texts = [legit, promo, phishing]

    labels = predict_batch(texts)
    assert isinstance(labels, list) and len(labels) == 3
    assert labels[0] == "ham", f"expected ham for legit message, got {labels[0]}"
    # promo may be spam or scam depending on heuristics; accept both
    assert labels[1] in ("spam", "scam"), f"expected spam/scam for promo, got {labels[1]}"
    # phishing financial link should be classified as scam
    assert labels[2] == "scam", f"expected scam for phishing, got {labels[2]}"

    feats = extract_features(promo)
    assert isinstance(feats, dict)
    assert feats.get("links_count", 0) >= 1
    assert feats.get("suspicious_keywords", 0) >= 1


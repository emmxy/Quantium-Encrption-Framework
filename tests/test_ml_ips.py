"""
Unit tests for Machine Learning Random Forest WAF/IPS Threat Classifier Pipeline.
"""

import pytest
from threat_classifier import (
    ThreatClassifierPipeline,
    extract_features_from_raw,
    generate_benchmark_dataset,
    FEATURE_NAMES,
    CLASSES
)


class TestMLThreatClassifier:

    @pytest.fixture(scope="module")
    def pipeline(self):
        pipe = ThreatClassifierPipeline(random_state=42)
        if not pipe.load_artifacts():
            pipe.train_and_evaluate(n_samples=2000)
        return pipe

    def test_feature_extraction_dimension_and_types(self):
        features = extract_features_from_raw(
            method='POST',
            path='/encrypt_text',
            query='page=1',
            body='{"text": "Sample text for testing"}',
            request_rate=2.5,
            crypto_fail=False
        )
        assert len(features) == len(FEATURE_NAMES)
        assert len(features) == 14
        assert all(isinstance(v, (int, float)) for v in features)

    def test_dataset_generation_balance(self):
        X, y = generate_benchmark_dataset(n_samples=600, random_seed=42)
        assert len(X) == 600
        assert len(y) == 600
        assert list(X.columns) == FEATURE_NAMES
        # Check all classes present
        unique_classes = set(y.unique())
        assert len(unique_classes) == len(CLASSES)

    def test_pipeline_evaluation_metrics(self, pipeline):
        meta = pipeline.metadata
        metrics = meta['overall_metrics']
        assert metrics['accuracy'] >= 0.95
        assert metrics['macro_f1_score'] >= 0.95
        assert metrics['benign_false_positive_rate'] <= 0.05
        assert metrics['attack_false_negative_rate'] <= 0.05
        # Ensure per-class breakdown is present
        for c in CLASSES:
            assert c in meta['per_class_metrics']
            assert meta['per_class_metrics'][c]['f1_score'] >= 0.90

    def test_inference_latency(self, pipeline):
        meta = pipeline.metadata
        latency_us = meta.get('inference_latency_microseconds_per_request', 0)
        assert latency_us > 0
        assert latency_us < 2000.0, "Inference latency must be sub-millisecond for real-time WAF"

    def test_sqli_detection(self, pipeline):
        res = pipeline.predict_request('GET', '/search', "query=1' UNION SELECT null, username, password FROM users--", '')
        assert res['is_attack'] is True
        assert res['predicted_class'] == 'sqli'
        assert res['action'] == 'block'

    def test_xss_detection(self, pipeline):
        res = pipeline.predict_request('POST', '/chat', '', '{"message": "<script>alert(document.cookie)</script>"}')
        assert res['is_attack'] is True
        assert res['predicted_class'] == 'xss'
        assert res['action'] == 'block'

    def test_path_traversal_detection(self, pipeline):
        res = pipeline.predict_request('GET', '/download', 'file=../../../../etc/passwd', '')
        assert res['is_attack'] is True
        assert res['predicted_class'] == 'path_traversal'
        assert res['action'] == 'block'

    def test_crypto_anomaly_detection(self, pipeline):
        res = pipeline.predict_request('POST', '/decrypt_text', '', '{"tampered": true}', request_rate=5.0, crypto_fail=True)
        assert res['is_attack'] is True
        assert res['predicted_class'] == 'crypto_anomaly'
        assert res['action'] == 'block'

    def test_rate_abuse_detection(self, pipeline):
        res = pipeline.predict_request('GET', '/generate_keys', '', '', request_rate=500.0, crypto_fail=False)
        assert res['is_attack'] is True
        assert res['predicted_class'] == 'rate_abuse'
        assert res['action'] == 'block'

    def test_benign_traffic_allowed(self, pipeline):
        # 1. Normal index
        res1 = pipeline.predict_request('GET', '/', '', '')
        assert res1['is_attack'] is False
        assert res1['predicted_class'] == 'benign'
        assert res1['action'] == 'allow'

        # 2. Hard negative: Normal English containing words like "select" and "from"
        res2 = pipeline.predict_request('POST', '/encrypt_text', '', '{"text": "Please select from our options below.", "algorithm": "kyber768"}')
        assert res2['is_attack'] is False
        assert res2['predicted_class'] == 'benign'
        assert res2['action'] == 'allow'

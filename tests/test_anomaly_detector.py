"""
Automated unit tests for Machine Learning Anomaly Detection.
"""

import numpy as np
import pytest

from src.anomaly_detector import NetworkAnomalyDetector
from src.feature_extraction import TrafficFeatureExtractor
from src.synthetic_data import SyntheticTrafficGenerator


@pytest.fixture
def traffic_features():
    gen = SyntheticTrafficGenerator(seed=42)
    raw_df = gen.generate_complete_dataset()
    extractor = TrafficFeatureExtractor(window_size_sec=10.0)
    features_df = extractor.extract_window_features(raw_df)
    return features_df


def test_isolation_forest_fit_predict(traffic_features):
    """Test Isolation Forest anomaly detection pipeline end-to-end."""
    detector = NetworkAnomalyDetector(contamination=0.08, n_estimators=50, random_state=42)
    detector.fit(traffic_features)

    assert detector.is_fitted is True

    labels, scores, explanations = detector.predict(traffic_features)

    assert len(labels) == len(traffic_features)
    assert len(scores) == len(traffic_features)
    assert len(explanations) == len(traffic_features)

    # Scores should be in [0.0, 1.0]
    assert np.all(scores >= 0.0)
    assert np.all(scores <= 1.0)

    # Some anomalies should be flagged
    assert np.sum(labels == 1) > 0


def test_model_evaluation_metrics():
    """Verify evaluation calculation with ground-truth test labels."""
    detector = NetworkAnomalyDetector()
    y_true = np.array([0, 0, 0, 1, 1, 1, 0, 0])
    y_pred = np.array([0, 0, 1, 1, 1, 0, 0, 0])

    metrics = detector.evaluate(y_true, y_pred)

    assert "precision" in metrics
    assert "recall" in metrics
    assert "f1_score" in metrics
    assert "accuracy" in metrics
    assert 0.0 <= metrics["precision"] <= 1.0
    assert 0.0 <= metrics["recall"] <= 1.0


def test_tiny_dataset_handling():
    """Verify robust fallback when dataset is too small for ML."""
    detector = NetworkAnomalyDetector()
    import pandas as pd
    tiny_df = pd.DataFrame([{"packet_size": 60, "src_ip": "1.1.1.1"}])

    detector.fit(tiny_df)
    assert detector.is_fitted is False

    labels, scores, explanations = detector.predict(tiny_df)
    assert len(labels) == 1
    assert labels[0] == 0

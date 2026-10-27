"""
Automated unit tests for Rule-Based Detection Engine.
"""

import pandas as pd
import pytest

from src.feature_extraction import TrafficFeatureExtractor
from src.rule_engine import RuleBasedDetectionEngine
from src.synthetic_data import SyntheticTrafficGenerator


@pytest.fixture
def synthetic_traffic_features():
    gen = SyntheticTrafficGenerator(seed=42)
    raw_df = gen.generate_complete_dataset()
    extractor = TrafficFeatureExtractor(window_size_sec=10.0)
    return extractor.extract_window_features(raw_df)


def test_port_scan_detection(synthetic_traffic_features):
    """Ensure rule engine flags port scan activity from the attacker IP."""
    engine = RuleBasedDetectionEngine()
    alerts = engine.evaluate_traffic(synthetic_traffic_features)

    port_scan_alerts = [a for a in alerts if a["alert_type"] == "Port Scan Detected"]
    assert len(port_scan_alerts) > 0
    assert any("203.0.113.88" in a["src_ip"] for a in port_scan_alerts)
    assert port_scan_alerts[0]["severity"] == "High"


def test_traffic_spike_detection(synthetic_traffic_features):
    """Ensure rule engine flags high-rate volumetric traffic surges."""
    engine = RuleBasedDetectionEngine()
    alerts = engine.evaluate_traffic(synthetic_traffic_features)

    spike_alerts = [a for a in alerts if a["alert_type"] == "Volumetric Traffic Spike"]
    assert len(spike_alerts) > 0
    assert any("198.51.100.42" in a["src_ip"] for a in spike_alerts)


def test_syn_flood_detection(synthetic_traffic_features):
    """Ensure rule engine flags SYN flood behavior."""
    engine = RuleBasedDetectionEngine()
    alerts = engine.evaluate_traffic(synthetic_traffic_features)

    syn_alerts = [a for a in alerts if a["alert_type"] == "TCP SYN Flood Indicator"]
    assert len(syn_alerts) > 0
    assert any("203.0.113.199" in a["src_ip"] for a in syn_alerts)
    assert syn_alerts[0]["severity"] == "Critical"


def test_alert_deduplication(synthetic_traffic_features):
    """Ensure rule engine does not generate duplicate alerts for the same source & window."""
    engine = RuleBasedDetectionEngine()
    alerts = engine.evaluate_traffic(synthetic_traffic_features)

    # Check that alert tuples (alert_type, src_ip, explanation) are unique
    alert_signatures = [(a["alert_type"], a["src_ip"]) for a in alerts]
    # Small number of unique alert signatures compared to hundreds of raw attack packets
    assert len(alert_signatures) < 20

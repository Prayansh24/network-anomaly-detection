"""
Automated unit tests for Traffic Feature Extraction.
"""

import pandas as pd
import pytest

from src.feature_extraction import TrafficFeatureExtractor
from src.synthetic_data import SyntheticTrafficGenerator


@pytest.fixture
def sample_traffic_df():
    gen = SyntheticTrafficGenerator(seed=42)
    return gen.generate_complete_dataset()


def test_packet_feature_extraction(sample_traffic_df):
    """Verify packet-level indicators (privileged port, SYN detection)."""
    extractor = TrafficFeatureExtractor(window_size_sec=10.0)
    res = extractor.extract_packet_features(sample_traffic_df)

    assert "is_privileged_port" in res.columns
    assert "is_syn" in res.columns
    # Check that port 80/443/53 are identified as privileged (<1024)
    priv_rows = res[res["dst_port"].isin([80, 443, 53])]
    assert (priv_rows["is_privileged_port"] == 1).all()


def test_window_feature_extraction(sample_traffic_df):
    """Verify time-window aggregation statistics."""
    extractor = TrafficFeatureExtractor(window_size_sec=10.0)
    res = extractor.extract_window_features(sample_traffic_df)

    expected_cols = [
        "packet_count_in_window",
        "byte_count_in_window",
        "packet_rate",
        "byte_rate",
        "syn_flag_count",
        "syn_ratio",
        "unique_dst_ports",
        "unique_dst_ips",
        "same_dest_attempts",
    ]
    for col in expected_cols:
        assert col in res.columns
        assert not res[col].isnull().any()

    # Port scanning traffic should exhibit high unique_dst_ports
    scan_rows = res[res["attack_type"] == "Port Scan"]
    assert scan_rows["unique_dst_ports"].max() > 10


def test_empty_dataframe_feature_extraction():
    """Verify graceful handling of empty inputs."""
    extractor = TrafficFeatureExtractor()
    empty_df = pd.DataFrame()
    res = extractor.extract_window_features(empty_df)
    assert res.empty

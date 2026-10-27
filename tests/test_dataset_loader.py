"""
Automated unit tests for Dataset Loader and Validator.
"""

from io import StringIO
import pandas as pd
import pytest

from src.dataset_loader import DatasetLoader
from src.synthetic_data import SyntheticTrafficGenerator


def test_synthetic_data_loading():
    """Verify that synthetic dataset loads and passes all validation requirements."""
    gen = SyntheticTrafficGenerator(seed=42)
    df = gen.generate_complete_dataset()
    csv_str = df.to_csv(index=False)

    loaded_df, result = DatasetLoader.validate_and_load(StringIO(csv_str))

    assert result.is_valid is True
    assert len(result.errors) == 0
    assert loaded_df is not None
    assert len(loaded_df) == len(df)
    assert "src_ip" in loaded_df.columns
    assert "dst_ip" in loaded_df.columns
    assert "packet_size" in loaded_df.columns


def test_column_alias_mapping():
    """Ensure column aliases (e.g. source_ip, length, proto) are mapped correctly."""
    custom_csv = StringIO(
        "time,source_ip,destination_ip,sport,dport,proto,length\n"
        "1700000001,192.168.1.10,8.8.8.8,54321,53,UDP,75\n"
        "1700000002,192.168.1.10,8.8.8.8,54322,53,UDP,80\n"
    )

    loaded_df, result = DatasetLoader.validate_and_load(custom_csv)
    assert result.is_valid is True
    assert loaded_df is not None
    assert "src_ip" in loaded_df.columns
    assert "dst_ip" in loaded_df.columns
    assert "packet_size" in loaded_df.columns
    assert loaded_df["protocol"].iloc[0] == "UDP"


def test_missing_required_columns():
    """Reject CSVs missing mandatory network fields."""
    incomplete_csv = StringIO("src_ip,packet_size\n192.168.1.10,64\n")
    loaded_df, result = DatasetLoader.validate_and_load(incomplete_csv)

    assert result.is_valid is False
    assert len(result.errors) > 0
    assert loaded_df is None


def test_empty_csv():
    """Reject completely empty datasets."""
    empty_csv = StringIO("")
    loaded_df, result = DatasetLoader.validate_and_load(empty_csv)

    assert result.is_valid is False
    assert "empty" in result.errors[0].lower()

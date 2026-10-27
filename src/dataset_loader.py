"""
Dataset Loader & Validator Module for SentinelNet.
Handles CSV ingestion, column schema mapping, dataset validation, and missing value checks.
"""

from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
import pandas as pd

from src.utils import get_project_root, setup_logger

logger = setup_logger("dataset_loader")

# Canonical internal schema required for network traffic processing
CANONICAL_COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "packet_size",
]

# Supported aliases for column header mapping
COLUMN_ALIASES: Dict[str, List[str]] = {
    "timestamp": ["timestamp", "time", "datetime", "date_time", "ts", "epoch"],
    "src_ip": ["src_ip", "source_ip", "saddr", "ip_src", "source", "src", "srcip"],
    "dst_ip": ["dst_ip", "destination_ip", "daddr", "ip_dst", "destination", "dst", "dstip"],
    "src_port": ["src_port", "source_port", "sport", "s_port", "srcport"],
    "dst_port": ["dst_port", "destination_port", "dport", "d_port", "dstport"],
    "protocol": ["protocol", "proto", "ip_proto", "trans_protocol"],
    "packet_size": ["packet_size", "length", "len", "bytes", "size", "pkt_len", "packet_length"],
    "tcp_flags": ["tcp_flags", "flags", "flag", "tcp_flag"],
}


class DatasetValidationResult:
    """Encapsulates the outcome of validating a dataset."""

    def __init__(
        self,
        is_valid: bool,
        errors: List[str],
        warnings: List[str],
        row_count: int = 0,
        column_mapping: Optional[Dict[str, str]] = None,
        detected_attacks: Optional[List[str]] = None,
    ):
        self.is_valid = is_valid
        self.errors = errors
        self.warnings = warnings
        self.row_count = row_count
        self.column_mapping = column_mapping or {}
        self.detected_attacks = detected_attacks or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "errors": self.errors,
            "warnings": self.warnings,
            "row_count": self.row_count,
            "column_mapping": self.column_mapping,
            "detected_attacks": self.detected_attacks,
        }


class DatasetLoader:
    """Ingests and validates network traffic datasets from CSV or DataFrames."""

    @staticmethod
    def map_columns(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, str], List[str]]:
        """
        Map varying column header names to canonical schema.
        
        Returns:
            Tuple of (renamed_df, column_mapping, missing_required_columns).
        """
        mapping: Dict[str, str] = {}
        df_cols_lower = {col.lower().strip().replace("-", "_"): col for col in df.columns}

        for canonical, aliases in COLUMN_ALIASES.items():
            for alias in aliases:
                if alias.lower() in df_cols_lower:
                    orig_col = df_cols_lower[alias.lower()]
                    mapping[orig_col] = canonical
                    break

        renamed_df = df.rename(columns=mapping)

        # Identify missing canonical columns
        missing = [col for col in CANONICAL_COLUMNS if col not in renamed_df.columns]
        return renamed_df, mapping, missing

    @classmethod
    def validate_and_load(
        cls, file_or_buffer: Union[str, Path, StringIO, Any]
    ) -> Tuple[Optional[pd.DataFrame], DatasetValidationResult]:
        """
        Load a CSV file, validate its structure, and return normalized DataFrame and result.
        
        Args:
            file_or_buffer: Path to CSV file, or file-like buffer (e.g. from st.file_uploader).
            
        Returns:
            Tuple of (DataFrame or None, DatasetValidationResult).
        """
        errors: List[str] = []
        warnings: List[str] = []

        try:
            if isinstance(file_or_buffer, (str, Path)):
                p = Path(file_or_buffer)
                if not p.exists():
                    return None, DatasetValidationResult(False, [f"File does not exist: {p}"], [])
                df = pd.read_csv(p)
            else:
                df = pd.read_csv(file_or_buffer)
        except pd.errors.EmptyDataError:
            return None, DatasetValidationResult(False, ["The dataset is empty or contains no readable columns."], [])
        except Exception as e:
            return None, DatasetValidationResult(False, [f"Failed to read CSV: {str(e)}"], [])

        if df.empty:
            return None, DatasetValidationResult(False, ["The dataset is completely empty."], [])

        row_count = len(df)
        if row_count < 5:
            warnings.append(f"Dataset has only {row_count} records. Machine learning results may be unreliable.")

        # Map columns
        df_norm, col_map, missing_cols = cls.map_columns(df)

        if missing_cols:
            errors.append(
                f"Missing required traffic columns: {', '.join(missing_cols)}. "
                f"Dataset must include source/dest IPs, ports, protocol, and size/length."
            )
            return None, DatasetValidationResult(False, errors, warnings, row_count, col_map)

        # Check for missing values in critical columns
        missing_counts = df_norm[CANONICAL_COLUMNS].isnull().sum()
        for col, count in missing_counts.items():
            if count > 0:
                pct = (count / row_count) * 100
                if pct > 30:
                    errors.append(f"Column '{col}' has {count} ({pct:.1f}%) missing values, exceeding tolerance.")
                else:
                    warnings.append(f"Column '{col}' has {count} missing values; will be imputed.")

        if errors:
            return None, DatasetValidationResult(False, errors, warnings, row_count, col_map)

        # Data type cleaning & sanitization
        try:
            # Timestamp parsing
            if not pd.api.types.is_numeric_dtype(df_norm["timestamp"]):
                df_norm["timestamp"] = pd.to_datetime(df_norm["timestamp"], errors="coerce")
                # If conversion produced NaTs, fallback to sequential indices
                if df_norm["timestamp"].isnull().all():
                    df_norm["timestamp"] = np.arange(len(df_norm), dtype=float)
                else:
                    # Convert datetime to unix float seconds
                    df_norm["timestamp"] = df_norm["timestamp"].astype("int64") / 1e9

            # Ports & packet sizes
            df_norm["src_port"] = pd.to_numeric(df_norm["src_port"], errors="coerce").fillna(0).astype(int)
            df_norm["dst_port"] = pd.to_numeric(df_norm["dst_port"], errors="coerce").fillna(0).astype(int)
            df_norm["packet_size"] = pd.to_numeric(df_norm["packet_size"], errors="coerce").fillna(64).astype(float)

            # Protocol string standardization
            df_norm["protocol"] = df_norm["protocol"].astype(str).str.upper()

            # Ensure tcp_flags column exists
            if "tcp_flags" not in df_norm.columns:
                df_norm["tcp_flags"] = "N/A"
                warnings.append("No TCP flags column detected; SYN flood rules will operate in fallback mode.")
            else:
                df_norm["tcp_flags"] = df_norm["tcp_flags"].fillna("N/A").astype(str)

        except Exception as e:
            errors.append(f"Data type conversion error during validation: {str(e)}")
            return None, DatasetValidationResult(False, errors, warnings, row_count, col_map)

        # Check if ground-truth attack labels exist
        detected_attacks = []
        if "attack_type" in df_norm.columns:
            detected_attacks = df_norm["attack_type"].unique().tolist()
        elif "label" in df_norm.columns:
            detected_attacks = df_norm["label"].unique().tolist()

        return df_norm, DatasetValidationResult(
            is_valid=True,
            errors=errors,
            warnings=warnings,
            row_count=row_count,
            column_mapping=col_map,
            detected_attacks=detected_attacks,
        )

    @classmethod
    def get_sample_dataset_path(cls) -> Path:
        """Ensure sample synthetic dataset exists and return its path."""
        sample_path = get_project_root() / "data" / "sample_traffic.csv"
        if not sample_path.exists():
            from src.synthetic_data import SyntheticTrafficGenerator
            gen = SyntheticTrafficGenerator(seed=42)
            gen.save_sample_csv(sample_path)
        return sample_path

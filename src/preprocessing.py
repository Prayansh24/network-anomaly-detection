"""
Data Preprocessing Pipeline for SentinelNet.
Handles feature normalization, categorical encoding, handling missing data,
and preventing label leakage prior to machine learning anomaly detection.
"""

from typing import List, Optional, Tuple, Union
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

from src.utils import setup_logger

logger = setup_logger("preprocessing")

# Columns that MUST be excluded from ML training to avoid data leakage
EXCLUDED_COLUMNS = [
    "timestamp",
    "datetime",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "tcp_flags",
    "is_anomaly",
    "attack_type",
    "label",
    "ground_truth",
    "anomaly_score",
    "predicted_label",
    "anomaly_label",
    "rule_alert",
]


class TrafficPreprocessor:
    """
    Normalizes numerical features and encodes categorical network protocols.
    Ensures safe preprocessing without target leakage.
    """

    def __init__(self):
        self.scaler = StandardScaler()
        self.fitted = False
        self.feature_names_: List[str] = []
        self.protocol_categories_: List[str] = ["TCP", "UDP", "ICMP", "OTHER"]

    def _prepare_raw_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Filter out identifier and label columns, encode protocol."""
        df_clean = df.copy()

        # Categorical Protocol One-Hot Encoding
        if "protocol" in df_clean.columns:
            proto_upper = df_clean["protocol"].astype(str).str.upper()
            for cat in self.protocol_categories_:
                df_clean[f"proto_{cat.lower()}"] = (proto_upper == cat).astype(float)
        else:
            for cat in self.protocol_categories_:
                df_clean[f"proto_{cat.lower()}"] = 0.0

        # Drop non-feature and target columns
        cols_to_drop = [c for c in EXCLUDED_COLUMNS if c in df_clean.columns]
        if "protocol" in df_clean.columns:
            cols_to_drop.append("protocol")

        feature_df = df_clean.drop(columns=cols_to_drop, errors="ignore")

        # Select only numerical columns
        numeric_df = feature_df.select_dtypes(include=[np.number]).copy()

        # Impute any lingering NaNs with 0
        numeric_df = numeric_df.fillna(0.0)

        # Handle zero-variance columns smoothly
        return numeric_df

    def fit(self, df: pd.DataFrame) -> "TrafficPreprocessor":
        """Fit scaler on numerical traffic features."""
        features_df = self._prepare_raw_features(df)
        self.feature_names_ = list(features_df.columns)

        if not features_df.empty:
            self.scaler.fit(features_df.values)
            self.fitted = True
            logger.info(f"Preprocessor fitted on {len(self.feature_names_)} features: {self.feature_names_}")
        else:
            logger.warning("Empty feature dataframe provided to preprocessor fit().")
        return self

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """Transform network features using fitted scaler."""
        if not self.fitted:
            raise RuntimeError("Preprocessor has not been fitted yet. Call fit() or fit_transform().")

        features_df = self._prepare_raw_features(df)

        # Align columns to match training features exactly
        for col in self.feature_names_:
            if col not in features_df.columns:
                features_df[col] = 0.0

        features_df = features_df[self.feature_names_]
        return self.scaler.transform(features_df.values)

    def fit_transform(self, df: pd.DataFrame) -> np.ndarray:
        """Fit and transform feature matrix."""
        self.fit(df)
        return self.transform(df)

    def get_feature_names(self) -> List[str]:
        """Return names of features used for training."""
        return self.feature_names_

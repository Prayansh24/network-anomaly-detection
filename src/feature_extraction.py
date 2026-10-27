"""
Traffic Feature Extraction Module for SentinelNet.
Transforms raw packet records into statistical, time-window, and flow-based feature vectors
for machine learning and rule-based anomaly detection.
"""

from typing import Dict, List, Optional, Tuple
import numpy as np
import pandas as pd

from src.utils import setup_logger

logger = setup_logger("feature_extraction")


class TrafficFeatureExtractor:
    """
    Extracts packet-level and time-window aggregated features from network traffic records.
    Distinguishes individual packet characteristics from collective flow behaviors.
    """

    def __init__(self, window_size_sec: float = 10.0):
        self.window_size_sec = window_size_sec

    def extract_packet_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract packet-level attributes:
        - Privileged vs ephemeral port flags
        - TCP SYN flag indicators
        - Protocol encoding
        """
        features_df = df.copy()

        # Privileged destination port (< 1024, e.g. SSH, HTTP, DNS, HTTPS)
        features_df["is_privileged_port"] = (features_df["dst_port"] < 1024).astype(int)

        # SYN flag detection
        if "tcp_flags" in features_df.columns:
            features_df["is_syn"] = (
                features_df["tcp_flags"].astype(str).str.upper().str.contains("SYN")
            ).astype(int)
        else:
            features_df["is_syn"] = 0

        return features_df

    def extract_window_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Compute rolling or windowed traffic statistics grouped by source IP (src_ip).
        Aggregates:
        - packet_count_in_window: Volume of packets sent by source
        - byte_count_in_window: Total payload/header bytes transferred
        - packet_rate: Packets per second
        - byte_rate: Bytes per second
        - syn_flag_count: Number of SYN packets observed
        - syn_ratio: Proportion of packets that are SYN requests
        - unique_dst_ports: Number of unique destination ports targeted
        - unique_dst_ips: Number of unique remote destinations targeted
        """
        if df.empty:
            return pd.DataFrame()

        # First extract packet-level flags
        df_work = self.extract_packet_features(df)

        # Ensure timestamp is numeric
        if not pd.api.types.is_numeric_dtype(df_work["timestamp"]):
            df_work["timestamp"] = pd.to_numeric(df_work["timestamp"], errors="coerce").fillna(0.0)

        # Create time bins
        min_ts = df_work["timestamp"].min()
        df_work["time_window"] = ((df_work["timestamp"] - min_ts) // self.window_size_sec).astype(int)

        # Group by (src_ip, time_window) to compute source-centric behavior in time window
        grouped = df_work.groupby(["src_ip", "time_window"])

        agg_metrics = grouped.agg(
            packet_count_in_window=("packet_size", "count"),
            byte_count_in_window=("packet_size", "sum"),
            syn_flag_count=("is_syn", "sum"),
            unique_dst_ports=("dst_port", "nunique"),
            unique_dst_ips=("dst_ip", "nunique"),
            min_timestamp=("timestamp", "min"),
            max_timestamp=("timestamp", "max"),
        ).reset_index()

        # Calculate durations and rates
        durations = (agg_metrics["max_timestamp"] - agg_metrics["min_timestamp"]).clip(lower=0.1)
        agg_metrics["packet_rate"] = agg_metrics["packet_count_in_window"] / durations
        agg_metrics["byte_rate"] = agg_metrics["byte_count_in_window"] / durations
        agg_metrics["syn_ratio"] = (
            agg_metrics["syn_flag_count"] / agg_metrics["packet_count_in_window"].clip(lower=1)
        ).round(4)

        # Merge back window statistics to each individual packet record
        merged_df = pd.merge(
            df_work,
            agg_metrics[
                [
                    "src_ip",
                    "time_window",
                    "packet_count_in_window",
                    "byte_count_in_window",
                    "packet_rate",
                    "byte_rate",
                    "syn_flag_count",
                    "syn_ratio",
                    "unique_dst_ports",
                    "unique_dst_ips",
                ]
            ],
            on=["src_ip", "time_window"],
            how="left",
        )

        # Fill any remaining NaNs
        fill_zeros = [
            "packet_count_in_window",
            "byte_count_in_window",
            "packet_rate",
            "byte_rate",
            "syn_flag_count",
            "syn_ratio",
            "unique_dst_ports",
            "unique_dst_ips",
        ]
        merged_df[fill_zeros] = merged_df[fill_zeros].fillna(0)

        # Repeated destination attempts indicator
        # Counts occurrences of same (src_ip, dst_ip, dst_port) within time window
        pair_counts = (
            df_work.groupby(["src_ip", "dst_ip", "dst_port", "time_window"])
            .size()
            .reset_index(name="same_dest_attempts")
        )

        final_df = pd.merge(
            merged_df,
            pair_counts,
            on=["src_ip", "dst_ip", "dst_port", "time_window"],
            how="left",
        )
        final_df["same_dest_attempts"] = final_df["same_dest_attempts"].fillna(1).astype(int)

        return final_df

    def get_feature_matrix(
        self, df: pd.DataFrame, feature_columns: Optional[List[str]] = None
    ) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Extract features and separate numerical feature matrix from metadata columns.
        
        Returns:
            Tuple of (full_features_df, model_ready_features_df).
        """
        full_df = self.extract_window_features(df)

        if feature_columns is None:
            feature_columns = [
                "packet_size",
                "packet_count_in_window",
                "byte_count_in_window",
                "packet_rate",
                "byte_rate",
                "syn_flag_count",
                "syn_ratio",
                "unique_dst_ports",
                "unique_dst_ips",
                "same_dest_attempts",
                "is_privileged_port",
            ]

        # Keep only available numerical columns
        available_cols = [c for c in feature_columns if c in full_df.columns]
        model_df = full_df[available_cols].copy()

        return full_df, model_df

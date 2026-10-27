"""
Machine Learning Anomaly Detection Module for SentinelNet.
Implements unsupervised anomaly detection using Isolation Forest, scoring,
feature attribution, and optional evaluation metrics when ground truth is available.
"""

from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

from src.preprocessing import TrafficPreprocessor
from src.utils import setup_logger

logger = setup_logger("anomaly_detector")


class NetworkAnomalyDetector:
    """
    Unsupervised network traffic anomaly detector using Isolation Forest.
    Calculates normalized anomaly scores and identifies anomalous features.
    """

    def __init__(
        self,
        contamination: float = 0.06,
        n_estimators: int = 100,
        random_state: int = 42,
    ):
        self.contamination = max(0.001, min(0.5, contamination))
        self.n_estimators = n_estimators
        self.random_state = random_state

        self.model: Optional[IsolationForest] = None
        self.preprocessor = TrafficPreprocessor()
        self.is_fitted = False
        self.feature_means_: Optional[np.ndarray] = None
        self.feature_stds_: Optional[np.ndarray] = None

    def fit(self, df: pd.DataFrame) -> "NetworkAnomalyDetector":
        """
        Fit Isolation Forest model on network traffic features.
        
        Args:
            df: DataFrame containing extracted traffic features.
        """
        if len(df) < 5:
            logger.warning("Dataset too small (< 5 rows) for robust ML training. Using fallback thresholds.")
            self.is_fitted = False
            return self

        # Fit preprocessor
        X_scaled = self.preprocessor.fit_transform(df)

        # Store baseline feature statistics for explanation
        self.feature_means_ = np.mean(X_scaled, axis=0)
        self.feature_stds_ = np.std(X_scaled, axis=0) + 1e-6

        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self.model.fit(X_scaled)
        self.is_fitted = True
        logger.info(f"Isolation Forest fitted with contamination={self.contamination} on {len(df)} samples.")
        return self

    def predict(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """
        Predict anomaly labels, continuous anomaly scores, and feature explanations.
        
        Returns:
            Tuple of:
            - binary labels: 1 for anomaly, 0 for normal
            - anomaly_scores: continuous float score between 0.0 (normal) and 1.0 (highly anomalous)
            - top_features: human-readable explanation of key deviating features
        """
        if not self.is_fitted or self.model is None or df.empty:
            # Fallback for unfitted / tiny datasets
            n = len(df)
            return np.zeros(n, dtype=int), np.zeros(n, dtype=float), ["Model not fitted (insufficient records)"] * n

        X_scaled = self.preprocessor.transform(df)

        # IsolationForest decision_function: lower (more negative) = more anomalous
        raw_scores = self.model.decision_function(X_scaled)

        # Convert raw scores to normalized 0.0 - 1.0 scale where 1.0 is most anomalous
        # decision_function typically ranges from -0.5 (very anomalous) to +0.5 (very normal)
        min_score = np.min(raw_scores)
        max_score = np.max(raw_scores)
        if max_score > min_score:
            # Invert so higher score = higher anomaly
            anomaly_scores = (max_score - raw_scores) / (max_score - min_score)
        else:
            anomaly_scores = np.zeros(len(raw_scores))

        # Binary prediction (-1 from scikit-learn is anomaly, 1 is normal)
        raw_preds = self.model.predict(X_scaled)
        binary_labels = np.where(raw_preds == -1, 1, 0)

        # Explain top deviating feature for anomalous records
        feature_names = self.preprocessor.get_feature_names()
        explanations = []

        for i in range(len(df)):
            if binary_labels[i] == 1 and self.feature_means_ is not None:
                # Compute absolute Z-score deviation from training mean
                z_scores = np.abs((X_scaled[i] - self.feature_means_) / self.feature_stds_)
                top_feature_idx = int(np.argmax(z_scores))
                top_feature_name = feature_names[top_feature_idx]
                top_deviation = z_scores[top_feature_idx]
                explanations.append(
                    f"Deviation in '{top_feature_name}' (z-score: {top_deviation:.1f}σ from baseline)"
                )
            else:
                explanations.append("Traffic patterns within standard statistical baseline")

        return binary_labels, anomaly_scores, explanations

    def evaluate(self, y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, Any]:
        """
        Calculate precision, recall, F1-score, and confusion matrix
        when ground truth labels exist strictly for model evaluation.
        """
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_true, y_pred, average="binary", zero_division=0
        )
        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)

        return {
            "precision": float(precision),
            "recall": float(recall),
            "f1_score": float(f1),
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
            "accuracy": float((tp + tn) / max(1, (tp + tn + fp + fn))),
        }

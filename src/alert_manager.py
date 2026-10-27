"""
Security Alert Manager for SentinelNet.
Coordinates alert generation across Rule-Based and Machine Learning detection engines,
performs alert correlation (Hybrid detection), persists alerts to SQLite, and provides
filtering, searching, and export facilities.
"""

import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import pandas as pd

from src.database import DatabaseManager
from src.utils import get_project_root, setup_logger

logger = setup_logger("alert_manager")


class AlertManager:
    """
    Central hub for processing, correlating, and managing cybersecurity alerts.
    """

    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        self.db = db_manager or DatabaseManager()

    def process_and_save_detections(
        self,
        features_df: pd.DataFrame,
        ml_labels: List[int],
        ml_scores: List[float],
        ml_explanations: List[str],
        rule_alerts: List[Dict[str, Any]],
        session_id: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Merge rule alerts and high-confidence ML anomalies, perform deduplication/correlation,
        and save them to SQLite.
        
        Returns:
            Consolidated list of saved alert dictionaries.
        """
        consolidated_alerts: List[Dict[str, Any]] = []

        # 1. Add all rule-based alerts
        for ra in rule_alerts:
            alert = dict(ra)
            consolidated_alerts.append(alert)

        # 2. Extract ML anomalies that exceed a high threshold or are distinct from rule alerts
        # Look for anomalies with score >= 0.65 or marked by model
        ml_alert_seen_ips = set()
        for idx in range(len(features_df)):
            if idx < len(ml_labels) and ml_labels[idx] == 1:
                score = float(ml_scores[idx]) if idx < len(ml_scores) else 0.5
                # Only elevate if score is meaningful
                if score >= 0.55:
                    row = features_df.iloc[idx]
                    src_ip = str(row.get("src_ip", "Unknown"))
                    dst_ip = str(row.get("dst_ip", "Unknown"))
                    time_window = row.get("time_window", 0)
                    ts = str(row.get("datetime", row.get("timestamp", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))))

                    ml_key = (src_ip, time_window)
                    if ml_key not in ml_alert_seen_ips:
                        ml_alert_seen_ips.add(ml_key)

                        # Check if a rule alert already covers this exact source & window
                        matching_rule = next(
                            (a for a in consolidated_alerts if a.get("src_ip") == src_ip and a.get("detection_method") == "Rule-Based"),
                            None,
                        )

                        if matching_rule:
                            # Upgrade to Hybrid Detection!
                            matching_rule["detection_method"] = "Hybrid (Rule + ML)"
                            matching_rule["anomaly_score"] = round(score, 3)
                            matching_rule["explanation"] += f" [ML Anomaly Score: {score:.2f} confirms outlier]"
                            if matching_rule["severity"] == "Medium":
                                matching_rule["severity"] = "High"
                            elif matching_rule["severity"] == "High":
                                matching_rule["severity"] = "Critical"
                        else:
                            # Pure ML Anomaly Detection Alert
                            severity = "High" if score >= 0.75 else "Medium"
                            explanation = ml_explanations[idx] if idx < len(ml_explanations) else "Statistical outlier"
                            consolidated_alerts.append({
                                "timestamp": ts,
                                "alert_type": "Statistical Anomaly (Isolation Forest)",
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "severity": severity,
                                "detection_method": "Machine Learning",
                                "anomaly_score": round(score, 3),
                                "explanation": f"Unsupervised ML model identified statistical deviation: {explanation}.",
                                "recommended_action": (
                                    "Review source traffic behavior for unauthorized software, "
                                    "non-standard protocols, or novel evasion techniques."
                                ),
                                "acknowledged": False,
                            })

        # Persist consolidated alerts to database
        self.db.save_alerts(consolidated_alerts, session_id=session_id)
        logger.info(f"Persisted {len(consolidated_alerts)} consolidated alerts for session {session_id}.")
        return consolidated_alerts

    def get_alerts_dataframe(
        self,
        severity: Optional[str] = None,
        acknowledged: Optional[bool] = None,
        search_query: Optional[str] = None,
        limit: int = 500,
    ) -> pd.DataFrame:
        """Fetch alerts from SQLite with filtering."""
        return self.db.get_alerts(
            severity=severity,
            acknowledged=acknowledged,
            search_query=search_query,
            limit=limit,
        )

    def acknowledge(self, alert_id: int) -> bool:
        """Acknowledge an alert by ID."""
        return self.db.acknowledge_alert(alert_id)

    def get_summary_statistics(self) -> Dict[str, Any]:
        """Return high-level summary counts for security alerts."""
        return self.db.get_alert_stats()

    def export_alerts_csv(self, output_path: Optional[str] = None) -> Path:
        """Export all current alerts from database to CSV."""
        if output_path is None:
            dest = get_project_root() / "reports" / "alerts_export.csv"
        else:
            dest = Path(output_path)
            if not dest.is_absolute():
                dest = get_project_root() / dest

        dest.parent.mkdir(parents=True, exist_ok=True)
        df = self.get_alerts_dataframe(limit=5000)
        df.to_csv(dest, index=False)
        return dest

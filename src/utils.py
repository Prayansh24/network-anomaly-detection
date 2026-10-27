"""
Utility functions for SentinelNet: Configuration, Logging, and Network Helpers.
"""

import ipaddress
import logging
from pathlib import Path
from typing import Any, Dict, Optional
import yaml

_LOGGER_INITIALIZED = False


def get_project_root() -> Path:
    """Return the absolute path to the project root directory."""
    # Since src/utils.py is inside <root>/src/, parent is <root>
    return Path(__file__).resolve().parent.parent


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load project configuration from a YAML file.
    
    Args:
        config_path: Path to the YAML file. If None, defaults to config.yaml in project root.
        
    Returns:
        Dictionary containing configuration parameters.
    """
    if config_path is None:
        target_path = get_project_root() / "config.yaml"
    else:
        target_path = Path(config_path)
        if not target_path.is_absolute():
            target_path = get_project_root() / target_path

    if not target_path.exists():
        # Fallback default configuration
        return {
            "app": {"name": "SentinelNet", "version": "1.0.0", "theme": "dark"},
            "database": {"db_path": "data/network_security.db"},
            "capture": {"default_duration_sec": 20, "default_packet_limit": 1000},
            "rules": {
                "port_scan": {"min_unique_ports": 10, "window_seconds": 10, "severity": "High"},
                "traffic_spike": {"packet_rate_threshold": 40.0, "byte_rate_threshold": 50000.0, "severity": "Medium"},
                "syn_flood": {"min_syn_packets": 15, "syn_ratio_threshold": 0.70, "severity": "Critical"},
                "repeated_connections": {"min_attempts_to_same_dest": 20, "window_seconds": 10, "severity": "Medium"},
                "unusual_destinations": {"min_unique_dst_ips": 15, "window_seconds": 10, "severity": "High"},
            },
            "ml": {
                "algorithm": "IsolationForest",
                "default_contamination": 0.05,
                "n_estimators": 100,
                "random_state": 42,
                "min_records_for_training": 15,
            },
        }

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
            return cfg or {}
    except Exception as e:
        logger = logging.getLogger("SentinelNet")
        logger.warning(f"Failed to parse config file at {target_path}: {e}. Using defaults.")
        return {}


def setup_logger(name: str = "SentinelNet", level: int = logging.INFO) -> logging.Logger:
    """
    Configure and return a standardized logger.
    
    Args:
        name: Name of the logger.
        level: Logging verbosity level.
        
    Returns:
        logging.Logger instance.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(level)
        ch = logging.StreamHandler()
        ch.setLevel(level)
        formatter = logging.Formatter(
            fmt="%(asctime)s | [%(levelname)s] | %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        ch.setFormatter(formatter)
        logger.addHandler(ch)
    return logger


def protocol_name(proto_value: Any) -> str:
    """
    Convert IP protocol number or string representation to standard name.
    
    Args:
        proto_value: Integer protocol code or string.
        
    Returns:
        Upper-case protocol name (e.g., 'TCP', 'UDP', 'ICMP', 'DNS', 'OTHER').
    """
    proto_str = str(proto_value).strip().upper()
    proto_map = {
        "1": "ICMP",
        "6": "TCP",
        "17": "UDP",
        "53": "DNS",
        "ICMP": "ICMP",
        "TCP": "TCP",
        "UDP": "UDP",
        "DNS": "DNS",
        "HTTP": "TCP",
        "HTTPS": "TCP",
    }
    return proto_map.get(proto_str, proto_str if proto_str.isalpha() else "OTHER")


def format_bytes(num_bytes: float) -> str:
    """Format bytes into readable human format (KB, MB, GB)."""
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:3.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} TB"


def is_valid_ip(ip_str: str) -> bool:
    """Check if given string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(str(ip_str).strip())
        return True
    except (ValueError, AttributeError):
        return False


def is_private_ip(ip_str: str) -> bool:
    """Check if IP address belongs to private / RFC 1918 space."""
    try:
        addr = ipaddress.ip_address(str(ip_str).strip())
        return addr.is_private
    except (ValueError, AttributeError):
        return False


def get_security_theme_css() -> str:
    """Return sleek dark cybersecurity dashboard CSS."""
    return """
    <style>
        /* General dark security theme */
        .main {
            background-color: #0b0f19;
        }
        .stMetric {
            background: linear-gradient(135deg, #161f30 0%, #111827 100%);
            padding: 14px 18px;
            border-radius: 8px;
            border: 1px solid #1f2937;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.4);
        }
        .stMetric label {
            color: #9ca3af !important;
            font-size: 0.85rem !important;
            font-weight: 600 !important;
            letter-spacing: 0.05em;
            text-transform: uppercase;
        }
        .stMetric div[data-testid="stMetricValue"] {
            color: #f3f4f6 !important;
            font-size: 1.8rem !important;
            font-weight: 700 !important;
            font-family: 'Consolas', 'Courier New', monospace;
        }
        .badge-critical {
            background-color: #7f1d1d;
            color: #fca5a5;
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: 700;
            font-size: 0.8rem;
            border: 1px solid #ef4444;
        }
        .badge-high {
            background-color: #7c2d12;
            color: #fdba74;
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: 700;
            font-size: 0.8rem;
            border: 1px solid #f97316;
        }
        .badge-medium {
            background-color: #713f12;
            color: #fde047;
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: 700;
            font-size: 0.8rem;
            border: 1px solid #eab308;
        }
        .badge-low {
            background-color: #14532d;
            color: #86efac;
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: 700;
            font-size: 0.8rem;
            border: 1px solid #22c55e;
        }
        .badge-synthetic {
            background-color: #312e81;
            color: #c7d2fe;
            padding: 4px 10px;
            border-radius: 4px;
            font-weight: 700;
            font-size: 0.82rem;
            border: 1px solid #6366f1;
            display: inline-block;
        }
        .card-panel {
            background: #111827;
            border-radius: 8px;
            padding: 16px;
            border: 1px solid #1f2937;
            margin-bottom: 16px;
        }
    </style>
    """


def run_pipeline(
    raw_df: Any,
    source_name: str = "SYNTHETIC DEMO DATA",
    contamination: float = 0.06,
    window_sec: float = 10.0,
) -> Dict[str, Any]:
    """
    Execute full end-to-end anomaly detection pipeline:
    1. Feature extraction (packet & window aggregations)
    2. ML Anomaly Detection (Isolation Forest)
    3. Deterministic Rule Engine evaluation
    4. Alert Correlation & SQLite Database persistence
    
    Returns:
        Dictionary containing all pipeline outputs and stats.
    """
    from src.alert_manager import AlertManager
    from src.anomaly_detector import NetworkAnomalyDetector
    from src.database import DatabaseManager
    from src.feature_extraction import TrafficFeatureExtractor
    from src.reporting import SecurityReportGenerator
    from src.rule_engine import RuleBasedDetectionEngine

    # 1. Feature Extraction
    extractor = TrafficFeatureExtractor(window_size_sec=window_sec)
    features_df = extractor.extract_window_features(raw_df)

    # 2. Machine Learning Anomaly Detection
    detector = NetworkAnomalyDetector(contamination=contamination, random_state=42)
    detector.fit(features_df)
    ml_labels, ml_scores, ml_explanations = detector.predict(features_df)

    # Add ML predictions back into features_df
    features_df["is_ml_anomaly"] = ml_labels
    features_df["anomaly_score"] = ml_scores
    features_df["anomaly_explanation"] = ml_explanations

    # 3. Rule-Based Detection
    rule_engine = RuleBasedDetectionEngine()
    rule_alerts = rule_engine.evaluate_traffic(features_df)

    # 4. Persistence & Correlation
    db_mgr = DatabaseManager()
    session_id = db_mgr.create_session(
        session_name=f"{source_name} Analysis",
        source_type=source_name,
        total_records=len(raw_df),
        anomaly_count=int((ml_labels == 1).sum()),
        alert_count=len(rule_alerts),
    )

    alert_mgr = AlertManager(db_manager=db_mgr)
    consolidated_alerts = alert_mgr.process_and_save_detections(
        features_df=features_df,
        ml_labels=ml_labels.tolist(),
        ml_scores=ml_scores.tolist(),
        ml_explanations=ml_explanations,
        rule_alerts=rule_alerts,
        session_id=session_id,
    )

    # 5. Security Summary
    reporter = SecurityReportGenerator(session_name=f"{source_name} Audit")
    summary = reporter.generate_summary_dictionary(
        traffic_df=raw_df,
        features_df=features_df,
        ml_anomalies_count=int((ml_labels == 1).sum()),
        alerts=consolidated_alerts,
        source_type=source_name,
    )

    # 6. Optional evaluation if ground truth label exists
    evaluation = None
    if "is_anomaly" in raw_df.columns:
        y_true = raw_df["is_anomaly"].values
        evaluation = detector.evaluate(y_true, ml_labels)

    return {
        "raw_df": raw_df,
        "features_df": features_df,
        "ml_labels": ml_labels,
        "ml_scores": ml_scores,
        "ml_explanations": ml_explanations,
        "rule_alerts": rule_alerts,
        "consolidated_alerts": consolidated_alerts,
        "session_id": session_id,
        "summary": summary,
        "evaluation": evaluation,
        "detector": detector,
        "source_name": source_name,
    }


"""
Automated unit tests for Database Module.
"""

import tempfile
from pathlib import Path
import pytest

from src.database import DatabaseManager


@pytest.fixture
def temp_db():
    with tempfile.TemporaryDirectory() as tmpdir:
        temp_path = Path(tmpdir) / "test_network.db"
        db = DatabaseManager(db_path=str(temp_path))
        yield db


def test_session_creation(temp_db):
    """Test creating an analysis session and retrieving it."""
    session_id = temp_db.create_session(
        session_name="Test Session",
        source_type="Synthetic Demo",
        total_records=500,
        anomaly_count=25,
        alert_count=3,
    )
    assert session_id > 0

    sessions_df = temp_db.get_recent_sessions(limit=5)
    assert len(sessions_df) == 1
    assert sessions_df["session_name"].iloc[0] == "Test Session"


def test_alert_persistence_and_acknowledgment(temp_db):
    """Test saving alerts, filtering them, and acknowledging."""
    session_id = temp_db.create_session("Alert Test", "CSV Upload")

    test_alerts = [
        {
            "alert_type": "Port Scan Detected",
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.1",
            "severity": "High",
            "detection_method": "Rule-Based",
            "anomaly_score": 0.85,
            "explanation": "Multiple ports accessed",
            "recommended_action": "Block IP",
            "acknowledged": False,
        },
        {
            "alert_type": "Traffic Spike",
            "src_ip": "10.0.0.8",
            "dst_ip": "10.0.0.1",
            "severity": "Medium",
            "detection_method": "Rule-Based",
            "anomaly_score": 0.60,
            "explanation": "Spike in bandwidth",
            "recommended_action": "Throttle",
            "acknowledged": False,
        },
    ]

    inserted = temp_db.save_alerts(test_alerts, session_id=session_id)
    assert inserted == 2

    # Query all
    df_alerts = temp_db.get_alerts()
    assert len(df_alerts) == 2

    # Query with filter
    df_high = temp_db.get_alerts(severity="High")
    assert len(df_high) == 1
    assert df_high["src_ip"].iloc[0] == "10.0.0.5"

    # Acknowledge first alert
    first_id = int(df_alerts["id"].iloc[0])
    ack_res = temp_db.acknowledge_alert(first_id)
    assert ack_res is True

    # Check stats
    stats = temp_db.get_alert_stats()
    assert stats["total_alerts"] == 2
    assert stats["acknowledged"] == 1
    assert stats["unacknowledged"] == 1


def test_reset_demo_data(temp_db):
    """Ensure resetting demo data clears rows while retaining table schema."""
    temp_db.create_session("Session to clear", "Demo")
    temp_db.save_alerts([{"alert_type": "Test", "severity": "Low"}])

    res = temp_db.reset_demo_data()
    assert res is True

    sessions = temp_db.get_recent_sessions()
    alerts = temp_db.get_alerts()
    assert len(sessions) == 0
    assert len(alerts) == 0

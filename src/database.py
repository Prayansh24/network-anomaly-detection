"""
Database module for SentinelNet.
Manages SQLite database storage for sessions, security alerts, and analysis metrics.
"""

import datetime
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Tuple
import pandas as pd

from src.utils import get_project_root, setup_logger

logger = setup_logger("database")


class DatabaseManager:
    """Manages SQLite persistence for SentinelNet with parameterized queries."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            self.db_path = get_project_root() / "data" / "network_security.db"
        else:
            p = Path(db_path)
            self.db_path = p if p.is_absolute() else get_project_root() / p

        # Ensure parent directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        """Create and return a database connection with row factory enabled."""
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self) -> None:
        """Initialize required database tables and indexes if they do not exist."""
        conn = self.get_connection()
        try:
            with conn:
                cursor = conn.cursor()

                # Table: analysis_sessions
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS analysis_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_name TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    total_records INTEGER DEFAULT 0,
                    anomaly_count INTEGER DEFAULT 0,
                    alert_count INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'Completed',
                    notes TEXT
                );
                """)

                # Table: security_alerts
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER,
                    timestamp TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    severity TEXT NOT NULL,
                    detection_method TEXT NOT NULL,
                    anomaly_score REAL,
                    explanation TEXT,
                    recommended_action TEXT,
                    acknowledged INTEGER DEFAULT 0,
                    acknowledged_at TEXT,
                    FOREIGN KEY(session_id) REFERENCES analysis_sessions(id) ON DELETE SET NULL
                );
                """)

                # Table: analysis_summaries
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS analysis_summaries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    metric_value REAL,
                    metric_text TEXT,
                    FOREIGN KEY(session_id) REFERENCES analysis_sessions(id) ON DELETE CASCADE
                );
                """)

                # Create useful indexes for fast search and filtering
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security_alerts(severity);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_acknowledged ON security_alerts(acknowledged);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON security_alerts(timestamp);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON security_alerts(src_ip);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_timestamp ON analysis_sessions(timestamp);")

                conn.commit()
            logger.info(f"Database initialized successfully at {self.db_path}")
        except sqlite3.Error as e:
            logger.error(f"Failed to initialize database: {e}")
            raise
        finally:
            conn.close()

    def create_session(
        self,
        session_name: str,
        source_type: str,
        total_records: int = 0,
        anomaly_count: int = 0,
        alert_count: int = 0,
        status: str = "Completed",
        notes: str = "",
    ) -> int:
        """Create a new analysis session record and return its ID."""
        now_iso = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = self.get_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO analysis_sessions 
                    (session_name, timestamp, source_type, total_records, anomaly_count, alert_count, status, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (session_name, now_iso, source_type, total_records, anomaly_count, alert_count, status, notes),
                )
                conn.commit()
                return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error(f"Failed to create session: {e}")
            return -1
        finally:
            conn.close()

    def save_alerts(self, alerts: List[Dict[str, Any]], session_id: Optional[int] = None) -> int:
        """
        Save a batch of security alerts into the database.
        
        Args:
            alerts: List of alert dictionaries.
            session_id: Associated session ID.
            
        Returns:
            Number of alerts inserted.
        """
        if not alerts:
            return 0

        inserted = 0
        now_iso = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = self.get_connection()
        try:
            with conn:
                cursor = conn.cursor()
                for a in alerts:
                    cursor.execute(
                        """
                        INSERT INTO security_alerts
                        (session_id, timestamp, alert_type, src_ip, dst_ip, severity, detection_method, 
                         anomaly_score, explanation, recommended_action, acknowledged)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            session_id,
                            a.get("timestamp", now_iso),
                            a.get("alert_type", "Unknown Alert"),
                            a.get("src_ip", "N/A"),
                            a.get("dst_ip", "N/A"),
                            a.get("severity", "Medium"),
                            a.get("detection_method", "Rule-Based"),
                            float(a.get("anomaly_score", 0.0)) if a.get("anomaly_score") is not None else None,
                            a.get("explanation", ""),
                            a.get("recommended_action", ""),
                            1 if a.get("acknowledged", False) else 0,
                        ),
                    )
                    inserted += 1
                conn.commit()
            return inserted
        except sqlite3.Error as e:
            logger.error(f"Failed to save alerts: {e}")
            return inserted
        finally:
            conn.close()

    def get_alerts(
        self,
        severity: Optional[str] = None,
        acknowledged: Optional[bool] = None,
        search_query: Optional[str] = None,
        limit: int = 500,
    ) -> pd.DataFrame:
        """
        Retrieve alerts with optional filtering and search.
        
        Returns:
            Pandas DataFrame containing alerts.
        """
        query = "SELECT * FROM security_alerts WHERE 1=1"
        params: List[Any] = []

        if severity and severity.upper() != "ALL":
            query += " AND severity = ?"
            params.append(severity)

        if acknowledged is not None:
            query += " AND acknowledged = ?"
            params.append(1 if acknowledged else 0)

        if search_query:
            term = f"%{search_query.strip()}%"
            query += " AND (src_ip LIKE ? OR dst_ip LIKE ? OR alert_type LIKE ? OR explanation LIKE ?)"
            params.extend([term, term, term, term])

        query += " ORDER BY timestamp DESC, id DESC LIMIT ?"
        params.append(limit)

        conn = self.get_connection()
        try:
            df = pd.read_sql_query(query, conn, params=params)
            return df
        except sqlite3.Error as e:
            logger.error(f"Failed to query alerts: {e}")
            return pd.DataFrame()
        finally:
            conn.close()

    def acknowledge_alert(self, alert_id: int) -> bool:
        """Mark an alert as acknowledged with the current timestamp."""
        now_iso = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = self.get_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE security_alerts SET acknowledged = 1, acknowledged_at = ? WHERE id = ?",
                    (now_iso, alert_id),
                )
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.Error as e:
            logger.error(f"Failed to acknowledge alert {alert_id}: {e}")
            return False
        finally:
            conn.close()

    def get_alert_stats(self) -> Dict[str, Any]:
        """Get aggregate counts for alerts by severity and acknowledgement status."""
        stats = {
            "total_alerts": 0,
            "unacknowledged": 0,
            "acknowledged": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM security_alerts")
            stats["total_alerts"] = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM security_alerts WHERE acknowledged = 0")
            stats["unacknowledged"] = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM security_alerts WHERE acknowledged = 1")
            stats["acknowledged"] = cursor.fetchone()[0]

            cursor.execute("SELECT severity, COUNT(*) FROM security_alerts GROUP BY severity")
            for sev, count in cursor.fetchall():
                if sev:
                    key = sev.strip().lower()
                    if key in stats:
                        stats[key] = count
            return stats
        except sqlite3.Error as e:
            logger.error(f"Failed to get alert stats: {e}")
            return stats
        finally:
            conn.close()

    def get_recent_sessions(self, limit: int = 10) -> pd.DataFrame:
        """Retrieve recent analysis sessions."""
        conn = self.get_connection()
        try:
            df = pd.read_sql_query(
                "SELECT * FROM analysis_sessions ORDER BY id DESC LIMIT ?",
                conn,
                params=[limit],
            )
            return df
        except sqlite3.Error as e:
            logger.error(f"Failed to get recent sessions: {e}")
            return pd.DataFrame()
        finally:
            conn.close()

    def reset_demo_data(self) -> bool:
        """
        Safely clears demo data from database tables without deleting the file.
        Preserves schema and indexes.
        """
        conn = self.get_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM security_alerts;")
                cursor.execute("DELETE FROM analysis_summaries;")
                cursor.execute("DELETE FROM analysis_sessions;")
                conn.commit()
            logger.info("Demo data reset successfully in SQLite database.")
            return True
        except sqlite3.Error as e:
            logger.error(f"Failed to reset demo data: {e}")
            return False
        finally:
            conn.close()

"""
SentinelNet: Network Traffic Analysis and Anomaly Detection System.
Main Streamlit Application Entrypoint.
"""

import sys
from pathlib import Path
import streamlit as st
import pandas as pd

# Add project root to sys.path to ensure module imports resolve smoothly
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.database import DatabaseManager
from src.synthetic_data import SyntheticTrafficGenerator
from src.utils import get_security_theme_css, load_config, run_pipeline

# Configure Streamlit page layout
st.set_page_config(
    page_title="SentinelNet | Network Anomaly Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Apply cybersecurity styling
st.markdown(get_security_theme_css(), unsafe_allow_html=True)

# Initialize Session State
if "pipeline_results" not in st.session_state:
    st.session_state["pipeline_results"] = None
if "active_source" not in st.session_state:
    st.session_state["active_source"] = "No Data Loaded"

# Sidebar System Health & Info
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=64)
    st.title("SentinelNet")
    st.caption("Network Traffic Anomaly Detection System")
    st.markdown("---")

    # System Status Panel
    st.subheader("System Status")
    db_mgr = DatabaseManager()
    db_stats = db_mgr.get_alert_stats()

    st.markdown(f"**Database:** `Connected (SQLite)`")
    st.markdown(f"**Historical Alerts:** `{db_stats['total_alerts']}`")
    st.markdown(f"**Unacknowledged:** `{db_stats['unacknowledged']}`")

    if st.session_state["pipeline_results"]:
        st.success(f"Active: {st.session_state['active_source']}")
    else:
        st.warning("Status: Standby (Awaiting Input)")

    st.markdown("---")
    st.markdown(
        """
        **Pages:**
        - `1_Overview`: Threat posture & trends
        - `2_Live_Monitoring`: Scapy packet capture
        - `3_Dataset_Analysis`: Upload & inspect CSV
        - `4_Anomaly_Detection`: ML Isolation Forest
        - `5_Security_Alerts`: Incident remediation
        - `6_Reports`: Audit export & summary
        """
    )
    st.caption("Developed for Computer Networks & Cybersecurity")

# Main Page Header
st.title("🛡️ SentinelNet Security Dashboard")
st.markdown(
    "A hybrid network traffic analysis and anomaly detection platform combining **unsupervised machine learning** "
    "(Isolation Forest) with **deterministic cybersecurity heuristics** to detect port scans, traffic spikes, "
    "SYN floods, and suspicious connection patterns."
)

st.markdown("---")

# Quick Action Banner / Hero Section
col_hero, col_quick = st.columns([2, 1])

with col_hero:
    st.markdown("### 🚀 Quick Start: Demonstration Mode")
    st.markdown(
        "Demonstrate the entire network security pipeline offline without needing live raw capture privileges or external dependencies. "
        "The deterministic synthetic generator simulates normal web/DNS browsing interleaved with realistic cyber attack patterns."
    )
    st.info(
        "ℹ️ **SYNTHETIC DEMO MODE:** Explicitly simulated for university project demonstration and testing. "
        "Exercises feature extraction, Isolation Forest scoring, rule engines, alerts, and reporting."
    )

with col_quick:
    st.markdown("### ⚡ Instant Demo")
    if st.button("🔥 Run Complete Synthetic Demo", type="primary", use_container_width=True):
        with st.spinner("Generating synthetic packet metadata and executing security pipeline..."):
            gen = SyntheticTrafficGenerator(seed=42)
            raw_traffic = gen.generate_complete_dataset()
            results = run_pipeline(
                raw_df=raw_traffic,
                source_name="SYNTHETIC DEMO DATA",
                contamination=0.06,
            )
            st.session_state["pipeline_results"] = results
            st.session_state["active_source"] = "SYNTHETIC DEMO DATA"
            st.success("✅ Demo pipeline executed successfully! View findings in the Overview and Anomaly Detection pages.")

# System Architecture & Capabilities Cards
st.markdown("### 🔍 System Capabilities")

col1, col2, col3 = st.columns(3)

with col1:
    st.markdown(
        """
        <div class="card-panel">
            <h4>📡 Traffic Ingestion</h4>
            <ul>
                <li>Optional Scapy live packet capture</li>
                <li>Offline CSV dataset loader with schema mapping</li>
                <li>100% deterministic synthetic traffic generator</li>
                <li>Zero payload collection (Privacy-Preserving)</li>
            </ul>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col2:
    st.markdown(
        """
        <div class="card-panel">
            <h4>🤖 Machine Learning Pipeline</h4>
            <ul>
                <li>Unsupervised Isolation Forest algorithm</li>
                <li>Normalized outlier scoring (0.0 to 1.0)</li>
                <li>Z-score feature deviation attribution</li>
                <li>Ground-truth evaluation (Precision, Recall, F1)</li>
            </ul>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col3:
    st.markdown(
        """
        <div class="card-panel">
            <h4>⚙️ Rule Engine & Alerts</h4>
            <ul>
                <li>Port scan & horizontal sweep detection</li>
                <li>TCP SYN-heavy flood indicators</li>
                <li>Volumetric packet/byte surge alarms</li>
                <li>SQLite persistent alert storage & triage</li>
            </ul>
        </div>
        """,
        unsafe_allow_html=True,
    )

# Current Pipeline Status
if st.session_state["pipeline_results"]:
    res = st.session_state["pipeline_results"]
    summary = res["summary"]

    st.markdown("---")
    st.subheader(f"📊 Current Analysis Session: {st.session_state['active_source']}")

    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    kpi1.metric("Packets Analyzed", f"{summary['total_records']:,}")
    kpi2.metric("ML Anomalies", f"{summary['ml_anomalies_count']} ({summary['anomaly_rate_pct']}%)")
    kpi3.metric("Security Alerts", f"{summary['total_alerts']}")
    kpi4.metric("Threat Level", summary["overall_threat_level"])

    st.markdown("👉 **Navigate using the sidebar to explore interactive charts, anomaly scatter plots, and security alerts.**")
else:
    st.markdown("---")
    st.info("💡 **Ready to begin:** Click **'Run Complete Synthetic Demo'** above or visit **Dataset Analysis** to upload your own CSV traffic file.")

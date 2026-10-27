"""
SentinelNet: Cybersecurity Audit Reports Page.
Compiles audit summaries, threat source rankings, protocol analytics,
and generates downloadable Markdown and CSV reports.
"""

import sys
from pathlib import Path
import streamlit as st
import pandas as pd
import plotly.express as px

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.reporting import SecurityReportGenerator
from src.synthetic_data import SyntheticTrafficGenerator
from src.utils import get_security_theme_css, run_pipeline

st.set_page_config(page_title="Audit Reports | SentinelNet", page_icon="📝", layout="wide")
st.markdown(get_security_theme_css(), unsafe_allow_html=True)

st.title("📝 Cybersecurity Audit & Compliance Reports")
st.markdown(
    "Generate formalized security reports summarizing traffic characteristics, anomaly distribution, "
    "identified threat actors, and recommended defense remediations."
)

# Check if pipeline data exists
if st.session_state.get("pipeline_results") is None:
    st.info("⚠️ No audit session active. Run synthetic demonstration data below or analyze an uploaded dataset.")
    if st.button("🔥 Run Synthetic Demo Data Now", type="primary"):
        with st.spinner("Compiling demo report..."):
            gen = SyntheticTrafficGenerator(seed=42)
            raw_traffic = gen.generate_complete_dataset()
            results = run_pipeline(raw_traffic, source_name="SYNTHETIC DEMO DATA")
            st.session_state["pipeline_results"] = results
            st.session_state["active_source"] = "SYNTHETIC DEMO DATA"
            st.rerun()
    st.stop()
else:
    results = st.session_state["pipeline_results"]
    summary = results["summary"]
    alerts = results["consolidated_alerts"]
    raw_df = results["raw_df"]

    reporter = SecurityReportGenerator(session_name=summary.get("session_name", "Traffic Audit"))
    markdown_report = reporter.generate_markdown_report(summary, alerts)

    st.markdown("---")

    # Executive Overview Metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Audit Target", summary.get("source_type", "N/A"))
    col2.metric("Total Records", f"{summary.get('total_records', 0):,}")
    col3.metric("ML Anomalies Flagged", summary.get("ml_anomalies_count", 0))
    col4.metric("Assessed Threat Posture", summary.get("overall_threat_level", "LOW"))

    st.markdown("---")

    # Top Suspicious Threat Sources & Targeted Ports
    col_src, col_dst = st.columns(2)

    with col_src:
        st.subheader("🎯 Top Suspicious Source IPs (Attacker Hosts)")
        alerts_df = pd.DataFrame(alerts)
        if not alerts_df.empty and "src_ip" in alerts_df.columns:
            src_counts = alerts_df["src_ip"].value_counts().reset_index()
            src_counts.columns = ["Source IP", "Alert Count"]

            fig_src = px.bar(
                src_counts.head(7),
                x="Source IP",
                y="Alert Count",
                color="Alert Count",
                color_continuous_scale="Reds",
                template="plotly_dark",
            )
            fig_src.update_layout(
                paper_bgcolor="#0b0f19",
                plot_bgcolor="#111827",
                margin=dict(l=20, r=20, t=20, b=20),
                height=300,
            )
            st.plotly_chart(fig_src, use_container_width=True)
        else:
            st.info("No threat source IPs recorded in alerts.")

    with col_dst:
        st.subheader("🎯 Most Targeted Destination Ports")
        if "dst_port" in raw_df.columns:
            port_counts = raw_df["dst_port"].value_counts().head(7).reset_index()
            port_counts.columns = ["Port", "Packet Volume"]
            port_counts["Port"] = port_counts["Port"].astype(str)

            fig_port = px.bar(
                port_counts,
                x="Port",
                y="Packet Volume",
                color="Packet Volume",
                color_continuous_scale="Purples",
                template="plotly_dark",
            )
            fig_port.update_layout(
                paper_bgcolor="#0b0f19",
                plot_bgcolor="#111827",
                margin=dict(l=20, r=20, t=20, b=20),
                height=300,
            )
            st.plotly_chart(fig_port, use_container_width=True)
        else:
            st.info("Port data unavailable.")

    st.markdown("---")

    # Full Markdown Report Preview & Export
    st.subheader("📄 Formal Security Audit Report Preview")

    with st.expander("👁️ View Formatted Markdown Audit Document", expanded=True):
        st.markdown(markdown_report)

    st.markdown("### 📥 Download Security Audit Package")
    col_d1, col_d2 = st.columns(2)

    with col_d1:
        st.download_button(
            label="📥 Download Audit Report (.md)",
            data=markdown_report.encode("utf-8"),
            file_name="sentinelnet_security_report.md",
            mime="text/markdown",
            use_container_width=True,
        )

    with col_d2:
        summary_df = pd.DataFrame([{
            "Metric": k,
            "Value": str(v),
        } for k, v in summary.items() if not isinstance(v, dict)])
        st.download_button(
            label="📥 Download Summary Metrics (.csv)",
            data=summary_df.to_csv(index=False).encode("utf-8"),
            file_name="sentinelnet_summary_metrics.csv",
            mime="text/csv",
            use_container_width=True,
        )

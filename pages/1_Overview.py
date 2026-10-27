"""
SentinelNet: Overview Dashboard Page.
Visualizes key cybersecurity metrics, traffic volume timelines, protocol splits,
and active alert posture.
"""

import sys
from pathlib import Path
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# Ensure project root in sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.synthetic_data import SyntheticTrafficGenerator
from src.utils import get_security_theme_css, run_pipeline

st.set_page_config(page_title="Overview | SentinelNet", page_icon="📊", layout="wide")
st.markdown(get_security_theme_css(), unsafe_allow_html=True)

st.title("📊 Security Posture & Traffic Overview")

# Check if pipeline data is available
if st.session_state.get("pipeline_results") is None:
    st.info("⚠️ No traffic dataset has been analyzed yet. Run the demonstration dataset below or upload a CSV in Dataset Analysis.")
    if st.button("🔥 Run Synthetic Demo Data Now", type="primary"):
        with st.spinner("Executing analysis pipeline on synthetic demonstration traffic..."):
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
    raw_df = results["raw_df"]
    features_df = results["features_df"]
    alerts = results["consolidated_alerts"]

    # Badge for simulated vs real
    if "SYNTHETIC" in st.session_state.get("active_source", "").upper():
        st.markdown('<span class="badge-synthetic">SIMULATED SYNTHETIC DEMO DATA</span>', unsafe_allow_html=True)
    else:
        st.markdown(f"**Data Source:** `{st.session_state.get('active_source')}`")

    st.markdown("##")

    # Key Metrics Row
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    kpi1.metric("Packets Processed", f"{summary['total_records']:,}")
    kpi2.metric("ML Anomalies Flagged", f"{summary['ml_anomalies_count']:,}", f"{summary['anomaly_rate_pct']}% of total")
    kpi3.metric("Security Alerts", f"{summary['total_alerts']}", "Rule & Hybrid Detections")

    # Threat level color coding
    threat_level = summary["overall_threat_level"]
    threat_color = "#ef4444" if threat_level in ["CRITICAL", "HIGH"] else ("#eab308" if threat_level == "ELEVATED" else "#22c55e")
    kpi4.metric("Threat Level", threat_level)

    st.markdown("---")

    # Visualizations Row 1: Traffic Volume Over Time & Protocol Distribution
    row1_col1, row1_col2 = st.columns([2, 1])

    with row1_col1:
        st.subheader("📈 Traffic Volume & Attack Timeline")
        if "datetime" in raw_df.columns:
            # Aggregate packets per second
            raw_df["time_sec"] = pd.to_datetime(raw_df["datetime"]).dt.floor("s")
            time_series = raw_df.groupby(["time_sec", "is_anomaly"]).size().reset_index(name="packet_count")
            time_series["Traffic Category"] = time_series["is_anomaly"].map({0: "Normal Traffic", 1: "Suspicious / Attack"})

            fig_time = px.area(
                time_series,
                x="time_sec",
                y="packet_count",
                color="Traffic Category",
                color_discrete_map={"Normal Traffic": "#3b82f6", "Suspicious / Attack": "#ef4444"},
                labels={"time_sec": "Timestamp", "packet_count": "Packets / sec"},
                template="plotly_dark",
            )
            fig_time.update_layout(
                paper_bgcolor="#0b0f19",
                plot_bgcolor="#111827",
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
                margin=dict(l=20, r=20, t=30, b=20),
                height=340,
            )
            st.plotly_chart(fig_time, use_container_width=True)
        else:
            st.info("Time series requires datetime field.")

    with row1_col2:
        st.subheader("🌐 Protocol Distribution")
        proto_df = raw_df["protocol"].value_counts().reset_index()
        proto_df.columns = ["Protocol", "Count"]

        fig_proto = px.pie(
            proto_df,
            names="Protocol",
            values="Count",
            hole=0.5,
            color="Protocol",
            color_discrete_sequence=px.colors.qualitative.Pastel,
            template="plotly_dark",
        )
        fig_proto.update_layout(
            paper_bgcolor="#0b0f19",
            plot_bgcolor="#111827",
            margin=dict(l=10, r=10, t=20, b=20),
            height=340,
            legend=dict(orientation="h", yanchor="bottom", y=-0.2),
        )
        st.plotly_chart(fig_proto, use_container_width=True)

    # Visualizations Row 2: Normal vs Anomaly Distribution & Packet Size Distribution
    row2_col1, row2_col2 = st.columns(2)

    with row2_col1:
        st.subheader("⚖️ Normal vs. Anomalous Records")
        ml_counts = pd.Series(results["ml_labels"]).value_counts().reset_index()
        ml_counts.columns = ["Label_Code", "Count"]
        ml_counts["Label"] = ml_counts["Label_Code"].map({0: "Normal Traffic", 1: "Potentially Anomalous"})

        fig_norm = px.bar(
            ml_counts,
            x="Label",
            y="Count",
            color="Label",
            color_discrete_map={"Normal Traffic": "#10b981", "Potentially Anomalous": "#f59e0b"},
            text="Count",
            template="plotly_dark",
        )
        fig_norm.update_layout(
            paper_bgcolor="#0b0f19",
            plot_bgcolor="#111827",
            showlegend=False,
            margin=dict(l=20, r=20, t=20, b=20),
            height=280,
        )
        st.plotly_chart(fig_norm, use_container_width=True)

    with row2_col2:
        st.subheader("📦 Packet Size Distribution (Bytes)")
        fig_size = px.histogram(
            raw_df,
            x="packet_size",
            nbins=35,
            color_discrete_sequence=["#6366f1"],
            labels={"packet_size": "Packet Length (Bytes)"},
            template="plotly_dark",
        )
        fig_size.update_layout(
            paper_bgcolor="#0b0f19",
            plot_bgcolor="#111827",
            margin=dict(l=20, r=20, t=20, b=20),
            height=280,
        )
        st.plotly_chart(fig_size, use_container_width=True)

    st.markdown("---")

    # Recent Security Alerts Feed
    st.subheader("🚨 Incident & Alert Feed")

    if not alerts:
        st.success("🎉 No active security incidents or threshold violations detected.")
    else:
        alerts_df = pd.DataFrame(alerts)
        display_cols = ["severity", "alert_type", "src_ip", "dst_ip", "detection_method", "timestamp", "explanation"]
        avail_cols = [c for c in display_cols if c in alerts_df.columns]

        st.dataframe(
            alerts_df[avail_cols].head(8),
            column_config={
                "severity": st.column_config.TextColumn("Severity"),
                "alert_type": st.column_config.TextColumn("Alert Type"),
                "src_ip": st.column_config.TextColumn("Source Host"),
                "dst_ip": st.column_config.TextColumn("Target Host"),
                "detection_method": st.column_config.TextColumn("Engine"),
                "timestamp": st.column_config.TextColumn("Time"),
                "explanation": st.column_config.TextColumn("Diagnostic Details"),
            },
            use_container_width=True,
            hide_index=True,
        )

    st.caption("ℹ️ Visit the 'Security Alerts' page in the sidebar to review full defensive remediation guidance and acknowledge alerts.")

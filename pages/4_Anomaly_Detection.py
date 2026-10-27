"""
SentinelNet: Machine Learning Anomaly Detection Page.
Explores Isolation Forest model behaviors, normalized anomaly scores,
feature deviation attributions, and model evaluation metrics.
"""

import sys
from pathlib import Path
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.synthetic_data import SyntheticTrafficGenerator
from src.utils import get_security_theme_css, run_pipeline

st.set_page_config(page_title="Anomaly Detection | SentinelNet", page_icon="🤖", layout="wide")
st.markdown(get_security_theme_css(), unsafe_allow_html=True)

st.title("🤖 Machine Learning Anomaly Detection")
st.markdown(
    "Unsupervised anomaly detection powered by **Isolation Forest**. "
    "Unlike rule-based systems that rely on fixed thresholds, Isolation Forest isolates anomalous observations "
    "by randomly selecting a feature and randomly selecting a split value between the maximum and minimum values."
)

# Check for pipeline results
if st.session_state.get("pipeline_results") is None:
    st.info("⚠️ No analyzed data available. Run the demonstration below or upload a dataset in Dataset Analysis.")
    if st.button("🔥 Run Synthetic Demo Data Now", type="primary"):
        with st.spinner("Analyzing demo traffic..."):
            gen = SyntheticTrafficGenerator(seed=42)
            raw_traffic = gen.generate_complete_dataset()
            results = run_pipeline(raw_traffic, source_name="SYNTHETIC DEMO DATA")
            st.session_state["pipeline_results"] = results
            st.session_state["active_source"] = "SYNTHETIC DEMO DATA"
            st.rerun()
    st.stop()
else:
    results = st.session_state["pipeline_results"]
    raw_df = results["raw_df"]
    features_df = results["features_df"]
    ml_scores = np.array(results["ml_scores"])
    ml_labels = np.array(results["ml_labels"])
    ml_explanations = results["ml_explanations"]

    st.markdown("---")

    # Educational Banner
    st.warning(
        "💡 **Cybersecurity Engineering Note:** An anomaly is a statistical outlier compared to baseline network patterns. "
        "It indicates unusual behavioral deviation (e.g. unexpected port sweeps, sudden byte bursts, or strange protocols) "
        "and warrants security investigation, but is not definitive proof of malicious attack on its own."
    )

    st.markdown("##")

    # Section 1: Anomaly Metrics & Contamination Tuning
    col_m1, col_m2, col_m3, col_m4 = st.columns(4)
    total_records = len(features_df)
    anomaly_count = int(np.sum(ml_labels == 1))
    normal_count = total_records - anomaly_count
    anomaly_pct = round((anomaly_count / max(1, total_records)) * 100, 2)

    col_m1.metric("Analyzed Records", f"{total_records:,}")
    col_m2.metric("Flagged Anomalies", f"{anomaly_count:,}", f"{anomaly_pct}%")
    col_m3.metric("Normal Records", f"{normal_count:,}")
    col_m4.metric("Mean Anomaly Score", f"{np.mean(ml_scores):.3f}")

    st.markdown("---")

    # Visualizations Row 1: Anomaly Score Distribution & Scatter Plot
    col_chart1, col_chart2 = st.columns(2)

    with col_chart1:
        st.subheader("📊 Anomaly Score Distribution (0.0 = Normal, 1.0 = Outlier)")
        scores_df = pd.DataFrame({
            "Anomaly Score": ml_scores,
            "Classification": np.where(ml_labels == 1, "Anomalous", "Normal"),
        })

        fig_hist = px.histogram(
            scores_df,
            x="Anomaly Score",
            color="Classification",
            nbins=40,
            color_discrete_map={"Normal": "#10b981", "Anomalous": "#ef4444"},
            barmode="overlay",
            opacity=0.75,
            template="plotly_dark",
        )
        fig_hist.update_layout(
            paper_bgcolor="#0b0f19",
            plot_bgcolor="#111827",
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
            margin=dict(l=20, r=20, t=20, b=20),
            height=320,
        )
        st.plotly_chart(fig_hist, use_container_width=True)

    with col_chart2:
        st.subheader("🎯 2D Multi-Feature Outlier Separation")
        # Plot packet_rate vs unique_dst_ports (or packet_size vs byte_rate)
        x_col = "packet_rate" if "packet_rate" in features_df.columns else "packet_size"
        y_col = "unique_dst_ports" if "unique_dst_ports" in features_df.columns else "byte_rate"

        scatter_df = features_df.copy()
        scatter_df["ML Classification"] = np.where(ml_labels == 1, "Anomaly", "Normal")

        fig_scatter = px.scatter(
            scatter_df,
            x=x_col,
            y=y_col,
            color="ML Classification",
            size="anomaly_score",
            hover_data=["src_ip", "dst_ip", "protocol"],
            color_discrete_map={"Normal": "#3b82f6", "Anomaly": "#f59e0b"},
            labels={x_col: "Packet Rate (pkts/sec)", y_col: "Unique Destination Ports Targeted"},
            template="plotly_dark",
        )
        fig_scatter.update_layout(
            paper_bgcolor="#0b0f19",
            plot_bgcolor="#111827",
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
            margin=dict(l=20, r=20, t=20, b=20),
            height=320,
        )
        st.plotly_chart(fig_scatter, use_container_width=True)

    st.markdown("---")

    # Section 2: Top Anomalous Records with Feature Attribution
    st.subheader("🔍 Top Outlier Records & Diagnostic Explanations")
    st.markdown("Below are the most statistically unusual network traffic events sorted by their Isolation Forest anomaly score.")

    top_anom_indices = np.argsort(ml_scores)[::-1][:15]
    top_records = []
    for idx in top_anom_indices:
        row = features_df.iloc[idx]
        top_records.append({
            "Score": round(float(ml_scores[idx]), 3),
            "Source IP": str(row.get("src_ip", "N/A")),
            "Target IP": str(row.get("dst_ip", "N/A")),
            "Protocol": str(row.get("protocol", "N/A")),
            "Port": int(row.get("dst_port", 0)),
            "Packet Rate (p/s)": round(float(row.get("packet_rate", 0)), 1),
            "Unique Ports": int(row.get("unique_dst_ports", 0)),
            "SYN Ratio": f"{float(row.get('syn_ratio', 0))*100:.0f}%",
            "Primary Feature Deviation": ml_explanations[idx],
        })

    top_anom_df = pd.DataFrame(top_records)
    st.dataframe(
        top_anom_df,
        column_config={
            "Score": st.column_config.ProgressColumn("Anomaly Score", min_value=0.0, max_value=1.0, format="%.2f"),
            "Primary Feature Deviation": st.column_config.TextColumn("Diagnostic Explanation", width="large"),
        },
        use_container_width=True,
        hide_index=True,
    )

    # Section 3: Ground Truth Evaluation (strictly when labeled data is provided)
    st.markdown("---")
    st.subheader("📈 Ground-Truth Evaluation Metrics")

    eval_metrics = results.get("evaluation")
    if eval_metrics is not None:
        st.markdown(
            "Ground-truth test labels were detected in this dataset (`is_anomaly`). "
            "The following validation metrics benchmark the unsupervised Isolation Forest predictions against the reference labels."
        )

        col_e1, col_e2, col_e3, col_e4 = st.columns(4)
        col_e1.metric("Precision", f"{eval_metrics['precision']:.3f}")
        col_e2.metric("Recall", f"{eval_metrics['recall']:.3f}")
        col_e3.metric("F1-Score", f"{eval_metrics['f1_score']:.3f}")
        col_e4.metric("Overall Accuracy", f"{eval_metrics['accuracy']:.3f}")

        col_cm1, col_cm2 = st.columns(2)
        with col_cm1:
            st.markdown("#### Confusion Matrix")
            cm_data = [
                [eval_metrics["true_negatives"], eval_metrics["false_positives"]],
                [eval_metrics["false_negatives"], eval_metrics["true_positives"]],
            ]
            fig_cm = px.imshow(
                cm_data,
                x=["Predicted Normal", "Predicted Anomaly"],
                y=["Actual Normal", "Actual Anomaly"],
                text_auto=True,
                color_continuous_scale="Blues",
                template="plotly_dark",
            )
            fig_cm.update_layout(
                paper_bgcolor="#0b0f19",
                plot_bgcolor="#111827",
                margin=dict(l=20, r=20, t=20, b=20),
                height=280,
            )
            st.plotly_chart(fig_cm, use_container_width=True)

        with col_cm2:
            st.markdown("#### Matrix Breakdown")
            st.markdown(f"- **True Negatives (TN):** `{eval_metrics['true_negatives']}` (Normal traffic correctly approved)")
            st.markdown(f"- **False Positives (FP):** `{eval_metrics['false_positives']}` (Normal traffic flagged as anomaly)")
            st.markdown(f"- **False Negatives (FN):** `{eval_metrics['false_negatives']}` (Attacks missed by unsupervised model)")
            st.markdown(f"- **True Positives (TP):** `{eval_metrics['true_positives']}` (Attacks correctly caught by model)")
            st.caption("Notice: Deterministic rules run alongside ML to catch specific patterns that unsupervised methods might score below the boundary.")
    else:
        st.info(
            "ℹ️ Ground-truth evaluation metrics appear when an uploaded dataset contains explicit `is_anomaly` or `attack_type` validation columns. "
            "Unsupervised models operate without labels during real-world inference."
        )

"""
SentinelNet: Offline Dataset Analysis Page.
Allows uploading custom CSV network traffic logs, validates schemas and formats,
provides sample synthetic datasets, and executes the security detection pipeline.
"""

import sys
from pathlib import Path
import streamlit as st
import pandas as pd

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.dataset_loader import DatasetLoader
from src.synthetic_data import SyntheticTrafficGenerator
from src.utils import get_security_theme_css, run_pipeline

st.set_page_config(page_title="Dataset Analysis | SentinelNet", page_icon="📁", layout="wide")
st.markdown(get_security_theme_css(), unsafe_allow_html=True)

st.title("📁 Offline Dataset Analysis & Ingestion")
st.markdown(
    "Upload pre-recorded network capture CSVs or test using our included synthetic evaluation datasets. "
    "SentinelNet automatically validates data schemas, normalizes headers, and inspects records for anomalies."
)

st.markdown("---")

col_upload, col_sample = st.columns([2, 1])

with col_sample:
    st.subheader("🧪 Sample Synthetic Data")
    st.markdown(
        "Download or instantly load our reference benchmark dataset containing normal browsing, DNS, "
        "SYN floods, port scans, and volumetric traffic spikes."
    )

    # Ensure sample dataset exists
    sample_file_path = DatasetLoader.get_sample_dataset_path()
    with open(sample_file_path, "rb") as f:
        sample_bytes = f.read()

    st.download_button(
        label="📥 Download Sample Synthetic CSV",
        data=sample_bytes,
        file_name="sentinelnet_synthetic_sample.csv",
        mime="text/csv",
        use_container_width=True,
    )

    if st.button("🚀 Load Sample Dataset Directly", type="secondary", use_container_width=True):
        loaded_df, val_res = DatasetLoader.validate_and_load(sample_file_path)
        if val_res.is_valid and loaded_df is not None:
            st.session_state["uploaded_traffic_df"] = loaded_df
            st.session_state["uploaded_file_name"] = "Sample Synthetic Dataset (Benchmark)"
            st.success("Sample benchmark loaded! Review preview below and start analysis.")

with col_upload:
    st.subheader("📤 Upload Network CSV Dataset")
    uploaded_file = st.file_uploader(
        "Choose a network traffic CSV file",
        type=["csv"],
        help="CSV must contain source/dest IPs, ports, protocol, and packet size or byte length.",
    )

    if uploaded_file is not None:
        with st.spinner("Validating schema and data formats..."):
            loaded_df, val_res = DatasetLoader.validate_and_load(uploaded_file)
            if not val_res.is_valid or loaded_df is None:
                st.error("❌ Dataset Validation Failed:")
                for err in val_res.errors:
                    st.markdown(f"- {err}")
            else:
                st.session_state["uploaded_traffic_df"] = loaded_df
                st.session_state["uploaded_file_name"] = uploaded_file.name
                st.success(f"✔️ Validation Passed: {len(loaded_df):,} records ready for analysis.")
                if val_res.warnings:
                    for warn in val_res.warnings:
                        st.warning(f"⚠️ Notice: {warn}")

st.markdown("---")

# Preview Section
if "uploaded_traffic_df" in st.session_state:
    df_to_analyze = st.session_state["uploaded_traffic_df"]
    file_label = st.session_state.get("uploaded_file_name", "Uploaded Dataset")

    st.subheader(f"🔍 Dataset Preview: {file_label}")

    metric1, metric2, metric3, metric4 = st.columns(4)
    metric1.metric("Total Records", f"{len(df_to_analyze):,}")
    metric2.metric("Unique Sources", df_to_analyze["src_ip"].nunique())
    metric3.metric("Unique Destinations", df_to_analyze["dst_ip"].nunique())
    metric4.metric("Protocols", ", ".join(df_to_analyze["protocol"].unique()[:4]))

    st.dataframe(df_to_analyze.head(10), use_container_width=True, hide_index=True)

    st.markdown("### ⚙️ Pipeline Execution Settings")
    col_opt1, col_opt2 = st.columns(2)
    with col_opt1:
        contamination = st.slider(
            "ML Sensitivity (Contamination Ratio)",
            min_value=0.01,
            max_value=0.20,
            value=0.06,
            step=0.01,
            help="Expected proportion of anomalies in the dataset. Higher values increase sensitivity.",
        )
    with col_opt2:
        window_size = st.slider(
            "Aggregation Time Window (Seconds)",
            min_value=2.0,
            max_value=30.0,
            value=10.0,
            step=1.0,
            help="Sliding window size for flow & packet rate calculations.",
        )

    if st.button("🚀 Run Full Security Analysis Pipeline", type="primary", use_container_width=True):
        progress_bar = st.progress(0, text="Initializing traffic feature extraction...")
        
        # Step 1: Feature Extraction
        progress_bar.progress(30, text="Aggregating window statistics & flow rates...")
        
        # Step 2: Running ML & Rules
        progress_bar.progress(60, text="Training Isolation Forest & executing rule heuristics...")
        results = run_pipeline(
            raw_df=df_to_analyze,
            source_name=file_label,
            contamination=contamination,
            window_sec=window_size,
        )
        progress_bar.progress(100, text="Analysis complete!")
        
        st.session_state["pipeline_results"] = results
        st.session_state["active_source"] = file_label
        st.success("🎉 Pipeline executed successfully! Check the Overview and Anomaly Detection pages.")
else:
    st.info("💡 Upload a CSV file or load the sample synthetic dataset above to begin.")

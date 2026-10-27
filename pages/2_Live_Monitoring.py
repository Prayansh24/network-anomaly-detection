"""
SentinelNet: Live Network Monitoring Page.
Facilitates real-time packet capture via Scapy, provides interface diagnostics,
and handles permission limitations on Windows gracefully.
"""

import sys
import time
from pathlib import Path
import streamlit as st
import pandas as pd

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src.capture import NetworkCaptureManager
from src.utils import get_security_theme_css, run_pipeline

st.set_page_config(page_title="Live Monitoring | SentinelNet", page_icon="📡", layout="wide")
st.markdown(get_security_theme_css(), unsafe_allow_html=True)

st.title("📡 Live Network Traffic Capture")
st.markdown(
    "Sniff network packets in real-time from a local interface using Scapy. "
    "Only protocol metadata, headers, and port numbers are gathered—**no payload contents are inspected or recorded.**"
)

# Persistent Capture Manager in session state
if "capture_manager" not in st.session_state:
    st.session_state["capture_manager"] = NetworkCaptureManager()

capture_mgr: NetworkCaptureManager = st.session_state["capture_manager"]

# Diagnostic Prerequisites Check
is_ready, prereq_msg = NetworkCaptureManager.check_capture_prerequisites()
if is_ready:
    st.success(f"✔️ **Capture Engine:** {prereq_msg}")
else:
    st.warning(f"⚠️ **Capture Environment Notice:** {prereq_msg}")

st.markdown("---")

# Capture Controls
col_ctrl, col_status = st.columns([2, 1])

with col_ctrl:
    st.subheader("⚙️ Capture Configuration")

    # Interface selection
    interfaces = NetworkCaptureManager.get_available_interfaces()
    iface_options = {f"{i['name']} ({i['id'][:25]}...)": i["id"] for i in interfaces}
    selected_label = st.selectbox("Network Interface", options=list(iface_options.keys()))
    selected_iface = iface_options.get(selected_label, "default")

    col_sub1, col_sub2 = st.columns(2)
    with col_sub1:
        duration = st.slider("Duration (Seconds)", min_value=5, max_value=60, value=15, step=5)
    with col_sub2:
        packet_limit = st.number_input("Max Packet Limit", min_value=50, max_value=5000, value=500, step=50)

    bpf_filter = st.text_input("BPF Filter (Optional)", placeholder="e.g. tcp, udp, ip host 192.168.1.1, port 80")

    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        start_disabled = capture_mgr.is_capturing
        if st.button("▶️ Start Live Capture", type="primary", disabled=start_disabled, use_container_width=True):
            success = capture_mgr.start_capture(
                interface=selected_iface,
                duration_sec=duration,
                packet_limit=packet_limit,
                bpf_filter=bpf_filter,
            )
            if success:
                st.rerun()

    with col_btn2:
        stop_disabled = not capture_mgr.is_capturing
        if st.button("⏹️ Stop Capture Safely", disabled=stop_disabled, use_container_width=True):
            capture_mgr.stop_capture()
            st.rerun()

with col_status:
    st.subheader("📊 Live Sniffer Status")
    status_text = "🟢 Active Sniffing..." if capture_mgr.is_capturing else "⚪ Idle"
    st.markdown(f"**State:** {status_text}")
    st.metric("Packets Buffered", capture_mgr.packets_captured_count)

    if capture_mgr.error_message:
        st.error(f"Capture Notice: {capture_mgr.error_message}")
        st.info("💡 **Windows Tip:** Live raw capture requires administrator rights or Npcap. Alternatively, use 'Dataset Analysis' or 'Synthetic Demo Mode' to evaluate the platform without raw sockets.")

# If capture is active, poll periodically
if capture_mgr.is_capturing:
    st.spinner("Capturing live network packets in background thread...")
    time.sleep(1.0)
    st.rerun()

st.markdown("---")

# Display Captured Traffic
st.subheader("📋 Captured Traffic Stream")

captured_df = capture_mgr.get_captured_dataframe()

if captured_df.empty:
    st.info("No packets captured yet. Select an interface and press 'Start Live Capture', or run Synthetic Demo Mode.")
else:
    st.success(f"Captured {len(captured_df)} packets successfully.")

    # Show table
    display_cols = ["datetime", "protocol", "src_ip", "src_port", "dst_ip", "dst_port", "packet_size", "tcp_flags"]
    avail = [c for c in display_cols if c in captured_df.columns]
    st.dataframe(captured_df[avail].tail(50), use_container_width=True, hide_index=True)

    # 1-Click Pipeline Execution on Captured Packets
    st.markdown("### 🔬 Analyze Captured Packets")
    if st.button("⚡ Run Anomaly Detection Pipeline on Captured Data", type="primary"):
        with st.spinner("Extracting features and evaluating models..."):
            pipeline_results = run_pipeline(
                raw_df=captured_df,
                source_name="Live Captured Traffic",
                contamination=0.06,
            )
            st.session_state["pipeline_results"] = pipeline_results
            st.session_state["active_source"] = "Live Captured Traffic"
            st.success("✅ Analysis completed! Navigate to Overview or Anomaly Detection to view findings.")

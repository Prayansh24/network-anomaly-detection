"""
Security Reporting and Export Module for SentinelNet.
Compiles executive summaries, threat intelligence distributions, and generates
exportable reports in CSV, Markdown, and JSON formats.
"""

import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import pandas as pd

from src.utils import get_project_root, setup_logger

logger = setup_logger("reporting")


class SecurityReportGenerator:
    """Generates structured cybersecurity audit reports and summaries."""

    def __init__(self, session_name: str = "Traffic Audit Session"):
        self.session_name = session_name
        self.generated_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate_summary_dictionary(
        self,
        traffic_df: pd.DataFrame,
        features_df: pd.DataFrame,
        ml_anomalies_count: int,
        alerts: List[Dict[str, Any]],
        source_type: str = "Synthetic Demo",
    ) -> Dict[str, Any]:
        """Aggregate traffic and detection statistics into a structured dictionary."""
        total_records = len(traffic_df)
        total_bytes = float(traffic_df["packet_size"].sum()) if "packet_size" in traffic_df.columns else 0.0

        # Protocols
        proto_dist = (
            traffic_df["protocol"].value_counts().to_dict()
            if "protocol" in traffic_df.columns
            else {}
        )

        # Top talkers
        top_src = (
            traffic_df["src_ip"].value_counts().head(5).to_dict()
            if "src_ip" in traffic_df.columns
            else {}
        )
        top_dst = (
            traffic_df["dst_ip"].value_counts().head(5).to_dict()
            if "dst_ip" in traffic_df.columns
            else {}
        )

        # Alert breakdown
        alert_severities = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        alert_types: Dict[str, int] = {}
        for a in alerts:
            sev = a.get("severity", "Medium")
            alert_severities[sev] = alert_severities.get(sev, 0) + 1
            atype = a.get("alert_type", "General")
            alert_types[atype] = alert_types.get(atype, 0) + 1

        threat_level = "LOW"
        if alert_severities["Critical"] > 0 or len(alerts) > 10:
            threat_level = "CRITICAL"
        elif alert_severities["High"] > 0 or len(alerts) > 5:
            threat_level = "HIGH"
        elif alert_severities["Medium"] > 0 or len(alerts) > 0:
            threat_level = "ELEVATED"

        return {
            "session_name": self.session_name,
            "generated_at": self.generated_at,
            "source_type": source_type,
            "overall_threat_level": threat_level,
            "total_records": total_records,
            "total_bytes": total_bytes,
            "ml_anomalies_count": ml_anomalies_count,
            "anomaly_rate_pct": round((ml_anomalies_count / max(1, total_records)) * 100, 2),
            "total_alerts": len(alerts),
            "severity_counts": alert_severities,
            "alert_type_distribution": alert_types,
            "protocol_distribution": proto_dist,
            "top_source_ips": top_src,
            "top_destination_ips": top_dst,
        }

    def generate_markdown_report(
        self, summary: Dict[str, Any], alerts: List[Dict[str, Any]]
    ) -> str:
        """Create a university-grade markdown report."""
        md = f"""# SentinelNet Security Audit Report

**Session:** {summary.get('session_name')}  
**Generated At:** {summary.get('generated_at')}  
**Data Source:** {summary.get('source_type')}  
**Assessed Threat Level:** **{summary.get('overall_threat_level')}**

---

## 1. Executive Summary

- **Total Network Records Analyzed:** {summary.get('total_records', 0):,}
- **Total Bytes Evaluated:** {summary.get('total_bytes', 0):,.0f} B
- **Unsupervised ML Anomalies Flagged:** {summary.get('ml_anomalies_count', 0)} ({summary.get('anomaly_rate_pct', 0.0)}%)
- **Deterministic Security Alerts Generated:** {summary.get('total_alerts', 0)}

### Severity Breakdown
- **Critical:** {summary.get('severity_counts', {}).get('Critical', 0)}
- **High:** {summary.get('severity_counts', {}).get('High', 0)}
- **Medium:** {summary.get('severity_counts', {}).get('Medium', 0)}
- **Low:** {summary.get('severity_counts', {}).get('Low', 0)}

---

## 2. Traffic Characterization

### Protocol Distribution
| Protocol | Packet Count |
|---|---|
"""
        for proto, count in summary.get("protocol_distribution", {}).items():
            md += f"| {proto} | {count:,} |\n"

        md += """
### Top Source IP Addresses
| Source IP | Packets |
|---|---|
"""
        for ip, count in summary.get("top_source_ips", {}).items():
            md += f"| `{ip}` | {count:,} |\n"

        md += """
---

## 3. Security Alerts & Findings

"""
        if not alerts:
            md += "*No security threshold violations or anomalous attacks detected during this observation window.*\n"
        else:
            md += "| Severity | Type | Method | Source IP | Destination IP | Explanation |\n"
            md += "|---|---|---|---|---|---|\n"
            for a in alerts:
                md += (
                    f"| **{a.get('severity')}** | {a.get('alert_type')} | {a.get('detection_method')} | "
                    f"`{a.get('src_ip')}` | `{a.get('dst_ip')}` | {a.get('explanation')} |\n"
                )

        md += """
---

## 4. Recommended Defensive Actions
1. **Firewall Ingress Rules:** Restrict or throttle external scanning IP addresses identified in critical alerts.
2. **SYN Flood Mitigation:** Enable TCP SYN Cookies (`syncookies=1`) and configure per-source connection rate limits.
3. **Endpoint Inspection:** Inspect systems exhibiting repetitive connection attempts for potential malware persistence or unauthorized brute force scripts.
4. **Baseline Updating:** Retrain the anomaly detection pipeline periodically with verified clean network baselines to adapt to evolving application profiles.

*Report generated automatically by SentinelNet Anomaly Detection System.*
"""
        return md

    def save_markdown_report(
        self, markdown_content: str, output_path: Optional[str] = None
    ) -> Path:
        """Save markdown report to disk."""
        if output_path is None:
            dest = get_project_root() / "reports" / "security_report.md"
        else:
            dest = Path(output_path)
            if not dest.is_absolute():
                dest = get_project_root() / dest

        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "w", encoding="utf-8") as f:
            f.write(markdown_content)
        return dest

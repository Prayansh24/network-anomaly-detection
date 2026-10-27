# SentinelNet Data Directory

This directory stores network traffic datasets and the SQLite security database.

## Contents

- `sample_traffic.csv`: A deterministic synthetic network traffic dataset generated for university project demonstration, testing, and offline evaluation. Contains 1,120 simulated packet records representing normal HTTP/HTTPS web browsing and DNS queries interleaved with realistic cybersecurity attack patterns (Port Scans, Traffic Spikes, TCP SYN Floods, and Repeated Connection Attempts).
- `network_security.db`: The local SQLite database automatically initialized at runtime to store historical analysis sessions, security alerts, and analysis metrics.
- `.gitkeep`: Git placeholder preserving folder structure.

## Data Privacy & Ethics
- Never store raw unencrypted packet payloads or credentials.
- All included datasets are strictly simulated synthetic metadata labeled as demo data.

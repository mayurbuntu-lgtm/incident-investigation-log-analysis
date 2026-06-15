# Security Incident Investigation — Brute Force Log Analysis

A Python-based security tool that analyzes real Linux authentication logs to detect brute force login attacks and generates a structured incident investigation report.

---

## What This Project Does

This tool replicates the kind of log analysis a SOC analyst performs during a real incident investigation. It parses Linux `auth.log` files, identifies suspicious login patterns, and flags IPs showing brute force behavior using a time-window detection algorithm.

---

## Detection Logic

An IP is flagged as a brute force threat if it generates **5 or more failed login attempts within a 2-minute window** — the same threshold used in real SOC detection rules.

---

## Features

- Parses raw Linux authentication logs using Python and Regex
- Extracts source hosts and targeted usernames from log entries
- Builds a timeline of suspicious authentication events
- Detects brute force behavior using a sliding time-window algorithm
- Generates a full investigation report saved to `report.txt`
- Outputs top suspicious sources, targeted accounts, and brute force alerts

---

## Tech Stack

| Tool | Purpose |
|------|---------|
| Python | Core scripting |
| Regex (`re`) | Log parsing |
| `datetime` | Time-window detection |
| Linux `auth.log` | Real log data source |

---

## How to Run

```bash
# Clone the repository
git clone https://github.com/mayurbuntu-lgtm/incident-investigation-log-analysis.git
cd incident-investigation-log-analysis

# Run the investigation script
python investigation.py

# View the generated report
cat report.txt
```

---

## Sample Output

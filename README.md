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


```
=== Security Incident Investigation Report ===

Top Suspicious Sources:
  150.183.249.110        → 80 failed attempts
  n219076184117.netvigator.com → 23 failed attempts
  207.243.167.114        → 23 failed attempts
  60.30.224.116          → 20 failed attempts
  195.129.24.210         → 15 failed attempts

Targeted User Accounts:
  root   → 351 attempts
  guest  → 17 attempts
  test   → 4 attempts

Brute Force Alerts (sample):
  [ALERT] 150.183.249.110 made 80 failed attempts within 2 minutes
  [ALERT] n219076184117.netvigator.com made 23 failed attempts within 2 minutes
  [ALERT] 218.188.2.4 made 12 failed attempts within 2 minutes
  [ALERT] 220-135-151-1.hinet-ip.hinet.net made 10 failed attempts within 2 minutes
  [ALERT] h64-187-1-131.gtconnect.net made 13 failed attempts within 2 minutes
  ... and 30+ additional flagged sources
ALERT: 207.243.167.114 made 23 failed attempts within 2 minutes

Conclusion:
Repeated authentication failures within a short time window indicate possible brute force activity.

```

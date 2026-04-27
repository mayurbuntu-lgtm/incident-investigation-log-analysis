# Security Incident Investigation using Logs

## Overview
This project analyzes Linux authentication logs to investigate suspicious login activity and detect possible brute force attacks.

## Tools Used
- Python
- Regular Expressions
- datetime module

## What the Script Does
- Parses authentication failure logs
- Extracts source hosts and targeted usernames
- Builds a timeline of suspicious events
- Detects brute force behavior using a time-window rule
- Saves the investigation report to `report.txt`

## Detection Logic
If one source has 5 or more failed login attempts within 2 minutes, it is flagged as possible brute force activity.

## Output
The script generates:
- Top suspicious sources
- Targeted user accounts
- Timeline of suspicious events
- Brute force alerts
- Final investigation summary

## Key Skills
- Log analysis
- Incident investigation
- Threat detection
- Brute force detection
- Report generation
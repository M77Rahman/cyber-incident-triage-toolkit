# Cyber Incident Triage Toolkit

A Python command-line tool that simulates first-line SOC (Security Operations Centre) triage: takes a batch of raw security alerts and turns them into a ranked, documented response queue.

## Why I built this
First-line SOC analysts spend most of their time doing the same job: reading an alert, deciding how bad it is, deciding what to do about it, and writing that decision down. I built this to practise that decision logic in code — rule-based severity classification, escalation logic, and auto-generated incident documentation — for entry-level cyber operations / SOC support roles.

## What it does
- Loads mock security alerts from CSV (phishing, malware, failed login, suspicious access, password reset, vulnerability)
- Classifies each alert's severity using rule-based logic
- Recommends an action: escalate, monitor, or hand to service desk
- Separates escalated alerts into their own CSV so they're not lost in the noise
- Generates a markdown incident report summarising the batch

## Example
```
Alert: suspicious_access, user=jsmith, source_ip=185.220.101.4
→ Severity: HIGH  |  Action: ESCALATE  |  Reason: known malicious IP range + off-hours login
```

## Tech used
Python, pandas, CSV, markdown reporting

## How to run
```bash
pip install -r requirements.txt
python triage.py
```

Outputs a triaged CSV, an escalated-alerts CSV, and a markdown incident report in the working directory.

## Notes
Alerts are mock data by design — the point is the triage/escalation logic, not a live SIEM feed. Swapping the CSV loader for a real alert source (e.g. a SIEM export) is a straightforward next step.

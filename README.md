# Cyber Incident Triage Toolkit

A Python-based command-line project that simulates first-line cyber security triage.

## Why I Built This
I built this project to show practical cyber security support skills for entry-level cyber operations roles. The toolkit focuses on alert triage, prioritisation, escalation logic, and incident documentation.

## Features
- Loads mock security alerts from CSV
- Classifies alert severity using rule-based logic
- Recommends actions such as escalation, monitoring, or service desk handling
- Generates triaged CSV output
- Produces a markdown incident report
- Separates escalated alerts into their own CSV file

## Alert Types Covered
- phishing
- malware
- failed_login
- suspicious_access
- password_reset
- vulnerability

## Tech Used
- Python
- Pandas
- CSV
- Markdown reporting

## How to Run
```bash
pip install -r requirements.txt
python triage.py

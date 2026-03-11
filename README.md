# Cyber Incident Triage Toolkit

A Python-based command-line project that simulates first-line cyber security triage.

## Features
- Loads mock security alerts from CSV
- Classifies alert severity using rule-based logic
- Recommends actions such as escalation or monitoring
- Generates triaged CSV output
- Produces a markdown incident report

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

## Why I Built This
I built this project to demonstrate practical cyber security support skills relevant to entry-level cyber operations roles, including:
- alert triage
- prioritisation
- documentation
- escalation logic
- incident reporting

## How to Run

```bash
pip install -r requirements.txt
python triage.py

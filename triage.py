import pandas as pd
from pathlib import Path


INPUT_FILE = "alerts.csv"
OUTPUT_DIR = Path("output")
ESCALATED_CSV = OUTPUT_DIR / "escalated_alerts.csv"
OUTPUT_CSV = OUTPUT_DIR / "triaged_alerts.csv"
OUTPUT_MD = OUTPUT_DIR / "incident_report.md"


def normalise_text(value):
    if pd.isna(value):
        return ""
    return str(value).strip().lower()


def classify_severity(row):
    alert_type = normalise_text(row["alert_type"])
    failed_logins = int(row.get("failed_logins", 0))
    attachment = normalise_text(row.get("attachment", "no"))
    external_sender = normalise_text(row.get("external_sender", "no"))
    kev_flag = normalise_text(row.get("kev_flag", "no"))
    cvss = float(row.get("cvss", 0))

    if alert_type == "malware":
        return "High"

    if alert_type == "vulnerability":
        if kev_flag == "yes" or cvss >= 9.0:
            return "Critical"
        if cvss >= 7.0:
            return "High"
        return "Medium"

    if alert_type == "phishing":
        if attachment == "yes" and external_sender == "yes":
            return "High"
        if attachment == "yes" or external_sender == "yes":
            return "Medium"
        return "Low"

    if alert_type == "failed_login":
        if failed_logins >= 7:
            return "High"
        if failed_logins >= 4:
            return "Medium"
        return "Low"

    if alert_type == "suspicious_access":
        if failed_logins >= 3 or cvss >= 6.0:
            return "High"
        return "Medium"

    if alert_type == "password_reset":
        return "Low"

    return "Low"


def decide_action(row):
    severity = row["severity"]
    alert_type = normalise_text(row["alert_type"])

    if severity == "Critical":
        return "Escalate immediately to security lead"

    if severity == "High":
        if alert_type in ["malware", "phishing", "vulnerability", "suspicious_access", "failed_login"]:
            return "Escalate for investigation"

    if alert_type == "password_reset":
        return "Resolve via service desk procedure"

    return "Monitor and document"


def add_notes(row):
    alert_type = normalise_text(row["alert_type"])
    severity = row["severity"]

    if alert_type == "phishing":
        return "Check sender, links, attachment and advise user not to interact"
    if alert_type == "malware":
        return "Isolate affected endpoint and collect basic evidence"
    if alert_type == "failed_login":
        return "Review login pattern and check for brute-force signs"
    if alert_type == "suspicious_access":
        return "Validate login location, device and user activity"
    if alert_type == "password_reset":
        return "Verify user identity before reset"
    if alert_type == "vulnerability":
        return "Confirm exposure, affected asset and patch priority"

    if severity in ["High", "Critical"]:
        return "Investigate and document"
    return "Record and monitor"


def summarise(df):
    total = len(df)
    by_severity = df["severity"].value_counts().to_dict()
    by_type = df["alert_type"].value_counts().to_dict()
    escalated = len(df[df["recommended_action"].str.contains("Escalate", case=False, na=False)])

    return total, by_severity, by_type, escalated


def write_markdown_report(df):
    total, by_severity, by_type, escalated = summarise(df)

    lines = []
    lines.append("# Cyber Incident Triage Report")
    lines.append("")
    lines.append("## Overview")
    lines.append(f"- Total alerts processed: **{total}**")
    lines.append(f"- Alerts escalated: **{escalated}**")
    lines.append("")

    lines.append("## Alerts by Severity")
    for severity, count in by_severity.items():
        lines.append(f"- {severity}: **{count}**")
    lines.append("")

    lines.append("## Alerts by Type")
    for alert_type, count in by_type.items():
        lines.append(f"- {alert_type}: **{count}**")
    lines.append("")

    lines.append("## Escalation Queue")
    escalated_df = df[df["recommended_action"].str.contains("Escalate", case=False, na=False)]

    if escalated_df.empty:
        lines.append("- No alerts required escalation.")
    else:
        for _, row in escalated_df.iterrows():
            lines.append(
                f"- Alert ID **{row['id']}** | Type: **{row['alert_type']}** | "
                f"Severity: **{row['severity']}** | User: **{row['user']}** | "
                f"Action: {row['recommended_action']}"
            )

    lines.append("")
    lines.append("## Analyst Notes")
    lines.append("This report was generated from mock alert data using rule-based triage logic.")
    lines.append("It is intended to demonstrate incident prioritisation, escalation decisions, and structured documentation.")

    OUTPUT_MD.write_text("\n".join(lines), encoding="utf-8")


def main():
    OUTPUT_DIR.mkdir(exist_ok=True)

    df = pd.read_csv(INPUT_FILE)

    df["severity"] = df.apply(classify_severity, axis=1)
    df["recommended_action"] = df.apply(decide_action, axis=1)
    df["triage_notes"] = df.apply(add_notes, axis=1)

    df.to_csv(OUTPUT_CSV, index=False)
    
    escalated_df = df[df["recommended_action"].str.contains("Escalate", case=False, na=False)]
    escalated_df.to_csv(ESCALATED_CSV, index=False)
    
    write_markdown_report(df)

    print("Triage complete.")
    print(f"Saved CSV output to: {OUTPUT_CSV}")
    print(f"Saved Markdown report to: {OUTPUT_MD}")


if __name__ == "__main__":
    main()

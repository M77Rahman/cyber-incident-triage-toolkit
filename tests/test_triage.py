import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from triage import classify_severity, decide_action


def test_malware_is_high():
    row = {
        "alert_type": "malware",
        "failed_logins": 0,
        "attachment": "no",
        "external_sender": "no",
        "kev_flag": "no",
        "cvss": 8.0,
    }
    assert classify_severity(row) == "High"


def test_kev_vulnerability_is_critical():
    row = {
        "alert_type": "vulnerability",
        "failed_logins": 0,
        "attachment": "no",
        "external_sender": "no",
        "kev_flag": "yes",
        "cvss": 9.1,
    }
    assert classify_severity(row) == "Critical"


def test_password_reset_is_low():
    row = {
        "alert_type": "password_reset",
        "failed_logins": 0,
        "attachment": "no",
        "external_sender": "no",
        "kev_flag": "no",
        "cvss": 0,
    }
    assert classify_severity(row) == "Low"


def test_failed_login_8_is_high():
    row = {
        "alert_type": "failed_login",
        "failed_logins": 8,
        "attachment": "no",
        "external_sender": "no",
        "kev_flag": "no",
        "cvss": 0,
    }
    assert classify_severity(row) == "High"


def test_critical_alert_escalates():
    row = {
        "alert_type": "vulnerability",
        "severity": "Critical",
    }
    assert decide_action(row) == "Escalate immediately to security lead"

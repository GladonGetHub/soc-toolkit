"""Tests for the case note: it must be complete, and nothing in it clickable."""

import re
from pathlib import Path

from soc_toolkit.case_note import build_case_note
from soc_toolkit.email_analyser import analyse_email

SAMPLES = Path(__file__).parent.parent / "samples"


def note(sample, intel=None):
    return build_case_note(analyse_email((SAMPLES / sample).read_bytes()), intel)


def test_phishing_note_has_verdict_actions_and_indicators():
    text = note("phishing_paypal_impersonation.eml")
    assert "VERDICT: Likely phishing (risk score 100/100)" in text
    assert "Search all mailboxes for the same email" in text
    assert "185[.]220[.]101[.]55" in text
    assert "0c1d248d30836dba5fbdb7e4e4d7a9fed42cc584db8fa58bd19e8baef8f6e480" in text
    assert "Not run" in text


def test_nothing_in_the_note_is_clickable():
    text = note("phishing_paypal_impersonation.eml")
    body = text.replace(re.search(r"Message-ID:.*", text).group(0), "")  # kept as sent, for searching
    assert "http://" not in body and "https://" not in body
    for live in ("paypal-account-verify.example", "gmail.com", "service@paypal.com", "185.220.101.55"):
        assert live not in body, live


def test_message_id_kept_as_sent_for_searching():
    assert "<20261103171420.4471@mailer-cheap.example>" in note("phishing_paypal_impersonation.eml")


def test_threat_intel_and_genuine_note():
    rows = [{"value": "185.220.101.55", "type": "ip", "role": "Sending IP", "verdict": "Malicious",
             "results": [{"provider": "AbuseIPDB", "score": 100, "summary": "100% abuse confidence"}]}]
    assert "Sending IP 185[.]220[.]101[.]55: Malicious (1 of 1 sources) - AbuseIPDB" in note(
        "phishing_paypal_impersonation.eml", rows)
    genuine = note("genuine_newsletter.eml")
    assert "VERDICT: No red flags found" in genuine and "RED FLAGS\n- None found." in genuine

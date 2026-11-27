"""Tests for Module 3 part 4: what gets looked up, intel findings and the case note."""

import re
from pathlib import Path

from soc_toolkit.log_intel import build_log_case_note, collect_log_iocs, intel_to_findings
from soc_toolkit.logs import parse_log

SAMPLES = Path(__file__).parent.parent / "samples" / "logs"
ATTACKER = "185.220.101.55"


def report(name):
    return parse_log((SAMPLES / name).read_bytes(), year=2026)


def malicious_row(role="Successful login after 58 failures"):
    return {"value": ATTACKER, "type": "ip", "role": role, "verdict": "Malicious",
            "results": [{"provider": "AbuseIPDB", "score": 100, "summary": "100% abuse confidence"},
                        {"provider": "Shodan InternetDB", "score": None, "summary": "no data"}]}


def test_only_real_internet_addresses_are_looked_up():
    iocs, skipped = collect_log_iocs(report("linux_auth_attack.log"))
    assert iocs == [(ATTACKER, "ip", "Successful login after 58 failures")]
    assert any("10.0.0.22" in s and "internal" in s for s in skipped)
    assert any("203.0.113.77" in s and "documentation" in s for s in skipped)


def test_windows_computer_names_are_not_looked_up():
    iocs, _ = collect_log_iocs(report("windows_security_attack.xml"))
    assert [v for v, _, _ in iocs] == [ATTACKER]          # not WIN-7Q2KX1, the lockout caller


def test_known_attacker_becomes_a_finding():
    f = intel_to_findings([malicious_row()])[0]
    assert f.severity == "High" and f.title == f"{ATTACKER} is a known attacker"
    assert "1 of 1 sources" in f.why and "AbuseIPDB" in f.why
    clean = dict(malicious_row(), verdict="Clean")
    assert intel_to_findings([clean]) == []


def test_case_note_defangs_internet_addresses_only():
    r = report("linux_auth_attack.log")
    note = build_log_case_note(r, r.findings, [malicious_row()])
    assert "VERDICT: Likely compromise" in note and "reset the password or disable the account" in note
    assert "185[.]220[.]101[.]55: Malicious" in note
    assert not re.search(r"(?<![\d.])185\.220\.101\.55", note)    # never clickable
    assert "10.0.0.22" in note                                      # internal stays readable


def test_case_note_for_a_normal_day():
    r = report("linux_auth_normal.log")
    note = build_log_case_note(r, r.findings)
    assert "VERDICT: No attack patterns found" in note and "No action needed" in note
    assert "Not run" in note

"""
Tests for part 4: choosing what to look up, and turning answers into flags.
No lookups happen here; the sources' answers are written out by hand.
"""

from pathlib import Path

from soc_toolkit.email_analyser import analyse_email
from soc_toolkit.email_intel import collect_iocs, intel_findings

SAMPLES = Path(__file__).parent.parent / "samples"


def answer(provider, score, summary="x"):
    return {"provider": provider, "score": score, "summary": summary}


def test_phishing_sample_sends_the_real_ip_and_hash_only():
    report = analyse_email((SAMPLES / "phishing_paypal_impersonation.eml").read_bytes())
    iocs, skipped = collect_iocs(report)
    assert ("185.220.101.55", "ip", "Sending IP") in iocs
    assert any(t == "sha256" for _, t, _ in iocs)
    # The .example link domain is a reserved test name, so it's skipped
    assert not any(t == "domain" for _, t, _ in iocs)
    assert any("paypal-account-verify.example" in s for s in skipped)


def test_documentation_ip_is_not_sent_outside():
    report = analyse_email((SAMPLES / "genuine_newsletter.eml").read_bytes())
    iocs, skipped = collect_iocs(report)
    assert not any(t == "ip" for _, t, _ in iocs)
    assert any("198.51.100.25" in s for s in skipped)


def test_malicious_ip_becomes_a_red_flag():
    rows = [{"value": "185.220.101.55", "type": "ip", "role": "Sending IP", "verdict": "Malicious",
             "results": [answer("AbuseIPDB", 100, "100% abuse confidence"), answer("Shodan InternetDB", None)]}]
    flags, good = intel_findings(rows)
    assert flags[0].title == "Sent from a known-bad IP" and flags[0].points == 50
    assert "AbuseIPDB: 100% abuse confidence" in flags[0].why and "1 of 1" in flags[0].why
    assert good == []


def test_suspicious_domain_and_clean_results():
    rows = [{"value": "bad.com", "type": "domain", "role": "Link domain", "verdict": "Suspicious",
             "results": [answer("VirusTotal", 30)]}]
    flags, _ = intel_findings(rows)
    assert flags[0].title == "Link goes to a suspicious website" and flags[0].points == 20

    clean = [{"value": "a" * 64, "type": "sha256", "role": "Attachment: report.pdf", "verdict": "Clean",
              "results": [answer("CIRCL hashlookup", 0, "Known good file: report.pdf")]}]
    flags, good = intel_findings(clean)
    assert flags == []
    assert [g.title for g in good] == ["Attachment is a known genuine file", "Nothing known bad in threat intelligence"]

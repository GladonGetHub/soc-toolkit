"""
Tests for the Phishing Email Analyser (headers and authentication).
Emails are built here as plain text, so no real mail or internet is needed.
"""

from pathlib import Path

import pytest

from soc_toolkit.phishing import MAX_EMAIL_BYTES, analyse_headers, org_domain

SAMPLES = Path(__file__).parent.parent / "samples"


def email(from_="Alice <alice@example.com>", auth="spf=pass; dkim=pass; dmarc=pass", extra=""):
    """Build a small email. Pass auth=None for no Authentication-Results header."""
    lines = []
    if auth is not None:
        lines.append(f"Authentication-Results: mx.example.net; {auth}")
    lines += [
        "Received: from out.example.com (out.example.com [192.168.1.5]) by mx.example.net; Tue, 3 Nov 2026 10:00:00 +0000",
        "Received: from relay.example.com (relay.example.com [203.0.113.9]) by out.example.com; Tue, 3 Nov 2026 09:59:59 +0000",
        f"From: {from_}",
        "To: bob@example.net",
        "Subject: Test",
    ]
    if extra:
        lines.append(extra)
    return ("\n".join(lines) + "\n\nHello\n").encode()


def titles(report):
    return [f.title for f in report.flags]


def test_sample_phishing_email():
    r = analyse_headers((SAMPLES / "phishing_paypal_impersonation.eml").read_bytes())
    assert r.verdict == "Likely phishing" and r.score == 100
    assert "Pretends to be PayPal" in titles(r)
    assert "Replies go to a different domain" in titles(r)
    assert "Fake address in the display name" in titles(r)
    assert r.origin_ip == "185.220.101.55"


def test_sample_genuine_email():
    r = analyse_headers((SAMPLES / "genuine_newsletter.eml").read_bytes())
    assert r.score == 0 and r.verdict == "No red flags found"
    assert [g.title for g in r.good] == ["SPF passed", "DKIM passed", "DMARC passed"]


def test_only_top_auth_header_is_trusted():
    """A fake 'pass' lower down must not hide the real result, and is flagged."""
    raw = email(auth="spf=fail; dkim=none; dmarc=fail",
                extra="Authentication-Results: fake.example; spf=pass; dkim=pass; dmarc=pass")
    r = analyse_headers(raw)
    assert r.auth["dmarc"][0] == "fail"
    assert "Fake authentication header" in titles(r)


def test_brand_check_allows_real_domains():
    assert analyse_headers(email('"PayPal" <service@mail.paypal.co.uk>')).score == 0
    assert analyse_headers(email('"Microsoft account team" <no-reply@microsoftonline.com>')).score == 0


def test_brand_check_catches_lookalikes_and_free_mail():
    assert "Pretends to be Royal Mail" in titles(analyse_headers(email('"Royal Mail" <help@royalmail-redelivery.example>')))
    r = analyse_headers(email('"HMRC Refunds" <hmrc.refund@gmail.com>'))
    assert "Pretends to be HMRC" in titles(r) and "free email account" in r.flags[0].why


def test_no_auth_results_is_a_note_not_a_score():
    r = analyse_headers(email(auth=None))
    assert "No authentication results" in titles(r) and r.score == 0


def test_received_spf_fallback():
    r = analyse_headers(email(auth=None, extra="Received-SPF: Fail (example.com: domain does not designate 203.0.113.9)"))
    assert r.auth["spf"][0] == "fail"


def test_origin_ip_skips_internal_addresses():
    # The earliest hop is 203.0.113.9; the internal 192.168.1.5 is skipped
    assert analyse_headers(email()).origin_ip == "203.0.113.9"


def test_org_domain():
    assert org_domain("mail.paypal.co.uk") == "paypal.co.uk"
    assert org_domain("www.hmrc.gov.uk") == "hmrc.gov.uk"
    assert org_domain("a.b.example.com") == "example.com"


def test_size_limit():
    with pytest.raises(ValueError):
        analyse_headers(b"x" * (MAX_EMAIL_BYTES + 1))

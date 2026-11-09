"""
Tests for the link checks in the Phishing Email Analyser.
Links are never visited: these only read the email's text.
"""

from pathlib import Path

from soc_toolkit.email_analyser import analyse_email
from soc_toolkit.links import analyse_links, lookalike_brand
from soc_toolkit.phishing import parse_email

SAMPLES = Path(__file__).parent.parent / "samples"


def html_email(body):
    raw = ("From: Alice <alice@example.com>\nTo: bob@example.net\nSubject: Test\n"
           "MIME-Version: 1.0\nContent-Type: text/html; charset=utf-8\n\n" + body)
    return parse_email(raw.encode())


def problems(body):
    links, _ = analyse_links(html_email(body))
    return links[0].problems


def test_mismatched_link_text():
    assert "mismatch" in problems('<a href="https://evil.example/login">https://www.paypal.com</a>')


def test_matching_link_text_is_fine():
    assert problems('<a href="https://www.paypal.com/signin">paypal.com</a>') == []
    assert problems('<a href="https://www.paypal.com/signin">Click here</a>') == []


def test_newsletter_click_tracker_is_not_a_mismatch():
    assert "mismatch" not in problems('<a href="https://abc.list-manage.com/track?u=1">www.thornbury-wealth.example</a>')


def test_at_trick_ip_and_shortener():
    assert "at_trick" in problems('<a href="https://www.paypal.com@evil.example/">Sign in</a>')
    assert "ip_host" in problems('<a href="http://203.0.113.50/login">Sign in</a>')
    assert "shortener" in problems('<a href="https://bit.ly/3abcDEF">Track parcel</a>')


def test_form_and_risky_file():
    assert "form" in problems('<form action="https://evil.example/collect"><input name="pw"></form>')
    assert "risky_file" in problems('<a href="https://files.example/invoice.pdf.exe">Invoice</a>')


def test_lookalike_domains():
    assert lookalike_brand("paypal-account-verify.example") == "paypal"
    assert lookalike_brand("secure.paypa1.com") == "paypal"
    assert lookalike_brand("rnicrosoft.com") == "microsoft"
    # Real company domains and innocent words are left alone
    assert lookalike_brand("www.paypal.co.uk") == ""
    assert lookalike_brand("storage.googleapis.com") == ""
    assert lookalike_brand("groupsales.example") == ""
    assert lookalike_brand("pineapple.example") == ""


def test_each_problem_counts_once():
    body = "".join(f'<a href="https://bit.ly/{i}">link</a>' for i in range(5))
    _, flags = analyse_links(html_email(body))
    assert len(flags) == 1 and flags[0].points == 15 and "5 links" in flags[0].why


def test_sample_phishing_link_is_caught():
    r = analyse_email((SAMPLES / "phishing_paypal_impersonation.eml").read_bytes())
    link_titles = [f.title for f in r.flags if f.area == "Links"]
    assert "Link text doesn't match where it goes" in link_titles
    assert "Lookalike domain" in link_titles


def test_sample_genuine_links_are_clean():
    r = analyse_email((SAMPLES / "genuine_newsletter.eml").read_bytes())
    assert r.score == 0 and len(r.links) == 1
    assert any(g.area == "Links" for g in r.good)

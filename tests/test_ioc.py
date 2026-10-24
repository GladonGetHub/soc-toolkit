"""Indicator parsing and verdict logic. Run with:  pytest"""

from soc_toolkit.enrich import Result, enrich, verdict
from soc_toolkit.ioc import defang, detect_type, is_private_ip, parse_iocs, refang
from soc_toolkit.sources import Demo


def test_refang():
    assert refang("194[.]165[.]16[.]11") == "194.165.16.11"
    assert refang("hxxps://bad[.]site/x") == "https://bad.site/x"


def test_defang_round_trip():
    assert refang(defang("https://example.com")) == "https://example.com"


def test_detect_type():
    assert detect_type("8.8.8.8") == "ip"
    assert detect_type("2001:4860:4860::8888") == "ip"
    assert detect_type("example.co.uk") == "domain"
    assert detect_type("https://example.com/a") == "url"
    assert detect_type("d41d8cd98f00b204e9800998ecf8427e") == "md5"
    assert detect_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "sha1"
    assert detect_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "sha256"
    assert detect_type("not an ioc!") == "unknown"


def test_private_ip():
    assert is_private_ip("192.168.10.10")
    assert is_private_ip("10.20.0.10")
    assert not is_private_ip("194.165.16.11")
    assert not is_private_ip("203.0.113.77")  # documentation range, not internal


def test_parse_dedupes_and_splits():
    text = "194[.]165[.]16[.]11, 194.165.16.11\n8.8.8.8;example.com"
    assert parse_iocs(text) == [("194.165.16.11", "ip"), ("8.8.8.8", "ip"), ("example.com", "domain")]


def test_verdict_thresholds():
    r = lambda s: [Result("x", s, "")]
    assert verdict("1.2.3.4", "ip", r(90)) == "Malicious"
    assert verdict("1.2.3.4", "ip", r(20)) == "Suspicious"
    assert verdict("1.2.3.4", "ip", r(0)) == "Clean"
    assert verdict("1.2.3.4", "ip", r(None)) == "Unknown"


def test_highest_score_wins():
    results = [Result("a", 0, ""), Result("b", None, ""), Result("c", 80, "")]
    assert verdict("1.2.3.4", "ip", results) == "Malicious"


def test_demo_enrich():
    assert enrich("194.165.16.11", "ip", [Demo()])[0] == "Malicious"
    assert enrich("8.8.8.8", "ip", [Demo()])[0] == "Clean"
    assert enrich("192.168.10.10", "ip", [Demo()]) == ("Internal", [])


def test_sources_only_get_types_they_support():
    from soc_toolkit.sources import AbuseIPDB
    calls = []
    class Spy(AbuseIPDB):
        def lookup(self, v, t):
            calls.append(v)
            return Result("spy", None, "")
    enrich("abc.com", "domain", [Spy("k")])
    assert calls == []  # AbuseIPDB only checks IPs

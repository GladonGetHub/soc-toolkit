"""
Each source is tested with a fake response in the same format the real
service sends, so these run without API keys or internet.
"""

from soc_toolkit import sources as s


class FakeResponse:
    def __init__(self, status, payload=None):
        self.status_code, self._payload, self.text = status, payload or {}, ""

    def json(self):
        return self._payload


def fake(monkeypatch, status, payload=None, method="get"):
    """Make every requests.get (or .post) return this fake response."""
    monkeypatch.setattr(s.requests, method, lambda *a, **k: FakeResponse(status, payload))


def test_virustotal(monkeypatch):
    fake(monkeypatch, 200, {"data": {"attributes": {"last_analysis_stats":
         {"malicious": 15, "suspicious": 0, "harmless": 60, "undetected": 15}}}})
    res = s.VirusTotal("k").lookup("194.165.16.11", "ip")
    assert res.score == 50 and "15 of 90" in res.summary
    fake(monkeypatch, 404)
    assert s.VirusTotal("k").lookup("x.com", "domain").score is None


def test_abuseipdb(monkeypatch):
    fake(monkeypatch, 200, {"data": {"abuseConfidenceScore": 100, "totalReports": 42}})
    res = s.AbuseIPDB("k").lookup("194.165.16.11", "ip")
    assert res.score == 100 and res.details["Reports (90 days)"] == 42


def test_bad_key_message(monkeypatch):
    fake(monkeypatch, 401)
    assert "key rejected" in s.AbuseIPDB("k").lookup("1.2.3.4", "ip").summary


def test_otx_pulse_counts(monkeypatch):
    fake(monkeypatch, 200, {"pulse_info": {"count": 12, "pulses": [{"name": "APT report", "malware_families": [{"display_name": "Emotet"}]}]}})
    res = s.OTX("k").lookup("194.165.16.11", "ip")
    assert res.score == 60 and res.details["Malware families"] == ["Emotet"]
    fake(monkeypatch, 200, {"pulse_info": {"count": 1, "pulses": []}})
    assert s.OTX("k").lookup("x.com", "domain").score == 10


def test_otx_whitelisted(monkeypatch):
    fake(monkeypatch, 200, {"pulse_info": {"count": 50, "pulses": []},
                            "validation": [{"source": "whitelist", "message": "Whitelisted IP"}]})
    assert s.OTX("k").lookup("8.8.8.8", "ip").score == 0


def test_malwarebazaar(monkeypatch):
    fake(monkeypatch, 200, {"query_status": "ok", "data": [{"signature": "AgentTesla", "file_type": "exe"}]}, "post")
    res = s.MalwareBazaar("k").lookup("a" * 64, "sha256")
    assert res.score == 100 and "AgentTesla" in res.summary
    fake(monkeypatch, 200, {"query_status": "hash_not_found"}, "post")
    assert s.MalwareBazaar("k").lookup("a" * 64, "sha256").score is None


def test_urlhaus_url_and_host(monkeypatch):
    fake(monkeypatch, 200, {"query_status": "ok", "url_status": "online", "threat": "malware_download"}, "post")
    assert s.URLhaus("k").lookup("http://bad.site/x.exe", "url").score == 100
    fake(monkeypatch, 200, {"query_status": "ok", "url_count": "3", "urls": [{"url_status": "offline"}]}, "post")
    assert s.URLhaus("k").lookup("bad.site", "domain").score == 70
    fake(monkeypatch, 200, {"query_status": "no_results"}, "post")
    assert s.URLhaus("k").lookup("good.site", "domain").score is None


def test_threatfox_ip_filter(monkeypatch):
    fake(monkeypatch, 200, {"query_status": "ok", "data": [
        {"ioc": "1.2.3.45:443", "confidence_level": 100, "malware_printable": "Wrong"},
        {"ioc": "1.2.3.4:8080", "confidence_level": 75, "malware_printable": "Cobalt Strike", "threat_type_desc": "C2"}]}, "post")
    res = s.ThreatFox("k").lookup("1.2.3.4", "ip")
    assert res.score == 75 and "Cobalt Strike" in res.summary  # 1.2.3.45 must not count


def test_greynoise(monkeypatch):
    fake(monkeypatch, 200, {"noise": False, "riot": True, "name": "Google"})
    assert s.GreyNoise().lookup("8.8.8.8", "ip").score == 0
    fake(monkeypatch, 200, {"noise": True, "riot": False, "classification": "malicious"})
    assert s.GreyNoise().lookup("1.2.3.4", "ip").score == 70
    fake(monkeypatch, 404)
    assert s.GreyNoise().lookup("1.2.3.4", "ip").score is None


def test_shodan_internetdb(monkeypatch):
    fake(monkeypatch, 200, {"ports": [22, 443], "vulns": ["CVE-2023-1"], "tags": []})
    res = s.ShodanInternetDB().lookup("1.2.3.4", "ip")
    assert res.score is None and "22, 443" in res.summary  # open ports alone don't change the verdict
    fake(monkeypatch, 200, {"ports": [4444], "tags": ["c2"]})
    assert s.ShodanInternetDB().lookup("1.2.3.4", "ip").score == 70


def test_circl_known_good(monkeypatch):
    fake(monkeypatch, 200, {"FileName": "kernel32.dll", "hashlookup:trust": 90})
    res = s.CIRCLHashlookup().lookup("a" * 32, "md5")
    assert res.score == 0 and "kernel32.dll" in res.summary
    fake(monkeypatch, 404)
    assert s.CIRCLHashlookup().lookup("a" * 32, "md5").score is None

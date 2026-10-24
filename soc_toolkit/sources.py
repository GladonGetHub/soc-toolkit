"""
Threat-intelligence sources.

Each source is a small class with the same three things:
  name      - shown in the app
  supports  - which IOC types it can check
  lookup()  - asks the service and returns a Result with a 0-100 score

Because they all look the same, adding a new source means writing one new
class here and adding it to config.py. Nothing else changes.

Scores:  50+ = Malicious, 15-49 = Suspicious, under 15 = Clean,
         None = "no data" or "no opinion" (doesn't affect the verdict).
"""

import base64
from urllib.parse import quote

import requests

from .enrich import Result

TIMEOUT = 15  # seconds before we give up on a slow service
HASHES = {"md5", "sha1", "sha256"}
ALL_TYPES = {"ip", "domain", "url"} | HASHES


def _get(url, **kwargs):
    """GET with a timeout. Returns (response, error_text)."""
    try:
        return requests.get(url, timeout=TIMEOUT, **kwargs), ""
    except requests.RequestException as e:
        return None, str(e)


def _post(url, **kwargs):
    """POST with a timeout. Returns (response, error_text)."""
    try:
        return requests.post(url, timeout=TIMEOUT, **kwargs), ""
    except requests.RequestException as e:
        return None, str(e)


def _failed(name, r, err, link=""):
    """Standard Result for a lookup that didn't work."""
    if r is None:
        return Result(name, None, "Lookup failed (no connection)", link, error=err)
    if r.status_code == 401 or r.status_code == 403:
        return Result(name, None, "API key rejected, check it in .env", link, error=str(r.status_code))
    if r.status_code == 429:
        return Result(name, None, "Rate limit reached, try again later", link, error="429")
    return Result(name, None, f"Error {r.status_code}", link, error=r.text[:200])


# ---------------------------------------------------------------- VirusTotal
class VirusTotal:
    """Runs the indicator past ~90 security engines. Free key: 4 lookups a minute, 500 a day."""

    name = "VirusTotal"
    supports = ALL_TYPES
    base = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        self.headers = {"x-apikey": api_key}

    def _endpoint(self, value, ioc_type):
        if ioc_type == "ip":
            return f"{self.base}/ip_addresses/{value}", f"https://www.virustotal.com/gui/ip-address/{value}"
        if ioc_type == "domain":
            return f"{self.base}/domains/{value}", f"https://www.virustotal.com/gui/domain/{value}"
        if ioc_type == "url":
            # VirusTotal identifies URLs by their base64 form without "=" padding
            url_id = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
            return f"{self.base}/urls/{url_id}", f"https://www.virustotal.com/gui/url/{url_id}"
        return f"{self.base}/files/{value}", f"https://www.virustotal.com/gui/file/{value}"

    def lookup(self, value, ioc_type):
        api_url, link = self._endpoint(value, ioc_type)
        r, err = _get(api_url, headers=self.headers)
        if r is not None and r.status_code == 404:
            return Result(self.name, None, "Not seen by VirusTotal", link)
        if r is None or r.status_code != 200:
            return _failed(self.name, r, err, link)

        attrs = r.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        # Suspicious votes count as half. Scaled up because even a handful of
        # engines agreeing is a strong signal: 15 of 90 engines -> score 50.
        score = min(100, round((malicious + 0.5 * suspicious) / total * 100 * 3))
        details = {
            "Malicious": malicious, "Suspicious": suspicious,
            "Harmless": stats.get("harmless", 0), "Undetected": stats.get("undetected", 0),
            "Country": attrs.get("country", ""), "Owner": attrs.get("as_owner", ""),
            "Malware family": (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label", ""),
        }
        return Result(self.name, score, f"{malicious} of {total} engines flag it as malicious", link,
                      {k: v for k, v in details.items() if v != ""})


# ----------------------------------------------------------------- AbuseIPDB
class AbuseIPDB:
    """Community reports of abusive IPs (brute force, scanning, spam). Free key: 1,000 checks a day."""

    name = "AbuseIPDB"
    supports = {"ip"}

    def __init__(self, api_key: str):
        self.headers = {"Key": api_key, "Accept": "application/json"}

    def lookup(self, value, ioc_type):
        link = f"https://www.abuseipdb.com/check/{value}"
        r, err = _get("https://api.abuseipdb.com/api/v2/check", headers=self.headers,
                      params={"ipAddress": value, "maxAgeInDays": 90})
        if r is None or r.status_code != 200:
            return _failed(self.name, r, err, link)
        d = r.json().get("data", {})
        score = d.get("abuseConfidenceScore", 0)
        reports = d.get("totalReports", 0)
        details = {
            "Abuse confidence": f"{score}%", "Reports (90 days)": reports,
            "Country": d.get("countryCode", ""), "ISP": d.get("isp", ""),
            "Usage": d.get("usageType", ""), "Tor exit node": d.get("isTor", False),
        }
        return Result(self.name, score, f"{score}% abuse confidence from {reports} reports", link, details)


# ------------------------------------------------------------ AlienVault OTX
class OTX:
    """AlienVault Open Threat Exchange: community 'pulses' (threat reports) that mention the IOC."""

    name = "AlienVault OTX"
    supports = ALL_TYPES
    base = "https://otx.alienvault.com/api/v1/indicators"

    def __init__(self, api_key: str):
        self.headers = {"X-OTX-API-KEY": api_key}

    def lookup(self, value, ioc_type):
        if ioc_type == "ip":
            section = "IPv6" if ":" in value else "IPv4"
        elif ioc_type in HASHES:
            section = "file"
        else:
            section = ioc_type  # "domain" or "url"
        # URLs keep their slashes (that's how the OTX SDK sends them); everything else is encoded fully
        safe = quote(value, safe=":/?=&" if ioc_type == "url" else "")
        link = f"https://otx.alienvault.com/indicator/{'ip' if ioc_type == 'ip' else section}/{safe}"
        r, err = _get(f"{self.base}/{section}/{safe}/general", headers=self.headers)
        if r is not None and r.status_code == 404:
            return Result(self.name, None, "Not in OTX", link)
        if r is None or r.status_code != 200:
            return _failed(self.name, r, err, link)

        data = r.json()
        pulse_info = data.get("pulse_info", {}) or {}
        count = pulse_info.get("count", 0)
        pulses = pulse_info.get("pulses", []) or []
        # OTX marks well-known safe indicators (e.g. Google DNS) as whitelisted
        whitelisted = any("whitelist" in str(v.get("source", "")).lower() or "whitelist" in str(v.get("message", "")).lower()
                          for v in (data.get("validation") or []))
        if whitelisted:
            score, summary = 0, "Whitelisted as a known safe indicator"
        else:
            # Popular indicators appear in many reports, so we only call it
            # malicious when lots of separate reports mention it.
            score = 0 if count == 0 else 10 if count < 3 else 30 if count < 10 else 60
            summary = f"Mentioned in {count} threat report(s)" if count else "No threat reports mention it"
        families = sorted({f.get("display_name", "") for p in pulses for f in (p.get("malware_families") or []) if isinstance(f, dict)} - {""})
        details = {"Pulses": count, "Latest reports": [p.get("name", "") for p in pulses[:5]]}
        if families:
            details["Malware families"] = families[:5]
        return Result(self.name, score, summary, link, details)


# ------------------------------------------------------- abuse.ch (one key)
class _AbuseCh:
    """Shared setup for abuse.ch services. One free Auth-Key works for all three."""

    def __init__(self, api_key: str):
        self.headers = {"Auth-Key": api_key}


class MalwareBazaar(_AbuseCh):
    """Database of known malware samples."""

    name = "MalwareBazaar"
    supports = HASHES

    def lookup(self, value, ioc_type):
        link = f"https://bazaar.abuse.ch/browse.php?search={ioc_type}%3A{value}"
        r, err = _post("https://mb-api.abuse.ch/api/v1/", headers=self.headers,
                       data={"query": "get_info", "hash": value})
        if r is None or r.status_code != 200:
            return _failed(self.name, r, err, link)
        body = r.json()
        if body.get("query_status") != "ok" or not body.get("data"):
            return Result(self.name, None, "Not a known malware sample", link)
        s = body["data"][0]
        family = s.get("signature") or "unknown family"
        details = {"Malware family": family, "File type": s.get("file_type", ""),
                   "File name": s.get("file_name", ""), "First seen": s.get("first_seen", ""),
                   "Tags": s.get("tags") or []}
        return Result(self.name, 100, f"Known malware sample: {family}", link, details)


class URLhaus(_AbuseCh):
    """Database of URLs used to spread malware."""

    name = "URLhaus"
    supports = {"url", "domain", "ip"}
    base = "https://urlhaus-api.abuse.ch/v1"

    def lookup(self, value, ioc_type):
        if ioc_type == "url":
            r, err = _post(f"{self.base}/url/", headers=self.headers, data={"url": value})
        else:
            r, err = _post(f"{self.base}/host/", headers=self.headers, data={"host": value})
        link = f"https://urlhaus.abuse.ch/browse.php?search={quote(value, safe='')}"
        if r is None or r.status_code != 200:
            return _failed(self.name, r, err, link)
        body = r.json()
        if body.get("query_status") != "ok":
            return Result(self.name, None, "Not listed in URLhaus", link)

        if ioc_type == "url":
            status = body.get("url_status", "unknown")
            score = 100 if status == "online" else 80
            details = {"Status": status, "Threat": body.get("threat", ""), "Tags": body.get("tags") or [],
                       "Date added": body.get("date_added", "")}
            return Result(self.name, score, f"Known malware URL ({status})", link, details)

        count = int(body.get("url_count") or 0)
        online = sum(1 for u in (body.get("urls") or []) if u.get("url_status") == "online")
        score = 0 if count == 0 else 90 if online else 70
        details = {"Malware URLs on this host": count, "Still online": online,
                   "Blacklists": body.get("blacklists", {})}
        summary = f"Hosted {count} malware URL(s), {online} still online" if count else "No malware URLs recorded"
        return Result(self.name, score, summary, link, details)


class ThreatFox(_AbuseCh):
    """Database of attacker infrastructure: C2 servers, payload hosts, malware hashes."""

    name = "ThreatFox"
    supports = ALL_TYPES - {"sha1"}  # ThreatFox searches MD5 and SHA256 only

    def lookup(self, value, ioc_type):
        if ioc_type in HASHES:
            payload = {"query": "search_hash", "hash": value}
        else:
            # IPs are usually stored as ip:port, so allow a partial match for IPs
            payload = {"query": "search_ioc", "search_term": value, "exact_match": ioc_type != "ip"}
        link = f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{quote(value, safe='')}"
        r, err = _post("https://threatfox-api.abuse.ch/api/v1/", headers=self.headers, json=payload)
        if r is None or r.status_code != 200:
            return _failed(self.name, r, err, link)
        body = r.json()
        data = body.get("data")
        if body.get("query_status") != "ok" or not isinstance(data, list) or not data:
            return Result(self.name, None, "Not listed in ThreatFox", link)
        if ioc_type == "ip":
            # Keep only real matches, e.g. 1.2.3.4 or 1.2.3.4:443, not 1.2.3.45
            data = [d for d in data if str(d.get("ioc", "")).split(":")[0] == value] or data
        top = max(data, key=lambda d: d.get("confidence_level") or 0)
        malware = top.get("malware_printable") or "unknown malware"
        threat = top.get("threat_type_desc") or top.get("threat_type") or ""
        details = {"Malware": malware, "Threat type": threat, "Confidence": top.get("confidence_level"),
                   "First seen": top.get("first_seen", ""), "Matches": len(data)}
        return Result(self.name, top.get("confidence_level") or 75, f"{malware}: {threat}".strip(": "), link, details)


# ------------------------------------------------------------------ GreyNoise
class GreyNoise:
    """
    Tells you whether an IP is just background internet noise (mass scanners)
    or a known business service. Works without a key at about 10 lookups a day.
    """

    name = "GreyNoise"
    supports = {"ip"}

    def __init__(self, api_key: str = ""):
        self.headers = {"key": api_key} if api_key else {}

    def lookup(self, value, ioc_type):
        link = f"https://viz.greynoise.io/ip/{value}"
        r, err = _get(f"https://api.greynoise.io/v3/community/{value}", headers=self.headers)
        if r is not None and r.status_code == 404:
            return Result(self.name, None, "Not seen scanning the internet", link)
        if r is None or r.status_code != 200:
            return _failed(self.name, r, err, link)
        d = r.json()
        classification = d.get("classification", "unknown")
        details = {"Classification": classification, "Scanner (noise)": d.get("noise", False),
                   "Known business service": d.get("riot", False), "Name": d.get("name", ""),
                   "Last seen": d.get("last_seen", "")}
        if d.get("riot"):
            return Result(self.name, 0, f"Known business service: {d.get('name', '')}", link, details)
        if classification == "malicious":
            return Result(self.name, 70, "Seen attacking the internet (malicious)", link, details)
        if classification == "benign":
            return Result(self.name, 0, f"Benign scanner: {d.get('name', '')}", link, details)
        # Scanning, but not classified either way: background noise, not targeted
        return Result(self.name, 15, "Mass internet scanner (background noise)", link, details)


# ----------------------------------------------------------- Shodan InternetDB
class ShodanInternetDB:
    """Open ports, known vulnerabilities and tags for an IP. No key needed (non-commercial use)."""

    name = "Shodan InternetDB"
    supports = {"ip"}
    bad_tags = {"c2": 70, "malware": 70, "compromised": 70, "tor": 30, "scanner": 20}

    def lookup(self, value, ioc_type):
        link = f"https://www.shodan.io/host/{value}"
        r, err = _get(f"https://internetdb.shodan.io/{value}")
        if r is not None and r.status_code == 404:
            return Result(self.name, None, "No open ports recorded", link)
        if r is None or r.status_code != 200:
            return _failed(self.name, r, err, link)
        d = r.json()
        ports, vulns, tags = d.get("ports") or [], d.get("vulns") or [], d.get("tags") or []
        # Open ports and CVEs describe exposure, not guilt, so they don't change
        # the verdict on their own. Only tags such as "c2" or "malware" do.
        flagged = [self.bad_tags[t] for t in tags if t in self.bad_tags]
        score = max(flagged) if flagged else None
        summary = f"Open ports: {', '.join(map(str, ports[:8])) or 'none'}"
        if vulns:
            summary += f"; {len(vulns)} known CVE(s)"
        if tags:
            summary += f"; tags: {', '.join(tags)}"
        details = {"Ports": ports, "CVEs": vulns[:10], "Tags": tags, "Hostnames": (d.get("hostnames") or [])[:5]}
        return Result(self.name, score, summary, link, details)


# ------------------------------------------------------------ CIRCL hashlookup
class CIRCLHashlookup:
    """
    The opposite check: is this a known GOOD file (e.g. a genuine Windows DLL)?
    Helps rule out false positives. No key needed.
    """

    name = "CIRCL hashlookup"
    supports = HASHES

    def lookup(self, value, ioc_type):
        link = f"https://hashlookup.circl.lu/lookup/{ioc_type}/{value}"
        r, err = _get(link)
        if r is not None and r.status_code == 404:
            return Result(self.name, None, "Not in the known-good file sets", link)
        if r is None or r.status_code != 200:
            return _failed(self.name, r, err, link)
        d = r.json()
        trust = d.get("hashlookup:trust", 50)
        details = {"File name": d.get("FileName", ""), "Size": d.get("FileSize", ""),
                   "Product": d.get("ProductCode", {}).get("ProductName", "") if isinstance(d.get("ProductCode"), dict) else "",
                   "Trust (0-100)": trust}
        # Above 50 means several known-good sources list it. We still return a
        # score of 0, not "proof of safety": a malicious score elsewhere wins.
        if trust > 50:
            return Result(self.name, 0, f"Known good file: {d.get('FileName', 'unnamed')}", link, details)
        return Result(self.name, None, "Listed, but with low trust", link, details)


# ---------------------------------------------------------------------- Demo
# Sample answers for practice. Uses the IOCs from the TWP Splunk project.
DEMO_DATA = {
    "194.165.16.11": (95, "APT command-and-control server"),
    "45.129.56.200": (90, "Financial malware C2"),
    "185.220.101.55": (80, "TOR exit node"),
    "91.108.4.183": (75, "Banking trojan infrastructure"),
    "203.0.113.77": (60, "Brute-force source"),
    "8.8.8.8": (0, "Google public DNS"),
    "1.1.1.1": (0, "Cloudflare public DNS"),
}


class Demo:
    name = "Demo"
    supports = ALL_TYPES

    def lookup(self, value, ioc_type):
        if value in DEMO_DATA:
            score, label = DEMO_DATA[value]
            return Result(self.name, score, f"Sample data: {label}")
        return Result(self.name, None, "Sample data: no record")

"""
Phishing Email Analyser, part 4: checking the email with threat intelligence.

Parts 1 to 3 judge an email by how it's built. This part asks the outside
world: has anyone seen this sender's IP, these websites or these files
before? It gathers the indicators from the email and hands them to Module 1's
sources, then turns what they say into red flags (or good signs).
"""

import ipaddress

from .ioc import detect_type, is_private_ip
from .phishing import EmailReport, Flag

# Test and reserved names that can never be real websites, so there's no
# point asking about them (and the samples use them on purpose).
RESERVED_TLDS = {"example", "test", "invalid", "localhost", "local", "internal", "lan", "home"}
RESERVED_DOMAINS = {"example.com", "example.net", "example.org"}
# Documentation IP ranges, used in examples and training material only
TEST_NETWORKS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]

ROLES = {"ip": "Sending IP", "domain": "Link domain", "url": "Link", "sha256": "Attachment"}
INTEL_WEIGHTS = {"Malicious": 50, "Suspicious": 20}


def _is_test_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip in net for net in TEST_NETWORKS if net.version == ip.version)


def _is_reserved_domain(host: str) -> bool:
    host = host.lower().rstrip(".")
    return host.rsplit(".", 1)[-1] in RESERVED_TLDS or any(
        host == d or host.endswith("." + d) for d in RESERVED_DOMAINS)


def collect_iocs(report: EmailReport) -> tuple[list[tuple[str, str, str]], list[str]]:
    """
    Return (indicators to check, things skipped and why).
    Each indicator is (value, type, role), e.g. ("185.220.101.55", "ip", "Sending IP").
    """
    iocs, skipped, seen = [], [], set()

    def add(value, ioc_type, role):
        if value and value.lower() not in seen:
            seen.add(value.lower())
            iocs.append((value, ioc_type, role))

    ip = report.origin_ip
    if ip:
        if is_private_ip(ip) or _is_test_ip(ip):
            skipped.append(f"{ip}: an internal or documentation address, so it's not sent outside")
        else:
            add(ip, "ip", ROLES["ip"])

    for link in report.links:
        host = link.host
        if not host:
            continue
        kind = detect_type(host)
        if kind == "ip":
            if is_private_ip(host) or _is_test_ip(host):
                skipped.append(f"{host}: an internal or documentation address")
            else:
                add(host, "ip", "Link IP")
        elif kind == "domain":
            if _is_reserved_domain(host):
                skipped.append(f"{host}: a reserved test name that can't exist on the internet")
            else:
                add(host, "domain", ROLES["domain"])

    for att in report.attachments:
        if att.size:
            add(att.sha256, "sha256", f"{ROLES['sha256']}: {att.name}")
    return iocs, skipped


def intel_findings(rows: list[dict]) -> tuple[list[Flag], list[Flag]]:
    """
    Turn lookup results into red flags and good signs.
    rows: [{"value", "type", "role", "verdict", "results"}] where results are
    the sources' answers as dicts (provider, score, summary, ...).
    """
    flags, good = [], []
    for row in rows:
        scored = [x for x in row["results"] if x["score"] is not None]
        if not scored:
            continue
        best = max(scored, key=lambda x: x["score"])
        bad = sum(x["score"] >= 50 for x in scored)
        shown = row["value"] if row["type"] == "sha256" else row["value"].replace(".", "[.]")
        what = row["role"].split(":")[0]
        if row["verdict"] in INTEL_WEIGHTS:
            title = {"Sending IP": "Sent from a known-bad IP", "Link IP": "Link points to a known-bad IP",
                     "Link domain": "Link goes to a known-bad website",
                     "Attachment": "Attachment is known malware"}.get(what, "Known bad indicator")
            if row["verdict"] == "Suspicious":
                title = title.replace("known-bad", "suspicious").replace("known malware", "suspicious")
            flags.append(Flag(
                INTEL_WEIGHTS[row["verdict"]], title,
                f"{row['role']} {shown} is rated {row['verdict']} by threat intelligence, flagged by "
                f"{bad} of {len(scored)} sources. Top finding: {best['provider']}: {best['summary']}.",
                area="Threat intel"))
        elif row["type"] == "sha256" and any("Known good" in x["summary"] for x in scored):
            good.append(Flag(0, "Attachment is a known genuine file",
                             f"{row['role']} matches a known genuine file in CIRCL's database.",
                             area="Threat intel"))
    if rows and not flags:
        good.append(Flag(0, "Nothing known bad in threat intelligence",
                         f"{len(rows)} indicator{'s' if len(rows) > 1 else ''} checked. No source had them on record "
                         "as malicious. New phishing sites often aren't listed yet, so this doesn't prove it's safe.",
                         area="Threat intel"))
    return flags, good

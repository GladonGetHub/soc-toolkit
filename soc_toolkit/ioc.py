"""
Indicator of Compromise (IOC) helpers.

An analyst pastes in a messy list of IPs, domains, URLs and hashes, often
"defanged" so nobody clicks them by accident (e.g. 194[.]165[.]16[.]11 or
hxxps://bad[.]site). This module cleans that list up and works out what
type each indicator is, so the enrichment code knows which API to ask.
"""

import ipaddress
import re

# Hash type is decided by length: MD5 = 32 hex chars, SHA1 = 40, SHA256 = 64
HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}

HEX_RE = re.compile(r"^[a-fA-F0-9]+$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)


def refang(value: str) -> str:
    """Turn a defanged indicator back into its real form."""
    v = value.strip().strip("'\"<>")
    replacements = {
        "[.]": ".", "(.)": ".", "{.}": ".", "[dot]": ".",
        "[:]": ":", "hxxps": "https", "hxxp": "http",
    }
    for old, new in replacements.items():
        v = v.replace(old, new).replace(old.upper(), new)
    return v


def defang(value: str) -> str:
    """Make an indicator safe to paste into a ticket or chat."""
    return value.replace("http", "hxxp").replace(".", "[.]")


def detect_type(value: str) -> str:
    """Return one of: ip, url, domain, md5, sha1, sha256, unknown."""
    v = value.strip()
    if not v:
        return "unknown"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if v.lower().startswith(("http://", "https://")):
        return "url"
    if HEX_RE.match(v) and len(v) in HASH_TYPES:
        return HASH_TYPES[len(v)]
    if DOMAIN_RE.match(v):
        return "domain"
    return "unknown"


# Address ranges that belong inside an organisation's network.
# (Python's own is_private also includes some documentation ranges, such as
# 203.0.113.0/24, which attackers' examples often use, so we list them ourselves.)
INTERNAL_RANGES = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC 1918 private
    "127.0.0.0/8", "169.254.0.0/16",                    # loopback, link-local
    "::1/128", "fc00::/7", "fe80::/10",                 # IPv6 equivalents
)]


def is_private_ip(value: str) -> bool:
    """True for internal addresses (10.x, 172.16-31.x, 192.168.x, loopback)."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip in net for net in INTERNAL_RANGES if net.version == ip.version)


def parse_iocs(text: str) -> list[tuple[str, str]]:
    """
    Split pasted text into unique (indicator, type) pairs.
    Accepts one per line, or separated by commas, spaces or semicolons.
    """
    seen = set()
    results = []
    for raw in re.split(r"[\s,;]+", text or ""):
        if not raw:
            continue
        value = refang(raw)
        ioc_type = detect_type(value)
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        results.append((value, ioc_type))
    return results

"""
Phishing Email Analyser, part 1: headers and authentication.

An email's headers are like the stamps and postmarks on an envelope. The
"From" line is just what the sender wrote on the front, and anyone can
write anything there. The postmarks (Received headers) and the receiving
server's checks (SPF, DKIM, DMARC) show where it really came from.

This file reads those headers and lists the red flags an analyst would look
for by hand. It never opens attachments or runs anything in the email.
"""

import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr

from .ioc import is_private_ip

MAX_EMAIL_BYTES = 5 * 1024 * 1024  # 5 MB is plenty for one email's source

# Second-level parts that mean the real domain is three labels long,
# e.g. hmrc.gov.uk, not gov.uk
MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "nhs.uk", "ltd.uk", "plc.uk", "me.uk",
    "com.au", "net.au", "org.au", "co.nz", "co.za", "co.jp", "co.in",
    "com.br", "com.ng", "com.gh", "co.ke", "com.cn", "com.sg",
}

# Free mailbox providers. Fine for people, odd for a bank or a delivery firm.
FREE_PROVIDERS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "hotmail.co.uk",
    "live.com", "live.co.uk", "yahoo.com", "yahoo.co.uk", "aol.com", "icloud.com",
    "me.com", "proton.me", "protonmail.com", "gmx.com", "mail.com", "yandex.com",
}

# Brands that phishing emails often pretend to be, and the names their real
# domains use. "PayPal" in the display name but a domain that isn't exactly
# paypal.* is a classic sign of impersonation, and so is a lookalike such as
# paypal-secure-login.com.
BRANDS = {
    "paypal": ["paypal"],
    "microsoft": ["microsoft", "microsoftonline", "office", "office365", "outlook", "live", "hotmail"],
    "office 365": ["microsoft", "microsoftonline", "office", "office365"],
    "outlook": ["microsoft", "outlook", "live", "hotmail"],
    "apple": ["apple", "icloud"], "icloud": ["apple", "icloud"],
    "amazon": ["amazon"], "netflix": ["netflix"], "google": ["google", "gmail", "googlemail"],
    "hmrc": ["hmrc"], "dhl": ["dhl"], "royal mail": ["royalmail"], "dpd": ["dpd"],
    "evri": ["evri"], "fedex": ["fedex"], "ups": ["ups"],
    "barclays": ["barclays"], "hsbc": ["hsbc"], "lloyds": ["lloyds", "lloydsbank"],
    "natwest": ["natwest"], "santander": ["santander"], "halifax": ["halifax"],
    "nationwide": ["nationwide"], "monzo": ["monzo"], "docusign": ["docusign"],
    "dropbox": ["dropbox"], "linkedin": ["linkedin"], "facebook": ["facebook", "facebookmail", "meta"],
    "instagram": ["instagram", "facebookmail", "meta"], "whatsapp": ["whatsapp", "meta"],
    "coinbase": ["coinbase"], "binance": ["binance"],
}

# Points per red flag. Same scale as Module 1: 50+ likely phishing, 15+ suspicious.
WEIGHTS = {
    "dmarc_fail": 40, "spf_fail": 30, "spf_softfail": 15, "spf_missing": 10,
    "dkim_fail": 25, "dkim_missing": 10, "brand_impersonation": 35,
    "address_in_name": 30, "reply_to_mismatch": 25, "return_path_mismatch": 10,
    "forged_auth": 20,
}


@dataclass
class Flag:
    points: int          # 0 means "worth knowing" rather than suspicious
    title: str
    why: str             # plain-English explanation for the analyst


@dataclass
class Hop:
    from_host: str
    ip: str
    by_host: str
    time: str


@dataclass
class HeaderReport:
    subject: str = ""
    date: str = ""
    from_name: str = ""
    from_address: str = ""
    from_domain: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: str = ""
    message_id: str = ""
    auth: dict = field(default_factory=dict)   # {"spf": ("pass", "detail"), ...}
    hops: list = field(default_factory=list)   # earliest first
    origin_ip: str = ""
    forged_auth: list = field(default_factory=list)  # methods faked lower down
    flags: list = field(default_factory=list)
    good: list = field(default_factory=list)
    raw_headers: str = ""

    @property
    def score(self) -> int:
        return min(100, sum(f.points for f in self.flags))

    @property
    def verdict(self) -> str:
        if self.score >= 50:
            return "Likely phishing"
        if self.score >= 15:
            return "Suspicious"
        return "No red flags in headers"


# ------------------------------------------------------------------ helpers
def parse_email(raw: bytes) -> EmailMessage:
    """Turn the raw email source into a message object. Nothing is executed."""
    return BytesParser(policy=policy.default).parsebytes(raw)


def domain_of(address: str) -> str:
    """'Name <a@b.com>' -> 'b.com'."""
    addr = parseaddr(address or "")[1]
    return addr.rsplit("@", 1)[-1].lower().strip(" >.") if "@" in addr else ""


def org_domain(domain: str) -> str:
    """mail.paypal.co.uk -> paypal.co.uk. Good enough for comparing senders."""
    parts = (domain or "").lower().strip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def org_name(domain: str) -> str:
    """mail.paypal.co.uk -> paypal (the part a company actually owns)."""
    return org_domain(domain).split(".")[0]


def same_org(a: str, b: str) -> bool:
    return bool(a) and bool(b) and org_domain(a) == org_domain(b)


def _header(msg, name) -> str:
    value = msg.get(name)
    return str(value).strip() if value is not None else ""


# ------------------------------------------------------- authentication
AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)\b(.*)", re.I | re.S)


def parse_auth_results(msg) -> dict:
    """
    Read SPF, DKIM and DMARC results from the receiving server's
    Authentication-Results header.

    Only the top one is used. Headers are added from the top down as an email
    travels, so the top one was written by the receiving mail server. A
    phisher can put a fake "dmarc=pass" further down, but not above it.
    """
    results = {}
    headers = msg.get_all("Authentication-Results") or []
    if headers:
        for clause in str(headers[0]).split(";")[1:]:
            m = AUTH_RE.search(clause)
            if not m:
                continue
            method, result, detail = m.group(1).lower(), m.group(2).lower(), " ".join(m.group(3).split())
            # Several DKIM signatures are common; one pass is enough
            if method in results and results[method][0] == "pass":
                continue
            results[method] = (result, detail)

    # Older servers put SPF in its own header
    if "spf" not in results:
        spf = _header(msg, "Received-SPF")
        if spf:
            results["spf"] = (spf.split()[0].lower(), " ".join(spf.split()[1:])[:200])
    return results


# ------------------------------------------------------- received chain
IP_RE = re.compile(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?|\[(?:IPv6:)?([0-9a-fA-F:]{3,})\]")


def parse_received(msg) -> list[Hop]:
    """
    Read the postmarks. Each mail server adds a Received line at the top, so
    we reverse them to show the route from the sender to the recipient.
    """
    hops = []
    for value in reversed(msg.get_all("Received") or []):
        text = " ".join(str(value).split())
        main, _, when = text.rpartition(";") if ";" in text else (text, "", "")
        from_host = re.search(r"\bfrom\s+(\S+)", main, re.I)
        by_host = re.search(r"\bby\s+(\S+)", main, re.I)
        from_part = main[:by_host.start()] if by_host else main
        ip = ""
        for m in IP_RE.finditer(from_part):
            ip = m.group(1) or m.group(2)
            break
        hops.append(Hop(
            from_host=from_host.group(1).strip("()") if from_host else "",
            ip=ip,
            by_host=by_host.group(1).strip("()") if by_host else "",
            time=when.strip(),
        ))
    return hops


def origin_ip(hops: list[Hop]) -> str:
    """The first public IP on the route: where the email entered the internet."""
    for hop in hops:
        if hop.ip and "." in hop.ip and not is_private_ip(hop.ip) and not hop.ip.startswith("127."):
            return hop.ip
    return ""


# ------------------------------------------------------------ red flags
def _brand_in(text: str) -> tuple[str, str]:
    """Return (brand key, the brand as written in the name), or ("", "")."""
    for brand in BRANDS:
        m = re.search(rf"\b{re.escape(brand)}\b", text, re.I)
        if m:
            return brand, m.group(0)
    return "", ""


def find_forged_auth(msg, real: dict) -> list[str]:
    """
    Methods that a lower Authentication-Results header claims passed, but
    the real (top) one says didn't. Phishers add these hoping a filter or an
    analyst reads the wrong one.
    """
    forged = []
    for header in (msg.get_all("Authentication-Results") or [])[1:]:
        for clause in str(header).split(";")[1:]:
            m = AUTH_RE.search(clause)
            if m and m.group(2).lower() == "pass":
                method = m.group(1).lower()
                if real.get(method, ("",))[0] != "pass" and method not in forged:
                    forged.append(method)
    return forged


def find_flags(r: HeaderReport) -> tuple[list[Flag], list[Flag]]:
    flags, good = [], []

    # SPF: is the sending server allowed to send for this domain?
    spf = r.auth.get("spf", ("", ""))[0]
    if spf == "pass":
        good.append(Flag(0, "SPF passed", "The server that sent it is on the domain's approved list."))
    elif spf in ("fail", "hardfail"):
        flags.append(Flag(WEIGHTS["spf_fail"], "SPF failed",
                          "The server that sent this is not allowed to send email for this domain."))
    elif spf == "softfail":
        flags.append(Flag(WEIGHTS["spf_softfail"], "SPF soft fail",
                          "The domain says this server probably shouldn't be sending its email."))
    elif r.auth:
        flags.append(Flag(WEIGHTS["spf_missing"], f"SPF {spf or 'missing'}",
                          "No SPF pass, so there's no proof the sending server is allowed to send for this domain."))

    # DKIM: was the email signed, and is the signature intact?
    dkim = r.auth.get("dkim", ("", ""))[0]
    if dkim == "pass":
        good.append(Flag(0, "DKIM passed", "The email carries a valid digital signature and wasn't changed on the way."))
    elif dkim == "fail":
        flags.append(Flag(WEIGHTS["dkim_fail"], "DKIM failed",
                          "The digital signature doesn't match. The email was forged or changed in transit."))
    elif r.auth:
        flags.append(Flag(WEIGHTS["dkim_missing"], f"DKIM {dkim or 'missing'}",
                          "The email isn't signed, so there's no proof it came from the domain it claims."))

    # DMARC: do SPF/DKIM line up with the From address the reader sees?
    dmarc = r.auth.get("dmarc", ("", ""))[0]
    if dmarc == "pass":
        good.append(Flag(0, "DMARC passed", "The From address the reader sees is backed by SPF or DKIM."))
    elif dmarc == "fail":
        flags.append(Flag(WEIGHTS["dmarc_fail"], "DMARC failed",
                          "The From address isn't backed by SPF or DKIM. The domain's owner says not to trust it."))

    if not r.auth:
        flags.append(Flag(0, "No authentication results",
                          "There are no SPF, DKIM or DMARC results. The email may have been saved before it "
                          "reached a mail server, or the headers were removed. Get the original from the mailbox."))

    # Display name pretending to be a brand
    brand, shown = _brand_in(r.from_name)
    if brand and org_name(r.from_domain) not in BRANDS[brand]:
        where = "a free email account" if r.from_domain in FREE_PROVIDERS else r.from_domain
        flags.append(Flag(WEIGHTS["brand_impersonation"], f"Pretends to be {shown}",
                          f"The name says {shown}, but the email really comes from {where}."))

    # A fake "pass" planted in a lower header
    if r.forged_auth:
        names = ", ".join(m.upper() for m in r.forged_auth)
        flags.append(Flag(WEIGHTS["forged_auth"], "Fake authentication header",
                          f"A lower header claims {names} passed, but the receiving server's own check says "
                          "otherwise. Someone added it to make the email look genuine."))

    # Display name containing a different email address
    name_addr = re.search(r"[\w.+-]+@([\w-]+\.[\w.-]+)", r.from_name)
    if name_addr and not same_org(name_addr.group(1), r.from_domain):
        flags.append(Flag(WEIGHTS["address_in_name"], "Fake address in the display name",
                          f"The name shows {name_addr.group(0)}, but the real address is {r.from_address}. "
                          "Many mail apps only show the name."))

    # Replies going somewhere else
    reply_domain = domain_of(r.reply_to)
    if reply_domain and not same_org(reply_domain, r.from_domain):
        flags.append(Flag(WEIGHTS["reply_to_mismatch"], "Replies go to a different domain",
                          f"Hitting Reply sends your answer to {reply_domain}, not {r.from_domain}."))

    # Bounce address on a different domain (common in bulk mail, so low weight)
    rp_domain = domain_of(r.return_path)
    if rp_domain and r.from_domain and not same_org(rp_domain, r.from_domain):
        flags.append(Flag(WEIGHTS["return_path_mismatch"], "Return-Path on a different domain",
                          f"Bounces go to {rp_domain}. Newsletters often do this through a mailing service, "
                          "so it only matters alongside other red flags."))

    if r.from_domain in FREE_PROVIDERS and not brand:
        good.append(Flag(0, "Sent from a free email account",
                         f"{r.from_domain} is normal for a person, but not for a company or bank."))
    return flags, good


# ------------------------------------------------------------- main entry
def analyse_headers(raw: bytes) -> HeaderReport:
    """Read an email's raw source and report what its headers say."""
    if len(raw) > MAX_EMAIL_BYTES:
        raise ValueError("Email is larger than 5 MB.")
    msg = parse_email(raw)

    from_name, from_address = parseaddr(_header(msg, "From"))
    r = HeaderReport(
        subject=_header(msg, "Subject"),
        date=_header(msg, "Date"),
        from_name=from_name,
        from_address=from_address,
        from_domain=domain_of(from_address),
        reply_to=_header(msg, "Reply-To"),
        return_path=_header(msg, "Return-Path").strip("<>"),
        to=", ".join(a for _, a in getaddresses([_header(msg, "To")]) if a),
        message_id=_header(msg, "Message-ID"),
        auth=parse_auth_results(msg),
        hops=parse_received(msg),
        raw_headers="\n".join(f"{k}: {v}" for k, v in msg.items()),
    )
    r.origin_ip = origin_ip(r.hops)
    r.forged_auth = find_forged_auth(msg, r.auth)
    r.flags, r.good = find_flags(r)
    return r

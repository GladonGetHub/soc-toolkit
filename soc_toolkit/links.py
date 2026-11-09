"""
Phishing Email Analyser, part 2: links.

Phishing nearly always wants you to click something. The trick is that what
you SEE in an email isn't always where a link GOES: the text can say
https://www.paypal.com while the link behind it points somewhere else
entirely. Your mail app only shows the real address if you hover over it.

This file pulls every link out of the email, without visiting any of them,
and checks each one for the tricks phishers use most.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlsplit

from .ioc import defang
from .phishing import BRANDS, Flag, brand_label, org_domain, org_name

# Link-shortening services hide where a link really goes
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id", "shorte.st", "bl.ink",
}

# Mailing services that send newsletter links through their own click
# tracker. The link text shows the company's site but the link goes via the
# tracker first, which is normal for marketing email, not a phishing sign.
TRACKERS = {
    "list-manage.com", "mailchi.mp", "mcsv.net", "sendgrid.net", "mandrillapp.com",
    "hubspotlinks.com", "hubspotemail.net", "exacttarget.com", "rs6.net", "cmail19.com",
    "cmail20.com", "createsend.com", "klclick.com", "klclick1.com", "mailgun.org",
    "sparkpostmail.com", "sendibt2.com", "sendinblue.com", "brevo.com", "awstrack.me",
    "safelinks.protection.outlook.com", "urldefense.com", "mimecastprotect.com",
}

# Files that run code when opened. Nobody needs to download these from an email.
RISKY_EXTENSIONS = (
    ".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".bat", ".cmd", ".ps1", ".msi",
    ".hta", ".iso", ".img", ".lnk", ".jar", ".wsf", ".apk",
)

# Letters and numbers that look alike: paypa1 -> paypal, rnicrosoft -> microsoft
LOOKALIKE = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s")]

URL_RE = re.compile(r"""(?:https?://|www\.)[^\s<>"'()\[\]{}]+""", re.I)

# Points per kind of link problem. Each kind counts once per email, so ten
# bad links don't count ten times.
LINK_WEIGHTS = {
    "mismatch": 40, "at_trick": 35, "lookalike": 30, "form": 30, "risky_file": 25,
    "ip_host": 25, "punycode": 25, "shortener": 15, "plain_http": 5,
}


@dataclass
class Link:
    url: str                 # where it really goes
    shown: str = ""          # what the reader sees (HTML links only)
    found_in: str = ""       # "HTML link", "Plain text", "Form"
    host: str = ""
    problems: list = field(default_factory=list)   # kinds from LINK_WEIGHTS


# ------------------------------------------------------------ extraction
class _LinkCollector(HTMLParser):
    """Reads HTML the way a browser would see the links, without rendering it."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self._href, self._text = [], None, []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self._href, self._text = a["href"].strip(), []
        elif tag == "form":
            self.links.append(Link(url=(a.get("action") or "").strip(), found_in="Form"))

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append(Link(url=self._href, shown=" ".join("".join(self._text).split()), found_in="HTML link"))
            self._href = None


def email_bodies(msg) -> tuple[str, str]:
    """Return (plain text, HTML) from the email. Attachments are skipped."""
    plain, html = [], []
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            text = part.get_content()
        except (LookupError, ValueError):
            text = (part.get_payload(decode=True) or b"").decode("utf-8", errors="replace")
        (html if ctype == "text/html" else plain).append(text)
    return "\n".join(plain), "\n".join(html)


def extract_links(msg) -> list[Link]:
    """Every link in the email, once each. HTML links keep the text shown to the reader."""
    plain, html = email_bodies(msg)
    links = []
    if html:
        collector = _LinkCollector()
        collector.feed(html)
        links += collector.links
    for m in URL_RE.finditer(plain):
        links.append(Link(url=m.group(0).rstrip(".,;:!?"), found_in="Plain text"))

    unique, seen = [], set()
    for link in links:
        if link.url.lower().startswith(("mailto:", "tel:", "#", "cid:")):
            continue
        key = (link.url, link.shown)
        if link.url and key not in seen:
            seen.add(key)
            unique.append(link)
    # Drop a plain-text copy of a link already found in the HTML
    html_urls = {l.url for l in unique if l.found_in == "HTML link"}
    return [l for l in unique if not (l.found_in == "Plain text" and l.url in html_urls)]


# ------------------------------------------------------------- checking
def host_of(url: str) -> str:
    if url.lower().startswith("www."):
        url = "http://" + url
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _normalise(name: str) -> str:
    for fake, real in LOOKALIKE:
        name = name.replace(fake, real)
    return name


def _mentions(name: str, word: str) -> bool:
    """
    Does a domain name use this brand word? Long names match anywhere
    (microsoftsupport), short ones only as a whole word between hyphens,
    so "ups" doesn't match "groupsales" and "apple" doesn't match "pineapple".
    """
    if len(word) >= 6:
        return word in name.replace("-", "")
    return word in name.split("-")


def lookalike_brand(host: str) -> str:
    """
    The brand a domain is pretending to be, or "".

    paypal-account-verify.com uses "paypal" but isn't paypal.com.
    paypa1.com isn't paypal.com either, but reads like it at a glance.
    """
    if not host or _is_ip(host):
        return ""
    name = org_name(host)
    if any(name in real_names for real_names in BRANDS.values()):
        return ""                                      # a real company domain
    normalised = _normalise(name)
    for brand, real_names in BRANDS.items():
        word = brand.replace(" ", "")
        if _mentions(name, word) or _mentions(normalised, word) or normalised in real_names:
            return brand
    return ""


def _shown_host(shown: str) -> str:
    """If the link text looks like an address, which site does it name?"""
    m = re.search(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,63})(?:[/:?#]|\s|$)", shown.strip(), re.I)
    return m.group(1).lower() if m else ""


def check_link(link: Link) -> Link:
    url, host = link.url, host_of(link.url)
    link.host = host
    lowered = url.lower()

    if link.found_in == "Form":
        link.problems.append("form")
    shown = _shown_host(link.shown)
    via_tracker = org_domain(host) in TRACKERS or host in TRACKERS
    if shown and host and org_domain(shown) != org_domain(host) and not via_tracker:
        link.problems.append("mismatch")
    if "@" in (urlsplit(url).netloc if "://" in url else ""):
        link.problems.append("at_trick")
    if _is_ip(host):
        link.problems.append("ip_host")
    if host in SHORTENERS:
        link.problems.append("shortener")
    if "xn--" in host:
        link.problems.append("punycode")
    if lookalike_brand(host):
        link.problems.append("lookalike")
    if urlsplit(lowered).path.endswith(RISKY_EXTENSIONS):
        link.problems.append("risky_file")
    if lowered.startswith("http://"):
        link.problems.append("plain_http")
    return link


def _explain(kind: str, link: Link, count: int) -> Flag:
    url, more = defang(link.url), f" ({count} links like this)" if count > 1 else ""
    text = {
        "mismatch": ("Link text doesn't match where it goes",
                     f"It shows \"{defang(link.shown)}\" but really goes to {defang(link.host)}{more}. "
                     "This is the most common phishing trick."),
        "at_trick": ("\"@\" trick in a link",
                     f"In {url}, everything before the @ is ignored by the browser, so it really goes to "
                     f"{defang(link.host)}."),
        "lookalike": ("Lookalike domain",
                      f"{defang(link.host)} is made to look like {brand_label(lookalike_brand(link.host))}, "
                      f"but isn't their real domain{more}."),
        "form": ("Form inside the email",
                 "The email asks you to type something straight into it. Real companies don't collect "
                 "passwords or card details this way."),
        "risky_file": ("Link downloads a program",
                       f"{url} points to a file that runs code when opened{more}."),
        "ip_host": ("Link to a bare IP address",
                    f"{url} uses a raw IP address instead of a website name{more}. Genuine companies rarely do this."),
        "punycode": ("Disguised characters in a domain",
                     f"{defang(link.host)} uses \"xn--\" encoding, which can hide letters from other alphabets "
                     "that look like normal ones."),
        "shortener": ("Shortened link",
                      f"{url} goes through a link shortener, which hides the real destination{more}."),
        "plain_http": ("Link isn't encrypted",
                       f"{url} uses http, not https{more}. Not proof of phishing, but no login page should use it."),
    }[kind]
    return Flag(LINK_WEIGHTS[kind], *text, area="Links")


def link_flags(links: list[Link]) -> list[Flag]:
    """One red flag per kind of problem, with an example link."""
    by_kind = {}
    for link in links:
        for kind in link.problems:
            by_kind.setdefault(kind, []).append(link)
    return [_explain(kind, examples[0], len(examples)) for kind, examples in by_kind.items()]


def analyse_links(msg) -> tuple[list[Link], list[Flag]]:
    links = [check_link(l) for l in extract_links(msg)]
    return links, link_flags(links)

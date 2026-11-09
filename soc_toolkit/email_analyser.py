"""
Phishing Email Analyser: puts the parts together.

  phishing.py  - headers: who really sent it (part 1)
  links.py     - links: where it wants you to go (part 2)

Each part adds its red flags to one report, and the points add up to one
risk score, the same way an analyst builds a case from several clues.
"""

from .links import analyse_links
from .phishing import EmailReport, Flag, analyse_headers, parse_email


def analyse_email(raw: bytes) -> EmailReport:
    """Read an email's raw source and report everything suspicious about it."""
    report = analyse_headers(raw)          # also checks the 5 MB limit
    links, flags = analyse_links(parse_email(raw))
    report.links = links
    report.flags += flags
    if links and not flags:
        n = len(links)
        report.good.append(Flag(0, f"{n} link{'s' if n > 1 else ''} checked, no tricks found",
                                "Each link goes where its text says, with no lookalike domains, shorteners "
                                "or raw IP addresses.", area="Links"))
    return report

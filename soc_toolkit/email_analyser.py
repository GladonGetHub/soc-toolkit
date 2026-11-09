"""
Phishing Email Analyser: puts the parts together.

  phishing.py     - headers: who really sent it (part 1)
  links.py        - links: where it wants you to go (part 2)
  attachments.py  - attachments: what the files really are (part 3)

Each part adds its red flags to one report, and the points add up to one
risk score, the same way an analyst builds a case from several clues.
"""

from .attachments import analyse_attachments
from .links import analyse_links
from .phishing import EmailReport, Flag, analyse_headers, parse_email


def analyse_email(raw: bytes) -> EmailReport:
    """Read an email's raw source and report everything suspicious about it."""
    report = analyse_headers(raw)          # also checks the 5 MB limit
    msg = parse_email(raw)
    links, flags = analyse_links(msg)
    report.links = links
    report.flags += flags
    if links and not flags:
        n = len(links)
        report.good.append(Flag(0, f"{n} link{'s' if n > 1 else ''} checked, no tricks found",
                                "Each link goes where its text says, with no lookalike domains, shorteners "
                                "or raw IP addresses.", area="Links"))
    attachments, att_flags = analyse_attachments(msg)
    report.attachments = attachments
    report.flags += att_flags
    if attachments and not att_flags:
        n = len(attachments)
        report.good.append(Flag(0, f"{n} attachment{'s' if n > 1 else ''} checked, nothing risky",
                                "Each file is what its name says, with no programs, macros or hidden tricks. "
                                "Its hash can still be checked against malware databases.", area="Attachments"))
    return report

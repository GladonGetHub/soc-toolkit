"""
Enrichment: combine what each threat-intel source says into one verdict.

Every source (see sources.py) returns a Result with a 0-100 score, or None
when it has no opinion. The overall verdict is based on the highest score,
the same way an analyst treats one strong "this is bad" signal as enough
to escalate.
"""

from dataclasses import dataclass, field

from .ioc import is_private_ip


@dataclass
class Result:
    provider: str
    score: int | None          # 0-100, None if the source had no data or no opinion
    summary: str
    link: str = ""
    details: dict = field(default_factory=dict)
    error: str = ""


def verdict(value: str, ioc_type: str, results: list[Result]) -> str:
    """Combine source results into one word an analyst can act on."""
    if ioc_type == "ip" and is_private_ip(value):
        return "Internal"
    scores = [r.score for r in results if r.score is not None]
    if not scores:
        return "Unknown"
    top = max(scores)
    if top >= 50:
        return "Malicious"
    if top >= 15:
        return "Suspicious"
    return "Clean"


def enrich(value: str, ioc_type: str, providers: list) -> tuple[str, list[Result]]:
    """Run every source that supports this IOC type, then give a verdict."""
    if ioc_type == "ip" and is_private_ip(value):
        return "Internal", []
    results = [p.lookup(value, ioc_type) for p in providers if ioc_type in p.supports]
    return verdict(value, ioc_type, results), results

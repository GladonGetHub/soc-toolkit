"""
Looking up indicators from any page of the app.

Module 1 and Module 2 both send indicators to the threat-intel sources, so
the shared parts live here: which keys to use, caching, the public limits
and pacing for the free VirusTotal key.
"""

import hashlib
import time
from dataclasses import asdict

import streamlit as st

from .config import MAIN_SOURCES, PUBLIC_MAX_PER_LOOKUP, PUBLIC_MAX_PER_SESSION, build_providers, is_public
from .enrich import enrich


def visitor_keys() -> dict:
    """Keys the visitor pasted into the IOC Enrichment sidebar (public version only)."""
    if not is_public():
        return {}
    return {s: st.session_state.get(f"key_{s}", "") for s in MAIN_SOURCES}


def key_fingerprint(keys: dict) -> str:
    """A one-way fingerprint of the visitor's keys, so cached results from one
    visitor's keys are never handed to a visitor with different (or no) keys."""
    joined = "|".join(f"{s}={keys.get(s, '')}" for s in sorted(keys))
    return hashlib.sha256(joined.encode()).hexdigest()


@st.cache_data(ttl=3600, show_spinner=False)
def cached_lookup(value: str, ioc_type: str, fingerprint: str, _keys: dict):
    """Cache results for an hour so repeat lookups don't burn API quota.
    The leading underscore stops Streamlit storing the keys themselves."""
    provs, _ = build_providers(_keys)
    verdict, results = enrich(value, ioc_type, provs)
    return verdict, [asdict(r) for r in results]


def within_public_limits(to_check: list) -> list | None:
    """
    In the public version, trim to the per-lookup limit and check the session
    limit. Returns the list to check, or None if the session limit is reached
    (an error has already been shown).
    """
    if not is_public():
        return to_check
    if len(to_check) > PUBLIC_MAX_PER_LOOKUP:
        st.warning(f"The public version checks up to {PUBLIC_MAX_PER_LOOKUP} at a time, "
                   f"so only the first {PUBLIC_MAX_PER_LOOKUP} were checked.")
        to_check = to_check[:PUBLIC_MAX_PER_LOOKUP]
    used = st.session_state.get("lookups_used", 0)
    if used + len(to_check) > PUBLIC_MAX_PER_SESSION:
        left = max(PUBLIC_MAX_PER_SESSION - used, 0)
        st.error(f"The public version allows {PUBLIC_MAX_PER_SESSION} lookups per session and you have {left} left. "
                 "To check more, run the toolkit on your own machine (see the GitHub page).")
        return None
    st.session_state["lookups_used"] = used + len(to_check)
    return to_check


def run_lookups(to_check: list[tuple[str, str]]) -> list[dict]:
    """
    Look up each (value, type) and return rows of
    {"value", "type", "verdict", "results"}, with a progress bar.
    """
    keys = visitor_keys()
    providers, _ = build_providers(keys)
    # The free VirusTotal key allows 4 lookups a minute, so pace big batches
    pace = any(p.name == "VirusTotal" for p in providers) and len(to_check) > 4
    if pace:
        st.info(f"Free VirusTotal keys allow 4 lookups a minute. This batch will take about "
                f"{len(to_check) // 4 + 1} minute(s).")
    fingerprint = key_fingerprint(keys)
    rows = []
    bar = st.progress(0, text="Checking...")
    for i, (value, ioc_type) in enumerate(to_check):
        if pace and i > 0 and i % 4 == 0:
            time.sleep(60)
        verdict, results = cached_lookup(value, ioc_type, fingerprint, keys)
        rows.append({"value": value, "type": ioc_type, "verdict": verdict, "results": results})
        bar.progress((i + 1) / len(to_check), text=f"Checked {i + 1} of {len(to_check)}")
    bar.empty()
    return rows


def flagged_by(results: list[dict]) -> str:
    """'3 of 5' = 3 sources scored it Malicious (50+) out of 5 that had an opinion."""
    scored = [x for x in results if x["score"] is not None]
    if not scored:
        return "-"
    return f"{sum(x['score'] >= 50 for x in scored)} of {len(scored)}"


def top_finding(results: list[dict]) -> str:
    """The highest-scoring source's summary, e.g. 'AbuseIPDB: 100% abuse confidence'."""
    best = sorted(results, key=lambda x: -(x["score"] if x["score"] is not None else -1))
    return f"{best[0]['provider']}: {best[0]['summary']}" if best else ""

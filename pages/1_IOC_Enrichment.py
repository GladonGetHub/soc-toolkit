"""
Module 1: IOC Enrichment

Paste indicators (IPs, domains, URLs, hashes), even defanged ones, and get
one verdict per indicator from every threat-intel source that's switched on.

On your own machine the sources come from your .env keys. On the public
website, visitors get the free no-key sources and can add their own keys.
"""

import csv
import hashlib
import io
import time
from dataclasses import asdict

import streamlit as st

from soc_toolkit.config import (MAIN_SOURCES, PUBLIC_MAX_PER_LOOKUP,
                                PUBLIC_MAX_PER_SESSION, build_providers, is_public)
from soc_toolkit.enrich import enrich
from soc_toolkit.ioc import defang, parse_iocs

st.set_page_config(page_title="IOC Enrichment", page_icon="🔎", layout="wide")
st.title("🔎 IOC Enrichment")
st.write("Paste indicators below, one per line. Defanged values like `194[.]165[.]16[.]11` are fine.")

public = is_public()

KEY_LINKS = {
    "VirusTotal": "https://www.virustotal.com",
    "AbuseIPDB": "https://www.abuseipdb.com",
    "OTX": "https://otx.alienvault.com",
    "abuse.ch": "https://auth.abuse.ch",
}


def forget_keys():
    for source in MAIN_SOURCES:
        st.session_state[f"key_{source}"] = ""


with st.sidebar:
    if public:
        with st.expander("🔑 Add your own API keys (optional)"):
            st.caption(
                "Free keys switch on more sources. They're kept only for this browser "
                "session and are never saved. Close the tab and they're gone."
            )
            for source in MAIN_SOURCES:
                label = "abuse.ch (MalwareBazaar, URLhaus, ThreatFox)" if source == "abuse.ch" else source
                st.text_input(label, type="password", key=f"key_{source}", help=f"Free key from {KEY_LINKS[source]}")
            st.button("Forget my keys", on_click=forget_keys)

visitor_keys = {s: st.session_state.get(f"key_{s}", "") for s in MAIN_SOURCES} if public else {}
providers, _ = build_providers(visitor_keys)

with st.sidebar:
    st.subheader("Sources")
    for p in providers:
        st.write(f"✅ {p.name}")
    if public:
        st.caption("Without keys, IPs and hashes are checked. Add your own keys above "
                   "to check domains and URLs too, and to switch on more sources.")
    elif len(providers) < 9:
        st.caption("Add more keys to .env to switch on more sources.")

if public:
    st.info(
        "**Public version.** Each indicator is sent to the third-party services listed "
        "in the sidebar. Don't paste internal, client or incident data you're not "
        f"allowed to share. Up to {PUBLIC_MAX_PER_LOOKUP} indicators per lookup."
    )

ICONS = {"Malicious": "🔴", "Suspicious": "🟠", "Clean": "🟢", "Internal": "🔵", "Unknown": "⚪"}


def short(value: str, ioc_type: str) -> str:
    """Shorten long hashes in the table so every column fits. Full value stays in Details and the CSV."""
    if ioc_type in ("md5", "sha1", "sha256"):
        return f"{value[:8]}…{value[-8:]}"
    return defang(value)


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


sample = "194[.]165[.]16[.]11\n45.129.56.200\n8.8.8.8\n192.168.10.10\nhxxps://example[.]com/login"


def load_example():
    st.session_state["ioc_text"] = sample


text = st.text_area("Indicators", height=180, placeholder=sample, key="ioc_text")
col1, col2 = st.columns([1, 5])
run = col1.button("Look up", type="primary")
col2.button("Load example", on_click=load_example)

if run:
    iocs = parse_iocs(text)
    unknown = [v for v, t in iocs if t == "unknown"]
    to_check = [(v, t) for v, t in iocs if t != "unknown"]

    if unknown:
        st.warning("Not recognised, skipped: " + ", ".join(unknown))
    if not to_check:
        st.stop()

    if public:
        if len(to_check) > PUBLIC_MAX_PER_LOOKUP:
            st.warning(f"The public version checks up to {PUBLIC_MAX_PER_LOOKUP} at a time, "
                       f"so only the first {PUBLIC_MAX_PER_LOOKUP} were checked.")
            to_check = to_check[:PUBLIC_MAX_PER_LOOKUP]
        used = st.session_state.get("lookups_used", 0)
        if used + len(to_check) > PUBLIC_MAX_PER_SESSION:
            left = max(PUBLIC_MAX_PER_SESSION - used, 0)
            st.error(f"The public version allows {PUBLIC_MAX_PER_SESSION} lookups per session and you have {left} left. "
                     "To check more, run the toolkit on your own machine (see the GitHub page).")
            st.stop()
        st.session_state["lookups_used"] = used + len(to_check)

    # The free VirusTotal key allows 4 lookups a minute, so pace big batches
    pace = any(p.name == "VirusTotal" for p in providers) and len(to_check) > 4
    if pace:
        st.info(f"Free VirusTotal keys allow 4 lookups a minute. This batch will take about {len(to_check) // 4 + 1} minute(s).")

    fingerprint = key_fingerprint(visitor_keys)
    rows = []
    bar = st.progress(0, text="Checking...")
    for i, (value, ioc_type) in enumerate(to_check):
        if pace and i > 0 and i % 4 == 0:
            time.sleep(60)
        verdict, results = cached_lookup(value, ioc_type, fingerprint, visitor_keys)
        rows.append({"value": value, "type": ioc_type, "verdict": verdict, "results": results})
        bar.progress((i + 1) / len(to_check), text=f"Checked {i + 1} of {len(to_check)}")
    bar.empty()
    st.session_state["rows"] = rows

rows = st.session_state.get("rows", [])
if rows:
    counts = {v: sum(r["verdict"] == v for r in rows) for v in ICONS}
    cols = st.columns(len(counts))
    for c, (label, n) in zip(cols, counts.items()):
        c.metric(f"{ICONS[label]} {label}", n)

    def no_results_text(r):
        if r["verdict"] == "Internal":
            return "Internal address, not looked up. Investigate it in your own logs."
        return "None of the sources switched on can check this type. Add a key to switch on more."

    def flagged_by(results):
        """'3 of 5' = 3 sources scored it Malicious (50+) out of 5 that had an opinion."""
        scored = [x for x in results if x["score"] is not None]
        if not scored:
            return "-"
        return f"{sum(x['score'] >= 50 for x in scored)} of {len(scored)}"

    st.dataframe(
        [{
            "Verdict": f"{ICONS[r['verdict']]} {r['verdict']}",
            "Indicator (defanged)": short(r["value"], r["type"]),
            "Type": r["type"],
            "Flagged by": flagged_by(r["results"]),
            "Top finding": next((f"{x['provider']}: {x['summary']}" for x in sorted(r["results"], key=lambda x: -(x["score"] or -1))), no_results_text(r)),
        } for r in rows],
        hide_index=True,
    )

    st.subheader("Details")
    for r in rows:
        with st.expander(f"{ICONS[r['verdict']]} {defang(r['value'])} ({r['type']})"):
            if not r["results"]:
                st.write(no_results_text(r))
            for res in r["results"]:
                st.markdown(f"**{res['provider']}**: {res['summary']}")
                if res["details"]:
                    st.json(res["details"], expanded=False)
                if res["link"]:
                    st.markdown(f"[Open in {res['provider']}]({res['link']})")
                if res["error"]:
                    st.caption(f"Error detail: {res['error']}")

    # Export for the ticket or case notes
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["indicator_defanged", "type", "verdict", "provider", "score", "summary"])
    for r in rows:
        for res in r["results"] or [{"provider": "-", "score": "", "summary": "internal"}]:
            w.writerow([defang(r["value"]), r["type"], r["verdict"], res["provider"], res["score"], res["summary"]])
    st.download_button("Download results (CSV)", buf.getvalue(), "ioc_results.csv", "text/csv")

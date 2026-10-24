"""
Module 1: IOC Enrichment

Paste indicators (IPs, domains, URLs, hashes), even defanged ones, and get
one verdict per indicator from every threat-intel source that has an API key
set, plus the free no-key sources.
"""

import csv
import io
import time
from dataclasses import asdict

import streamlit as st

from soc_toolkit.config import build_providers
from soc_toolkit.enrich import enrich
from soc_toolkit.ioc import defang, parse_iocs

st.set_page_config(page_title="IOC Enrichment", page_icon="🔎", layout="wide")
st.title("🔎 IOC Enrichment")
st.write("Paste indicators below, one per line. Defanged values like `194[.]165[.]16[.]11` are fine.")

providers, demo_mode = build_providers()

with st.sidebar:
    st.subheader("Sources")
    if demo_mode:
        st.warning("Demo mode: sample data only")
    for p in providers:
        st.write(f"✅ {p.name}")
    if not demo_mode:
        st.caption("Add more keys to .env to switch on more sources.")

ICONS = {"Malicious": "🔴", "Suspicious": "🟠", "Clean": "🟢", "Internal": "🔵", "Unknown": "⚪"}


def short(value: str, ioc_type: str) -> str:
    """Shorten long hashes in the table so every column fits. Full value stays in Details and the CSV."""
    if ioc_type in ("md5", "sha1", "sha256"):
        return f"{value[:8]}…{value[-8:]}"
    return defang(value)


@st.cache_data(ttl=3600, show_spinner=False)
def cached_lookup(value: str, ioc_type: str, demo: bool):
    """Cache results for an hour so repeat lookups don't burn API quota."""
    provs, _ = build_providers()
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

    # The free VirusTotal key allows 4 lookups a minute, so pace big batches
    pace = (not demo_mode) and any(p.name == "VirusTotal" for p in providers) and len(to_check) > 4
    if pace:
        st.info(f"Free VirusTotal keys allow 4 lookups a minute. This batch will take about {len(to_check) // 4 + 1} minute(s).")

    rows = []
    bar = st.progress(0, text="Checking...")
    for i, (value, ioc_type) in enumerate(to_check):
        if pace and i > 0 and i % 4 == 0:
            time.sleep(60)
        verdict, results = cached_lookup(value, ioc_type, demo_mode)
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
            "Top finding": next((f"{x['provider']}: {x['summary']}" for x in sorted(r["results"], key=lambda x: -(x["score"] or -1))), "Internal address, not looked up"),
        } for r in rows],
        hide_index=True,
    )

    st.subheader("Details")
    for r in rows:
        with st.expander(f"{ICONS[r['verdict']]} {defang(r['value'])} ({r['type']})"):
            if not r["results"]:
                st.write("Internal address. Investigate it in your own logs instead.")
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

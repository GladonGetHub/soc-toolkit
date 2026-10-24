"""
SOC Toolkit home page.

Run with:  streamlit run app.py
Each tool lives in the pages/ folder and appears in the sidebar automatically.
"""

import streamlit as st

from soc_toolkit.config import build_providers

st.set_page_config(page_title="SOC Toolkit", page_icon="🛡️", layout="wide")

st.title("🛡️ SOC Toolkit")
st.write(
    "Small tools that take the repetitive work off a SOC analyst: "
    "checking indicators, triaging phishing, reading logs and handing over shifts."
)

_, demo_mode = build_providers()
if demo_mode:
    st.info(
        "**Demo mode.** No API keys found, so lookups use sample data. "
        "Add your keys to a `.env` file to use live threat intelligence (see README)."
    )
else:
    st.success("Live mode: API keys loaded.")

st.subheader("Modules")
modules = [
    ("1", "IOC Enrichment", "Check IPs, domains, URLs and hashes against 9 threat-intel sources in one go", "✅ Ready"),
    ("2", "Phishing Email Analyser", "Upload a suspicious email and get a verdict", "🔜 Next"),
    ("3", "Log Parser", "Find brute-force patterns in Windows and Linux logs", "Planned"),
    ("4", "Threat Feed Aggregator", "Merge free threat feeds into one Splunk lookup", "Planned"),
    ("5", "Alert Triage Assistant", "Enrich a SIEM alert and draft the case note", "Planned"),
    ("6", "Shift Handover", "Open incidents and notes for the next shift", "Planned"),
    ("7", "Mini SOAR", "Score an alert and run the response steps", "Planned"),
    ("8", "Detection as Code", "Test detection rules before they go live", "Planned"),
]
st.dataframe([{"#": n, "Module": m, "What it does": d, "Status": s} for n, m, d, s in modules], hide_index=True)

st.caption("Open a ready module from the sidebar on the left.")

"""
SOC Toolkit home page (shown as "Home" in the sidebar, see app.py).
"""

import streamlit as st

from soc_toolkit.config import build_providers

st.title("🛡️ SOC Toolkit")
st.write(
    "Small tools that take the repetitive work off a SOC analyst: "
    "checking indicators, triaging phishing, reading logs and handing over shifts."
)

providers, public = build_providers()
if public:
    st.info(
        "**Public version.** The free sources work straight away with no sign-up. "
        "To switch on all 9 sources, add your own free API keys in the IOC Enrichment sidebar."
    )
else:
    st.success(f"Private mode: your API keys are loaded, {len(providers)} sources switched on.")

st.subheader("Modules")
modules = [
    ("1", "IOC Enrichment", "Check IPs, domains, URLs and hashes against 9 threat-intel sources in one go", "✅ Ready"),
    ("2", "Phishing Email Analyser", "Check an email's sender, authentication and links for phishing", "🔨 In progress"),
    ("3", "Log Parser", "Find brute-force patterns in Windows and Linux logs", "Planned"),
    ("4", "Threat Feed Aggregator", "Merge free threat feeds into one Splunk lookup", "Planned"),
    ("5", "Alert Triage Assistant", "Enrich a SIEM alert and draft the case note", "Planned"),
    ("6", "Shift Handover", "Open incidents and notes for the next shift", "Planned"),
    ("7", "Mini SOAR", "Score an alert and run the response steps", "Planned"),
    ("8", "Detection as Code", "Test detection rules before they go live", "Planned"),
]
st.dataframe([{"#": n, "Module": m, "What it does": d, "Status": s} for n, m, d, s in modules], hide_index=True)

st.caption("Open a ready module from the sidebar on the left.")
st.caption("Source code: [github.com/GladonGetHub/soc-toolkit](https://github.com/GladonGetHub/soc-toolkit)")

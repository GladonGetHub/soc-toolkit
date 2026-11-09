"""
SOC Toolkit: the menu.

Run with:  streamlit run app.py

This file only sets up the sidebar. Each page is its own file, and a new
module is added by adding one line to the list below.
"""

import streamlit as st

st.set_page_config(page_icon="🛡️", layout="wide")

pages = [
    st.Page("home.py", title="Home", icon="🛡️", default=True),
    st.Page("pages/1_IOC_Enrichment.py", title="IOC Enrichment", icon="🔎", url_path="IOC_Enrichment"),
    st.Page("pages/2_Phishing_Analyser.py", title="Phishing Email Analyser", icon="🎣", url_path="Phishing_Analyser"),
]
st.navigation(pages).run()

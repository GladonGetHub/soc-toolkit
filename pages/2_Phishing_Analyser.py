"""
Module 2: Phishing Email Analyser

Upload a suspicious email (.eml) or paste its source, and see what the
headers say about where it really came from.

Part 1: headers, SPF, DKIM, DMARC and the route the email took.
Coming next: links, attachments, and checking them with Module 1's sources.
"""

from pathlib import Path

import streamlit as st

from soc_toolkit.config import is_public
from soc_toolkit.ioc import defang
from soc_toolkit.phishing import MAX_EMAIL_BYTES, analyse_headers

st.set_page_config(page_title="Phishing Email Analyser", page_icon="🎣", layout="wide")
st.title("🎣 Phishing Email Analyser")
st.write(
    "Upload a suspicious email or paste its full source to see where it really came from. "
    "The email is only read, never opened: links aren't visited and attachments aren't run."
)

with st.expander("How do I get an email's source?"):
    st.markdown(
        "- **Outlook (web):** open the email, click **⋯**, then **View**, then **View message source**. Copy all of it.\n"
        "- **Outlook (desktop):** drag the email to your desktop to save it, then upload that file.\n"
        "- **Gmail:** open the email, click **⋮**, then **Show original**, then **Download original**.\n"
        "- **Thunderbird:** open the email, then **File**, **Save As**, **File**."
    )

if is_public():
    st.info(
        "**Public version.** The email is processed in memory and not stored. "
        "Don't upload emails containing personal or client data you're not allowed to share."
    )

SAMPLES = Path(__file__).parent.parent / "samples"
EXAMPLES = {
    "Sample phishing email": "phishing_paypal_impersonation.eml",
    "Sample genuine email": "genuine_newsletter.eml",
}


def load_sample(name):
    st.session_state["email_text"] = (SAMPLES / EXAMPLES[name]).read_text()
    # A new key gives a fresh, empty upload box, so the sample is what gets analysed
    st.session_state["upload_n"] = st.session_state.get("upload_n", 0) + 1


tab_upload, tab_paste = st.tabs(["Upload .eml file", "Paste email source"])
with tab_upload:
    upload = st.file_uploader("Email file", type=["eml", "txt"], key=f"email_upload_{st.session_state.get('upload_n', 0)}")
    st.caption("If a file is uploaded, it's analysed instead of anything pasted.")
with tab_paste:
    st.text_area("Full email source (headers and body)", height=200, key="email_text")

c1, c2, c3 = st.columns([1, 2, 2])
run = c1.button("Analyse", type="primary")
c2.button("Load sample phishing email", on_click=load_sample, args=("Sample phishing email",))
c3.button("Load sample genuine email", on_click=load_sample, args=("Sample genuine email",))

if run:
    if upload is not None:
        raw = upload.getvalue()
    else:
        raw = st.session_state.get("email_text", "").encode("utf-8", errors="replace")
    if not raw.strip():
        st.warning("Upload an email file or paste its source first.")
        st.stop()
    if len(raw) > MAX_EMAIL_BYTES:
        st.error("That email is larger than 5 MB. Remove large attachments and try again.")
        st.stop()
    if b"From:" not in raw[:50000] and b"from:" not in raw[:50000].lower():
        st.warning("That doesn't look like an email's full source: there's no From header. "
                   "See \"How do I get an email's source?\" above.")
        st.stop()
    st.session_state["report"] = analyse_headers(raw)

r = st.session_state.get("report")
if r:
    ICON = {"Likely phishing": "🔴", "Suspicious": "🟠", "No red flags in headers": "🟢"}
    st.divider()
    st.subheader(f"{ICON[r.verdict]} {r.verdict} (risk score {r.score}/100)")
    if r.verdict == "No red flags in headers":
        st.caption("The headers look genuine. Links and attachments can still be dangerous, "
                   "and a real account can be hacked, so read the content with care.")

    left, right = st.columns(2)
    with left:
        st.markdown("**🚩 Red flags**")
        scored = sorted([f for f in r.flags if f.points], key=lambda f: -f.points)
        if not scored:
            st.write("None found in the headers.")
        for f in scored:
            st.markdown(f"**{f.title}** (+{f.points})  \n{f.why}")
        for f in [f for f in r.flags if not f.points]:
            st.markdown(f"**ℹ️ {f.title}**  \n{f.why}")
    with right:
        st.markdown("**✅ Good signs**")
        if not r.good:
            st.write("None.")
        for g in r.good:
            st.markdown(f"**{g.title}**  \n{g.why}")

    st.subheader("Sender")
    st.dataframe([
        {"Field": "Display name", "Value": r.from_name or "(none)", "What it means": "What most mail apps show. Anyone can type anything here."},
        {"Field": "From address", "Value": r.from_address, "What it means": "The address the email claims to come from."},
        {"Field": "Reply-To", "Value": r.reply_to or "(same as From)", "What it means": "Where your reply would go."},
        {"Field": "Return-Path", "Value": r.return_path or "(none)", "What it means": "Where bounce messages go. Used by the SPF check."},
        {"Field": "To", "Value": r.to, "What it means": ""},
        {"Field": "Subject", "Value": r.subject, "What it means": ""},
        {"Field": "Date", "Value": r.date, "What it means": "Set by the sender, so it can be faked."},
        {"Field": "Message-ID", "Value": r.message_id, "What it means": ""},
    ], hide_index=True)

    st.subheader("Authentication")
    MEANING = {
        "spf": "Is the sending server allowed to send for this domain?",
        "dkim": "Is the email signed, and unchanged since it was sent?",
        "dmarc": "Do SPF or DKIM back up the From address the reader sees?",
    }
    MARK = {"pass": "✅", "fail": "❌", "softfail": "⚠️", "none": "⚪", "neutral": "⚪"}
    if r.auth:
        st.dataframe([{
            "Check": m.upper(),
            "Result": f"{MARK.get(r.auth[m][0], '⚪')} {r.auth[m][0]}" if m in r.auth else "⚪ not reported",
            "Question it answers": MEANING[m],
            "Detail": r.auth[m][1] if m in r.auth else "",
        } for m in ("spf", "dkim", "dmarc")], hide_index=True)
    else:
        st.write("No results found in the headers.")

    st.subheader("Route the email took")
    st.caption("From the sender's server (top) to the recipient's mailbox (bottom).")
    if r.hops:
        st.dataframe([{
            "Hop": i + 1, "From server": h.from_host, "IP": defang(h.ip) if h.ip else "",
            "Received by": h.by_host, "Time": h.time,
        } for i, h in enumerate(r.hops)], hide_index=True)
    if r.origin_ip:
        st.markdown(f"**Where it entered the internet:** `{defang(r.origin_ip)}`")
        st.caption("Copy this IP into IOC Enrichment to see if it's known for spam or attacks. "
                   "This will happen automatically in a later update.")

    with st.expander("All headers (raw)"):
        st.code(r.raw_headers, language=None)

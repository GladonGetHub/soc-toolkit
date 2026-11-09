"""
Module 2: Phishing Email Analyser

Upload a suspicious email (.eml) or paste its source, and see who really
sent it and where its links really go.

Part 1: headers, SPF, DKIM, DMARC and the route the email took.
Part 2: links.
Coming next: attachments, and checking everything with Module 1's sources.
"""

from pathlib import Path

import streamlit as st

from soc_toolkit.config import is_public
from soc_toolkit.display import safe_text
from soc_toolkit.email_analyser import analyse_email
from soc_toolkit.ioc import defang
from soc_toolkit.phishing import MAX_EMAIL_BYTES

st.title("🎣 Phishing Email Analyser")
st.write(
    "Upload a suspicious email or paste its full source to see who really sent it and where its links go. "
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
    "phishing": "phishing_paypal_impersonation.eml",
    "genuine": "genuine_newsletter.eml",
}


def load_sample(name):
    st.session_state["email_text"] = (SAMPLES / EXAMPLES[name]).read_text()
    # A new key gives a fresh, empty upload box, so the sample is what gets analysed
    st.session_state["upload_n"] = st.session_state.get("upload_n", 0) + 1


tab_upload, tab_paste = st.tabs(["Upload .eml file", "Paste email source"])
with tab_upload:
    upload = st.file_uploader("Email file (up to 5 MB)", type=["eml", "txt"],
                              key=f"email_upload_{st.session_state.get('upload_n', 0)}")
    st.caption("If a file is uploaded, it's analysed instead of anything pasted.")
with tab_paste:
    st.text_area("Full email source (headers and body)", height=200, key="email_text")

c1, c2, c3 = st.columns([1, 2, 2])
run = c1.button("Analyse", type="primary")
c2.button("Load sample phishing email", on_click=load_sample, args=("phishing",))
c3.button("Load sample genuine email", on_click=load_sample, args=("genuine",))

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
    if b"from:" not in raw[:50000].lower():
        st.warning("That doesn't look like an email's full source: there's no From header. "
                   "See \"How do I get an email's source?\" above.")
        st.stop()
    st.session_state["report"] = analyse_email(raw)

r = st.session_state.get("report")
if r:
    ICON = {"Likely phishing": "🔴", "Suspicious": "🟠", "No red flags found": "🟢"}
    st.divider()
    st.subheader(f"{ICON[r.verdict]} {r.verdict} (risk score {r.score}/100)")
    if r.verdict == "No red flags found":
        st.caption("Nothing suspicious in the sender details or links. A real account can still be hacked, "
                   "so if the email asks for money, passwords or urgency, check with the sender another way.")

    def show_flag(f, note_icon=True):
        points = f" (+{f.points})" if f.points else ""
        icon = "ℹ️ " if note_icon and not f.points else ""
        st.markdown(f"**{icon}{safe_text(f.title)}**{points}  \n{safe_text(f.why)}")

    left, right = st.columns(2)
    with left:
        st.markdown("#### 🚩 Red flags")
        for area in ("Headers", "Links"):
            flags = sorted([f for f in r.flags if f.area == area], key=lambda f: -f.points)
            st.markdown(f"**{'From the sender details' if area == 'Headers' else 'From the links'}**")
            if not [f for f in flags if f.points]:
                st.caption("None found.")
            for f in flags:
                show_flag(f)
    with right:
        st.markdown("#### ✅ Good signs")
        if not r.good:
            st.caption("None.")
        for g in r.good:
            show_flag(g, note_icon=False)

    # ---------------------------------------------------------------- links
    st.subheader("Links")
    st.caption("Every link in the email, defanged so none can be clicked. They were read, not visited.")
    PROBLEM_NAMES = {
        "mismatch": "Text doesn't match", "at_trick": "@ trick", "lookalike": "Lookalike domain",
        "form": "Form in email", "risky_file": "Downloads a program", "ip_host": "Bare IP address",
        "punycode": "Disguised characters", "shortener": "Shortened link", "plain_http": "Not encrypted",
    }
    if r.links:
        st.dataframe([{
            "": "🚩" if [p for p in l.problems if p != "plain_http"] else "✅",
            "Shown to the reader": defang(l.shown) if l.shown else "(the address itself)",
            "Really goes to": defang(l.url) if l.url else "(no address)",
            "Found in": l.found_in,
            "Problems": ", ".join(PROBLEM_NAMES[p] for p in l.problems) or "None",
        } for l in r.links], hide_index=True)
    else:
        st.write("No links found.")

    # --------------------------------------------------------------- sender
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

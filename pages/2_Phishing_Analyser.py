"""
Module 2: Phishing Email Analyser

Upload a suspicious email (.eml) or paste its source, and see who really
sent it and where its links really go.

Part 1: headers, SPF, DKIM, DMARC and the route the email took.
Part 2: links.
Part 3: attachments.
Part 4: checking the IP, link domains and file hashes with Module 1's sources.
Finally, a case note to paste into a ticket.
"""

from dataclasses import replace
from pathlib import Path

import streamlit as st

from soc_toolkit.attachments import PROBLEM_LABELS as ATTACH_LABELS
from soc_toolkit.attachments import RTLO
from soc_toolkit.case_note import build_case_note
from soc_toolkit.config import is_public
from soc_toolkit.display import safe_text
from soc_toolkit.email_analyser import analyse_email
from soc_toolkit.email_intel import collect_iocs, intel_findings
from soc_toolkit.ioc import defang
from soc_toolkit.links import PROBLEM_LABELS as LINK_LABELS
from soc_toolkit.lookup import flagged_by, run_lookups, top_finding, within_public_limits
from soc_toolkit.phishing import MAX_EMAIL_BYTES

st.title("🎣 Phishing Email Analyser")
st.write(
    "Upload a suspicious email or paste its full source to see who really sent it, where its links go "
    "and what its attachments really are. "
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
    st.session_state["report_n"] = st.session_state.get("report_n", 0) + 1

report = st.session_state.get("report")
if report:
    # Threat-intel results belong to the email they were run for
    intel = st.session_state.get("intel")
    if intel and intel["report_n"] != st.session_state.get("report_n"):
        intel = None
    r = replace(report, flags=report.flags + intel["flags"], good=report.good + intel["good"]) if intel else report

    ICON = {"Likely phishing": "🔴", "Suspicious": "🟠", "No red flags found": "🟢"}
    st.divider()
    st.subheader(f"{ICON[r.verdict]} {r.verdict} (risk score {r.score}/100)")
    if r.verdict == "No red flags found":
        st.caption("Nothing suspicious in the sender details, links or attachments. A real account can still be hacked, "
                   "so if the email asks for money, passwords or urgency, check with the sender another way.")

    # ------------------------------------------------- threat intelligence
    ROLE_ICON = {"Malicious": "🔴", "Suspicious": "🟠", "Clean": "🟢", "Unknown": "⚪", "Internal": "🔵"}
    with st.container(border=True):
        st.markdown("#### 🔎 Threat intelligence")
        iocs, skipped = collect_iocs(report)
        if intel:
            st.dataframe([{
                "What": row["role"],
                "Indicator": f"{row['value'][:8]}…{row['value'][-8:]}" if row["type"] == "sha256" else defang(row["value"]),
                "Verdict": f"{ROLE_ICON.get(row['verdict'], '⚪')} {row['verdict']}",
                "Flagged by": flagged_by(row["results"]),
                "Top finding": top_finding(row["results"]) or "No source had any data",
            } for row in intel["rows"]], hide_index=True)
            st.caption("Results are included in the risk score above. Open IOC Enrichment for each source's full answer.")
        elif iocs:
            NAMES = {"ip": ("IP address", "IP addresses"), "domain": ("website", "websites"),
                     "sha256": ("file hash", "file hashes")}
            counts = {}
            for _, t, _ in iocs:
                counts[t] = counts.get(t, 0) + 1
            parts = [f"{n} {NAMES[t][n > 1]}" for t, n in counts.items()]
            listed = " and ".join([", ".join(parts[:-1]), parts[-1]] if len(parts) > 1 else parts)
            st.write(f"Check this email's {listed} against the threat-intel sources used by IOC Enrichment.")
            st.caption("Only these indicators are sent, never the email itself. "
                       + ("In the public version, add your own keys in the IOC Enrichment sidebar for more sources."
                          if is_public() else ""))
            if st.button("Check with threat intelligence", type="primary"):
                to_check = within_public_limits([(v, t) for v, t, _ in iocs])
                if to_check is not None:
                    rows = run_lookups(to_check)
                    roles = {v: role for v, _, role in iocs}
                    for row in rows:
                        row["role"] = roles[row["value"]]
                    flags, good = intel_findings(rows)
                    st.session_state["intel"] = {"report_n": st.session_state.get("report_n"), "rows": rows, "flags": flags, "good": good}
                    st.rerun()
        else:
            st.write("Nothing in this email can be looked up.")
        if skipped:
            with st.expander(f"Not checked ({len(skipped)})"):
                for item in skipped:
                    st.markdown(f"- {safe_text(item)}")

    # ------------------------------------------------------------ case note
    case_note = build_case_note(r, intel["rows"] if intel else None)
    with st.expander("📝 Case note for your ticket"):
        st.caption("Everything you'd write up by hand: verdict, recommended action, red flags and defanged "
                   "indicators. Copy it with the icon at the top right of the box, or download it. "
                   + ("" if intel else "Run the threat intelligence check first to include its results."))
        st.code(case_note, language=None, wrap_lines=True)
        st.download_button("Download case note (.txt)", case_note, file_name="phishing_case_note.txt",
                           mime="text/plain")

    def show_flag(f, note_icon=True):
        points = f" (+{f.points})" if f.points else ""
        icon = "ℹ️ " if note_icon and not f.points else ""
        st.markdown(f"**{icon}{safe_text(f.title)}**{points}  \n{safe_text(f.why)}")

    left, right = st.columns(2)
    with left:
        st.markdown("#### 🚩 Red flags")
        AREA_NAMES = {"Headers": "From the sender details", "Links": "From the links",
                      "Attachments": "From the attachments"}
        if intel:
            AREA_NAMES["Threat intel"] = "From threat intelligence"
        for area, label in AREA_NAMES.items():
            flags = sorted([f for f in r.flags if f.area == area], key=lambda f: -f.points)
            st.markdown(f"**{label}**")
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
    if r.links:
        st.dataframe([{
            "": "🚩" if [p for p in l.problems if p != "plain_http"] else "✅",
            "Shown to the reader": defang(l.shown) if l.shown else "(the address itself)",
            "Really goes to": defang(l.url) if l.url else "(no address)",
            "Found in": l.found_in,
            "Problems": ", ".join(LINK_LABELS[p] for p in l.problems) or "None",
        } for l in r.links], hide_index=True)
    else:
        st.write("No links found.")

    # ---------------------------------------------------------- attachments
    st.subheader("Attachments")
    st.caption("Each file's contents were read to see what it really is. Nothing was opened, run or saved.")

    def size(n):
        return f"{n / 1024:.1f} KB" if n >= 1024 else f"{n} bytes"

    if r.attachments:
        st.dataframe([{
            "": "🚩" if a.problems else "✅",
            "File name": a.name.replace(RTLO, "[hidden character]"),
            "Size": size(a.size),
            "Email says it is": a.declared_type,
            "Really is": a.real_type,
            "Problems": ", ".join(ATTACH_LABELS[p] for p in a.problems) or "None",
            "SHA256": f"{a.sha256[:12]}…",
        } for a in r.attachments], hide_index=True)
        with st.expander("File hashes, to check in IOC Enrichment"):
            st.caption("A hash is a file's fingerprint. Malware databases such as VirusTotal and MalwareBazaar "
                       "can tell you if they've seen this exact file before, without anyone opening it.")
            for a in r.attachments:
                st.markdown(f"**{safe_text(a.name.replace(RTLO, '[hidden character]'))}**")
                st.code(f"SHA256  {a.sha256}\nSHA1    {a.sha1}\nMD5     {a.md5}", language=None)
    else:
        st.write("No attachments.")

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
        st.caption("This is the IP that \"Check with threat intelligence\" looks up.")

    with st.expander("All headers (raw)"):
        st.code(r.raw_headers, language=None)

"""
Module 3: Log Parser

Upload a login log and see password attacks hidden in it: brute force,
password spraying, distributed attacks, username guessing and, most
importantly, a successful login after many failures.

Part 1: Linux auth.log (SSH).
Coming next: Windows Security events, a timeline chart, threat intelligence
and a case note.
"""

from datetime import datetime
from pathlib import Path

import streamlit as st

from soc_toolkit import logs
from soc_toolkit.config import is_public
from soc_toolkit.display import safe_text

st.title("📜 Log Parser")
st.write(
    "Upload a login log to find password attacks hidden among thousands of normal lines: "
    "brute force, password spraying, distributed attacks, username guessing, and logins that worked after many failures."
)

with st.expander("How do I get a Linux login log?"):
    st.markdown(
        "SSH logins are recorded in **/var/log/auth.log** on Ubuntu and Debian "
        "(**/var/log/secure** on Red Hat and CentOS). Copy it somewhere you can upload from:\n"
        "```bash\nsudo cp /var/log/auth.log ~/auth.log && sudo chown $USER ~/auth.log\n```\n"
        "On systems that use the journal instead:\n"
        "```bash\njournalctl -u ssh --since today > ~/ssh.log\n```\n"
        "Windows Security logs are coming in the next update."
    )

if is_public():
    st.info(
        "**Public version.** The log is processed in memory and not stored. Logs contain usernames and "
        "internal addresses, so don't upload logs from systems you're not allowed to share."
    )

SAMPLES = Path(__file__).parent.parent / "samples" / "logs"
EXAMPLES = {"attack": "linux_auth_attack.log", "normal": "linux_auth_normal.log"}


def load_sample(name):
    st.session_state["log_text"] = (SAMPLES / EXAMPLES[name]).read_text()
    st.session_state["log_year"] = 2026          # the samples are from November 2026
    st.session_state["log_upload_n"] = st.session_state.get("log_upload_n", 0) + 1


tab_upload, tab_paste = st.tabs(["Upload log file", "Paste log lines"])
with tab_upload:
    upload = st.file_uploader("Log file (up to 5 MB, about 50,000 lines)", type=["log", "txt"],
                              key=f"log_upload_{st.session_state.get('log_upload_n', 0)}")
    st.caption("If a file is uploaded, it's analysed instead of anything pasted.")
with tab_paste:
    st.text_area("Log lines", height=200, key="log_text")

if "log_year" not in st.session_state:
    st.session_state["log_year"] = datetime.now().year
year = st.number_input("Year the log is from", min_value=2000, max_value=2100, step=1, key="log_year",
                       help="Classic auth.log lines don't include the year (\"Nov 16 09:14:02\"), so it's needed "
                            "to put events on a timeline.")

c1, c2, c3 = st.columns([1, 2, 2])
run = c1.button("Analyse", type="primary")
c2.button("Load sample attack log", on_click=load_sample, args=("attack",))
c3.button("Load sample normal day", on_click=load_sample, args=("normal",))

if run:
    raw = upload.getvalue() if upload is not None else st.session_state.get("log_text", "").encode()
    if not raw.strip():
        st.warning("Upload a log file or paste some log lines first.")
        st.stop()
    if len(raw) > logs.MAX_LOG_BYTES:
        st.error("That log is larger than 5 MB. Split it into smaller files, for example one per day.")
        st.stop()
    report = logs.parse_linux_auth(raw.decode("utf-8", errors="replace"), year=int(year))
    if not report.events:
        st.warning("No SSH login lines were found. This part reads Linux auth.log files: lines like "
                   "\"sshd[1234]: Failed password for root from 203.0.113.5\". Windows logs are coming next.")
        st.stop()
    st.session_state["log_report"] = report

r = st.session_state.get("log_report")
if r:
    st.divider()
    worst = r.findings[0].severity if r.findings else None
    HEAD = {"Critical": "🔴 Likely compromise", "High": "🟠 Attack activity found",
            "Medium": "🟡 Suspicious activity found", None: "🟢 No attack patterns found"}
    st.subheader(f"{HEAD[worst]} ({len(r.findings)} finding{'s' if len(r.findings) != 1 else ''})")

    m = st.columns(5)
    m[0].metric("Login events", f"{len(r.events):,}")
    m[1].metric("Failed", f"{len(r.fails):,}")
    m[2].metric("Successful", f"{len(r.successes):,}")
    m[3].metric("Source addresses", len({e.ip for e in r.events}))
    m[4].metric("Accounts", len({e.user for e in r.events}))
    st.caption(f"{r.log_type}: {r.total_lines:,} lines read, from {r.start:%d %b %Y %H:%M} to "
               f"{r.end:%d %b %Y %H:%M}. Lines that aren't login attempts (cron jobs, sessions closing) are skipped.")

    # ------------------------------------------------------------ findings
    st.markdown("#### Findings")
    ICON = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "⚪"}
    if not r.findings:
        st.write("Nothing crossed the detection thresholds. A few failed logins followed by a success is normal: "
                 "people mistype passwords.")
    for f in r.findings:
        with st.container(border=True):
            st.markdown(f"{ICON[f.severity]} **{f.severity}: {safe_text(f.title)}**  \n{safe_text(f.why)}")
            st.caption(f"MITRE ATT&CK {f.technique}: {f.technique_name}")

    # ------------------------------------------------------- summary tables
    left, right = st.columns(2)
    with left:
        st.markdown("#### Source addresses")
        st.dataframe([{
            "Address": row["ip"],
            "Where": "Internal" if row["internal"] else "Internet",
            "Failed": row["fails"],
            "Successful": row["successes"],
            "Accounts tried": len(row["users"]),
            "First seen": f"{row['first']:%d %b %H:%M:%S}",
            "Last seen": f"{row['last']:%d %b %H:%M:%S}",
        } for row in logs.ip_summary(r)], hide_index=True)
    with right:
        st.markdown("#### Accounts")
        st.dataframe([{
            "Account": row["user"],
            "Exists": "No" if row["invalid"] else "Yes",
            "Failed": row["fails"],
            "Successful": row["successes"],
            "Addresses": len(row["ips"]),
        } for row in logs.user_summary(r)], hide_index=True)

    with st.expander("Detection thresholds"):
        st.markdown(
            f"- **Brute force:** {logs.BRUTE_FORCE_FAILS}+ failures on one account from one address within "
            f"{int(logs.BRUTE_FORCE_WINDOW.total_seconds() // 60)} minutes\n"
            f"- **Password spraying:** one address trying {logs.SPRAY_ACCOUNTS}+ real accounts within "
            f"{int(logs.SPRAY_WINDOW.total_seconds() // 60)} minutes, 3 or fewer attempts each\n"
            f"- **Distributed attack:** {logs.DISTRIBUTED_ADDRESSES}+ addresses failing on one account within "
            f"{int(logs.DISTRIBUTED_WINDOW.total_seconds() // 60)} minutes\n"
            f"- **Username guessing:** {logs.INVALID_USER_ATTEMPTS}+ attempts on accounts that don't exist\n"
            f"- **Success after failures:** a login that works within "
            f"{int(logs.SUCCESS_LOOKBACK.total_seconds() // 60)} minutes of {logs.SUCCESS_AFTER_FAILS}+ failures"
        )

    with st.expander(f"All login events ({len(r.events):,})"):
        st.dataframe([{
            "Time": f"{e.time:%d %b %H:%M:%S}", "Result": "✅ Success" if e.outcome == "success" else "❌ Failed",
            "Account": e.user + (" (doesn't exist)" if e.invalid_user else ""), "From": e.ip,
            "Method": e.method, "Server": e.host, "Line": e.line_no,
        } for e in r.events[:5000]], hide_index=True)
        if len(r.events) > 5000:
            st.caption("Showing the first 5,000 events.")

"""
Module 3: Log Parser

Upload a login log and see password attacks hidden in it: brute force,
password spraying, distributed attacks, username guessing and, most
importantly, a successful login after many failures.

Part 1: Linux auth.log (SSH).
Part 2: Windows Security events, from Event Viewer (XML) or a CSV.
Coming next: a timeline chart, threat intelligence and a case note.
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

with st.expander("How do I get a login log?"):
    linux, windows = st.tabs(["Linux", "Windows"])
    with linux:
        st.markdown(
            "SSH logins are recorded in **/var/log/auth.log** on Ubuntu and Debian "
            "(**/var/log/secure** on Red Hat and CentOS). Copy it somewhere you can upload from:\n"
            "```bash\nsudo cp /var/log/auth.log ~/auth.log && sudo chown $USER ~/auth.log\n```\n"
            "On systems that use the journal instead:\n"
            "```bash\njournalctl -u ssh --since today > ~/ssh.log\n```"
        )
    with windows:
        st.markdown(
            "**From Event Viewer (no extra tools):**\n"
            "1. Open **Event Viewer**, then **Windows Logs**, then **Security**.\n"
            "2. Click **Filter Current Log** and type `4624,4625,4740` in the Event IDs box.\n"
            "3. Click **Save Filtered Log File As**, and choose **XML** as the file type.\n\n"
            "**From a SIEM such as Splunk:** export the search results as CSV. Common field names are "
            "recognised, such as `EventCode`, `Account_Name`, `Source_Network_Address` and `Logon_Type`.\n\n"
            "Event IDs read: **4625** failed logon, **4624** successful logon, **4740** account locked out. "
            "Windows' own background logons (SYSTEM, computer accounts, services) are skipped."
        )

if is_public():
    st.info(
        "**Public version.** The log is processed in memory and not stored. Logs contain usernames and "
        "internal addresses, so don't upload logs from systems you're not allowed to share."
    )

SAMPLES = Path(__file__).parent.parent / "samples" / "logs"
EXAMPLES = {"attack": "linux_auth_attack.log", "normal": "linux_auth_normal.log",
            "Windows": "windows_security_attack.xml"}


def load_sample(name):
    st.session_state["log_text"] = (SAMPLES / EXAMPLES[name]).read_text()
    st.session_state["log_year"] = 2026          # the samples are from November 2026
    st.session_state["log_upload_n"] = st.session_state.get("log_upload_n", 0) + 1


tab_upload, tab_paste = st.tabs(["Upload log file", "Paste log lines"])
with tab_upload:
    upload = st.file_uploader("Log file (up to 5 MB): Linux auth.log, or Windows events as XML or CSV",
                              type=["log", "txt", "xml", "csv"],
                              key=f"log_upload_{st.session_state.get('log_upload_n', 0)}")
    st.caption("If a file is uploaded, it's analysed instead of anything pasted.")
with tab_paste:
    st.text_area("Log lines", height=200, key="log_text")

if "log_year" not in st.session_state:
    st.session_state["log_year"] = datetime.now().year
year = st.number_input("Year the log is from", min_value=2000, max_value=2100, step=1, key="log_year",
                       help="Only needed for Linux logs: classic auth.log lines don't include the year "
                            "(\"Nov 16 09:14:02\"). Windows events always carry the full date.")

c1, c2, c3, c4 = st.columns([1, 2, 2, 2])
run = c1.button("Analyse", type="primary")
c2.button("Sample Linux attack", on_click=load_sample, args=("attack",))
c3.button("Sample Linux normal day", on_click=load_sample, args=("normal",))
c4.button("Sample Windows attack", on_click=load_sample, args=("Windows",))

if run:
    raw = upload.getvalue() if upload is not None else st.session_state.get("log_text", "").encode()
    if not raw.strip():
        st.warning("Upload a log file or paste some log lines first.")
        st.stop()
    if len(raw) > logs.MAX_LOG_BYTES:
        st.error("That log is larger than 5 MB. Split it into smaller files, for example one per day.")
        st.stop()
    try:
        report = logs.parse_log(raw, year=int(year))
    except Exception:
        st.error("That file couldn't be read. If it's a Windows XML export, check it was saved from Event "
                 "Viewer as XML and not as .evtx.")
        st.stop()
    if not report.events and not report.lockouts:
        st.warning("No login events were found. The Log Parser reads Linux auth.log files (lines like "
                   "\"sshd[1234]: Failed password for root from 203.0.113.5\") and Windows Security events "
                   "4624, 4625 and 4740 as XML or CSV. See \"How do I get a login log?\" above.")
        st.stop()
    st.session_state["log_report"] = report

r = st.session_state.get("log_report")
if r:
    st.divider()
    worst = r.findings[0].severity if r.findings else None
    HEAD = {"Critical": "🔴 Likely compromise", "High": "🟠 Attack activity found",
            "Medium": "🟡 Suspicious activity found", None: "🟢 No attack patterns found"}
    st.subheader(f"{HEAD[worst]} ({len(r.findings)} finding{'s' if len(r.findings) != 1 else ''})")

    m = st.columns(6 if r.lockouts else 5)
    m[0].metric("Login events", f"{len(r.events):,}")
    m[1].metric("Failed", f"{len(r.fails):,}")
    m[2].metric("Successful", f"{len(r.successes):,}")
    m[3].metric("Source addresses", len({e.ip for e in r.events}))
    m[4].metric("Accounts", len({e.user for e in r.events}))
    if r.lockouts:
        m[5].metric("Lockouts", len(r.lockouts))
    unit = "events" if r.log_type.startswith("Windows") else "lines"
    skipped = ("Windows' own background logons (SYSTEM, computer accounts, services) are skipped."
               if unit == "events" else "Lines that aren't login attempts (cron jobs, sessions closing) are skipped.")
    st.caption(f"{r.log_type}: {r.total_lines:,} {unit} read, from {r.start:%d %b %Y %H:%M} to "
               f"{r.end:%d %b %Y %H:%M}. {skipped}")

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
            f"{int(logs.SUCCESS_LOOKBACK.total_seconds() // 60)} minutes of {logs.SUCCESS_AFTER_FAILS}+ failures\n"
            f"- **Lockouts (Windows):** {logs.LOCKOUT_ACCOUNTS}+ accounts locked out within "
            f"{int(logs.LOCKOUT_WINDOW.total_seconds() // 60)} minutes; a single lockout is noted as Low"
        )

    with st.expander(f"All login events ({len(r.events):,})"):
        st.dataframe([{
            "Time": f"{e.time:%d %b %H:%M:%S}", "Result": "✅ Success" if e.outcome == "success" else "❌ Failed",
            "Account": e.user + (" (doesn't exist)" if e.invalid_user else ""), "From": e.ip,
            "Method": e.method, "Server": e.host, ("Line" if unit == "lines" else "Event"): e.line_no,
        } for e in r.events[:5000]], hide_index=True)
        if len(r.events) > 5000:
            st.caption("Showing the first 5,000 events.")

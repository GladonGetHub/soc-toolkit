"""
Log Parser, part 4: threat intelligence and the case note.

The log tells you WHAT an address did on your server. Threat intelligence
tells you whether the rest of the internet has seen it doing the same
elsewhere. An address already reported thousands of times for attacks is a
scanner or botnet, not a lost employee.

This file picks which addresses to look up, turns what the sources say into
findings, and writes the case note for the ticket.
"""

import re
from datetime import datetime, timezone

from . import __version__
from .email_intel import _is_test_ip
from .ioc import defang, detect_type, is_private_ip
from .logs import SEVERITY_ORDER, Finding, LogReport, ip_summary

MAX_LOOKUPS = 10
IPV4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])")


def collect_log_iocs(report: LogReport) -> tuple[list[tuple[str, str, str]], list[str]]:
    """
    Addresses worth looking up: those named in a finding first (worst first),
    then the busiest other internet addresses. Returns (indicators, skipped),
    each indicator being (address, "ip", what it did).
    """
    did = {}
    for f in sorted(report.findings, key=lambda f: SEVERITY_ORDER[f.severity]):
        for ip in f.ips:
            did.setdefault(ip, f.title)
    for row in ip_summary(report):
        if row["fails"]:
            did.setdefault(row["ip"], f"{row['fails']} failed logins")

    iocs, skipped = [], []
    for ip, what in did.items():
        if detect_type(ip) != "ip":
            continue                      # a computer name, e.g. the caller in a Windows lockout
        if is_private_ip(ip):
            skipped.append(f"{ip}: an internal address, so it's not sent outside")
        elif _is_test_ip(ip):
            skipped.append(f"{ip}: a documentation address used in examples, so there's nothing to look up")
        elif len(iocs) < MAX_LOOKUPS:
            iocs.append((ip, "ip", what))
        else:
            skipped.append(f"{ip}: over the limit of {MAX_LOOKUPS} lookups")
    return iocs, skipped


def intel_to_findings(rows: list[dict]) -> list[Finding]:
    """
    rows: [{"value", "verdict", "role", "results"}] from the lookups.
    A known-bad address becomes a finding, so it shows up with the others.
    """
    findings = []
    for row in rows:
        scored = [x for x in row["results"] if x["score"] is not None]
        if row["verdict"] not in ("Malicious", "Suspicious") or not scored:
            continue
        best = max(scored, key=lambda x: x["score"])
        bad = sum(x["score"] >= 50 for x in scored)
        findings.append(Finding(
            "High" if row["verdict"] == "Malicious" else "Medium",
            f"{row['value']} is a known {'attacker' if row['verdict'] == 'Malicious' else 'suspicious address'}",
            f"Threat intelligence rates {row['value']} {row['verdict']}, flagged by {bad} of {len(scored)} sources. "
            f"Top finding: {best['provider']}: {best['summary']}. In this log: {row['role']}.",
            "", [row["value"]], [], bad))
    return findings


# ----------------------------------------------------------------- case note
ACTIONS = {
    "Critical": [
        "Treat the account(s) that logged in as compromised: reset the password or disable the account, "
        "and end its sessions.",
        "Block the attacking address(es) at the firewall.",
        "Find out what happened after the login. Linux: shell history, new users, new SSH keys in "
        "~/.ssh/authorized_keys, cron jobs, unusual processes and outbound connections. Windows: new local "
        "admins, services, scheduled tasks and RDP sessions.",
        "Search other servers' logs for the same address and account.",
        "Close the door: SSH keys instead of passwords, no direct root or Administrator login, MFA, and "
        "RDP only through a VPN.",
    ],
    "High": [
        "Block the attacking address(es) at the firewall.",
        "Check none of the targeted accounts logged in from an unusual place afterwards.",
        "Unlock and reset any locked accounts only after confirming with their owners.",
        "Reduce exposure: SSH keys instead of passwords, fail2ban or account lockout, MFA, and no "
        "internet-facing RDP.",
    ],
    "Medium": [
        "Consider blocking the address(es).",
        "Check the accounts being guessed: a list of real usernames may have leaked.",
    ],
    "Low": [
        "Confirm the lockout with the user; usually a forgotten or recently changed password.",
    ],
    None: [
        "No action needed: nothing crossed the detection thresholds.",
    ],
}
HEADLINE = {"Critical": "Likely compromise", "High": "Attack activity found",
            "Medium": "Suspicious activity found", "Low": "Minor activity found", None: "No attack patterns found"}


def build_log_case_note(report: LogReport, findings: list[Finding], intel_rows: list | None = None,
                        when: datetime | None = None) -> str:
    """Plain text for a ticket. Internet addresses are defanged so they can't be clicked."""
    when = when or datetime.now(timezone.utc)
    worst = findings[0].severity if findings else None

    def show(ip):
        return ip if is_private_ip(ip) or detect_type(ip) != "ip" else defang(ip)

    def safe(text):
        """Defang every internet IPv4 address in a sentence; internal ones stay as they are."""
        return IPV4.sub(lambda m: show(m.group(0)), text)

    lines = [
        "LOGIN LOG ANALYSIS - CASE NOTE",
        f"Generated by SOC Toolkit v{__version__} on {when:%d %b %Y %H:%M} UTC",
        "",
        f"VERDICT: {HEADLINE[worst]} ({len(findings)} finding{'s' if len(findings) != 1 else ''})",
        "",
        "RECOMMENDED ACTION",
        *[f"- {a}" for a in ACTIONS[worst]],
        "",
        "LOG",
        f"Type:       {report.log_type}",
        f"Period:     {report.start:%d %b %Y %H:%M} to {report.end:%d %b %Y %H:%M}" if report.start else "Period:     -",
        f"Logins:     {len(report.events)} ({len(report.fails)} failed, {len(report.successes)} successful)"
        + (f", {len(report.lockouts)} lockouts" if report.lockouts else ""),
        f"Servers:    {', '.join(sorted({e.host for e in report.events if e.host})[:5]) or '-'}",
        "",
        "FINDINGS",
    ]
    for f in findings:
        mitre = f" [MITRE {f.technique} {f.technique_name}]" if f.technique else ""
        lines.append(f"- {f.severity.upper()}: {safe(f.title)}.{mitre} {safe(f.why)}")
    if not findings:
        lines.append("- None.")

    lines += ["", "ADDRESSES (internet addresses defanged)",
              f"{'Address':<22} {'Where':<9} {'Failed':>6} {'OK':>4} {'Accounts':>8}  First seen -> last seen"]
    for row in ip_summary(report)[:15]:
        lines.append(f"{show(row['ip']):<22} {'Internal' if row['internal'] else 'Internet':<9} {row['fails']:>6} "
                     f"{row['successes']:>4} {len(row['users']):>8}  {row['first']:%d %b %H:%M:%S} -> {row['last']:%H:%M:%S}")

    lines += ["", "THREAT INTELLIGENCE"]
    if intel_rows:
        for row in intel_rows:
            scored = [x for x in row["results"] if x["score"] is not None]
            best = max(scored, key=lambda x: x["score"]) if scored else None
            finding = f" - {best['provider']}: {best['summary']}" if best else " - no source had data"
            lines.append(f"- {defang(row['value'])}: {row['verdict']} "
                         f"({sum(x['score'] >= 50 for x in scored)} of {len(scored)} sources){finding}")
    else:
        lines.append("- Not run. Use \"Check with threat intelligence\" to add it.")

    lines += ["", "ANALYST NOTES", "- ", ""]
    return "\n".join(lines)

"""
Log Parser: reading login logs and spotting password attacks.

Part 1: Linux auth.log (SSH).
Part 2: Windows Security events (4625 failed, 4624 successful, 4740 locked out),
from an Event Viewer XML export or a CSV from PowerShell or a SIEM.

Every login attempt leaves a line in a log, like a signature in a building's
visitor book. One failed login is a typo. Hundreds from the same address in a
few minutes is a machine guessing passwords, and a success at the end means
the guess worked.

This file reads the lines (parse), then looks for the patterns an analyst
would hunt for by hand (detect). Each finding is mapped to MITRE ATT&CK
T1110 (Brute Force) and its sub-techniques.
"""

import csv
import io
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .ioc import is_private_ip

MAX_LOG_BYTES = 5 * 1024 * 1024  # about 50,000 lines of auth.log

# ------------------------------------------------------------------ settings
# How many attempts, in how long, before something counts as an attack.
# Kept in one place so they're easy to explain and to tune.
BRUTE_FORCE_FAILS = 10          # failed logins on ONE account from ONE address...
BRUTE_FORCE_WINDOW = timedelta(minutes=10)            # ...within 10 minutes
SPRAY_ACCOUNTS = 5              # ONE address trying 5+ different accounts...
SPRAY_WINDOW = timedelta(minutes=30)                  # ...within 30 minutes
DISTRIBUTED_ADDRESSES = 5       # 5+ different addresses failing on ONE account...
DISTRIBUTED_WINDOW = timedelta(minutes=30)            # ...within 30 minutes
INVALID_USER_ATTEMPTS = 5       # 5+ guesses at accounts that don't exist
LOCKOUT_ACCOUNTS = 3            # 3+ different accounts locked out within 30 minutes
LOCKOUT_WINDOW = timedelta(minutes=30)
SUCCESS_LOOKBACK = timedelta(minutes=60)              # a success within an hour of...
SUCCESS_AFTER_FAILS = 10        # ...10+ failures counts as a likely compromise
                                # (a person who mistypes a few times shouldn't trigger it)

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
MITRE = {
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1110": "Brute Force",
    "T1078": "Valid Accounts",
}


@dataclass
class LoginEvent:
    time: datetime
    host: str
    user: str
    ip: str
    outcome: str              # "fail" or "success"
    invalid_user: bool = False
    method: str = ""          # password, publickey, RDP, Network ...
    line_no: int = 0


@dataclass
class Finding:
    severity: str             # Critical, High, Medium, Low
    title: str
    why: str                  # plain-English explanation
    technique: str            # MITRE ATT&CK id, e.g. T1110.001
    ips: list = field(default_factory=list)
    users: list = field(default_factory=list)
    count: int = 0
    first: datetime | None = None
    last: datetime | None = None

    @property
    def technique_name(self) -> str:
        return MITRE.get(self.technique, "")


@dataclass
class LogReport:
    log_type: str = ""
    total_lines: int = 0
    events: list = field(default_factory=list)
    lockouts: list = field(default_factory=list)   # Windows 4740 (account locked out)
    findings: list = field(default_factory=list)
    skipped_lines: int = 0    # lines that aren't login events (most of a log)

    @property
    def fails(self):
        return [e for e in self.events if e.outcome == "fail"]

    @property
    def successes(self):
        return [e for e in self.events if e.outcome == "success"]

    @property
    def start(self):
        return min((e.time for e in self.events + self.lockouts), default=None)

    @property
    def end(self):
        return max((e.time for e in self.events + self.lockouts), default=None)


# ------------------------------------------------------------------- parsing
# Two timestamp styles: classic "Nov 16 09:14:02" (no year!) and the newer
# ISO style "2026-11-16T09:14:02.123456+00:00" used by recent Ubuntu.
CLASSIC = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<rest>.*)$")
ISO = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\s+(?P<host>\S+)\s+(?P<rest>.*)$")

SSHD = re.compile(r"^sshd(?:-session)?\[\d+\]:\s+(?P<msg>.*)$")
FAILED = re.compile(r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.*?) from (?P<ip>[0-9a-fA-F:.]+)")
ACCEPTED = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
REPEATED = re.compile(r"^message repeated (?P<n>\d+) times: \[\s*(?P<msg>.*?)\s*\]$")


def _timestamp(ts: str, year: int) -> datetime | None:
    try:
        if "T" in ts:
            return datetime.fromisoformat(ts)
        return datetime.strptime(f"{year} {' '.join(ts.split())}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def parse_linux_auth(text: str, year: int | None = None) -> LogReport:
    """
    Read a Linux auth.log (or journalctl output for sshd) into login events.

    Classic syslog lines have no year, so `year` says which year the log is
    from (default: this year).
    """
    year = year or datetime.now().year
    report = LogReport(log_type="Linux auth.log (SSH)")
    lines = text.splitlines()
    report.total_lines = len(lines)

    for n, line in enumerate(lines, start=1):
        m = ISO.match(line) or CLASSIC.match(line)
        sshd = SSHD.match(m.group("rest")) if m else None
        if not sshd:
            report.skipped_lines += 1
            continue
        when = _timestamp(m.group("ts"), year)
        if when is None:
            report.skipped_lines += 1
            continue
        when = when.replace(tzinfo=None)
        msg, repeat = sshd.group("msg"), 1
        rep = REPEATED.match(msg)
        if rep:   # "message repeated 5 times: [ Failed password ... ]"
            msg, repeat = rep.group("msg"), int(rep.group("n"))

        event = None
        if f := FAILED.match(msg):
            event = LoginEvent(when, m.group("host"), f.group("user"), f.group("ip"), "fail",
                               invalid_user=bool(f.group("invalid")), method=f.group("method"), line_no=n)
        elif a := ACCEPTED.match(msg):
            event = LoginEvent(when, m.group("host"), a.group("user"), a.group("ip"), "success",
                               method=a.group("method"), line_no=n)
        # "Invalid user X from ..." lines are skipped on purpose: sshd follows each
        # one with "Failed password for invalid user X", which is what we count.
        if event is None:
            report.skipped_lines += 1
            continue
        report.events.extend([event] * repeat)

    return _finish(report)


# ----------------------------------------------------------------- detection
def _busiest_window(times: list[datetime], window: timedelta) -> tuple[int, datetime | None, datetime | None]:
    """The most events inside any stretch of `window`, and when it ran from and to."""
    times = sorted(times)
    best, start, end, left = 0, None, None, 0
    for right, t in enumerate(times):
        while t - times[left] > window:
            left += 1
        if right - left + 1 > best:
            best, start, end = right - left + 1, times[left], t
    return best, start, end


def _spread(events, key, window) -> tuple[int, list, datetime | None, datetime | None]:
    """
    The most distinct values of `key` (e.g. accounts) seen inside any stretch
    of `window`. Returns (count, the values, start, end).
    """
    events = sorted(events, key=lambda e: e.time)
    seen = defaultdict(int)          # value -> how many times it's in the window now
    best, best_vals, start, end, left = 0, [], None, None, 0
    for e in events:
        seen[key(e)] += 1
        while e.time - events[left].time > window:
            old = key(events[left])
            seen[old] -= 1
            if not seen[old]:
                del seen[old]
            left += 1
        if len(seen) > best:
            best, best_vals, start, end = len(seen), sorted(seen), events[left].time, e.time
    return best, best_vals, start, end


def _fmt(t: datetime) -> str:
    return t.strftime("%d %b %H:%M:%S")


def _minutes(a: datetime, b: datetime) -> str:
    mins = max(1, round((b - a).total_seconds() / 60))
    return f"{mins} minute{'s' if mins != 1 else ''}"


def detect(events: list[LoginEvent], lockouts: list[LoginEvent] | None = None) -> list[Finding]:
    fails = [e for e in events if e.outcome == "fail"]
    successes = [e for e in events if e.outcome == "success"]
    findings = []

    by_ip_user, by_ip, by_user = defaultdict(list), defaultdict(list), defaultdict(list)
    for e in fails:
        by_ip_user[(e.ip, e.user)].append(e)
        by_ip[e.ip].append(e)
        by_user[e.user].append(e)

    # 1. Brute force: one address hammering one account
    for (ip, user), evs in by_ip_user.items():
        n, start, end = _busiest_window([e.time for e in evs], BRUTE_FORCE_WINDOW)
        if n >= BRUTE_FORCE_FAILS:
            findings.append(Finding(
                "High", f"Brute force on '{user}'",
                f"{ip} failed to log in as '{user}' {n} times in {_minutes(start, end)} "
                f"({_fmt(start)} to {_fmt(end)}). A person mistypes a few times; a script guesses hundreds.",
                "T1110.001", [ip], [user], n, start, end))

    # 2. Password spraying: one address, many REAL accounts, a few tries each.
    # Guesses at accounts that don't exist are left out: they get their own finding (4).
    for ip, evs in by_ip.items():
        evs = [e for e in evs if not e.invalid_user]
        n, users, start, end = _spread(evs, lambda e: e.user, SPRAY_WINDOW)
        if n >= SPRAY_ACCOUNTS:
            # Count every attempt in the 30 minutes from the start, not only up to
            # the moment the 5th account was reached
            window = [e for e in evs if start <= e.time <= start + SPRAY_WINDOW]
            tries, end = len(window), window[-1].time
            per_user = tries / n
            if per_user <= 3:
                each = f"{per_user:.0f} attempt{'s' if round(per_user) != 1 else ''}"
                findings.append(Finding(
                    "High", "Password spraying",
                    f"{ip} tried {n} different accounts with only {each} each, in "
                    f"{_minutes(start, end)}. Spraying tries one common password on many accounts, keeping "
                    "each account under its lockout limit.",
                    "T1110.003", [ip], users, tries, start, end))
            else:
                findings.append(Finding(
                    "High", f"Brute force across {n} accounts",
                    f"{ip} made {tries} failed attempts across {n} accounts in {_minutes(start, end)}.",
                    "T1110.001", [ip], users, tries, start, end))

    # 3. Distributed attack: many addresses, one account
    for user, evs in by_user.items():
        n, ips, start, end = _spread(evs, lambda e: e.ip, DISTRIBUTED_WINDOW)
        if n >= DISTRIBUTED_ADDRESSES:
            # Report the whole attack from these addresses, not just its busiest stretch
            attack = [e for e in evs if e.ip in ips]
            tries, start, end = len(attack), attack[0].time, attack[-1].time
            findings.append(Finding(
                "High", f"Distributed attack on '{user}'",
                f"{n} different addresses failed to log in as '{user}' ({tries} attempts in "
                f"{_minutes(start, end)}). Spreading guesses across many addresses avoids per-address blocking.",
                "T1110", ips, [user], tries, start, end))

    # 4. Guessing usernames that don't exist
    invalid_by_ip = defaultdict(list)
    for e in fails:
        if e.invalid_user:
            invalid_by_ip[e.ip].append(e)
    for ip, evs in invalid_by_ip.items():
        if len(evs) >= INVALID_USER_ATTEMPTS:
            names = sorted({e.user for e in evs})
            shown = ", ".join(names[:6]) + (f" and {len(names) - 6} more" if len(names) > 6 else "")
            findings.append(Finding(
                "Medium", "Guessing usernames that don't exist",
                f"{ip} tried {len(evs)} logins with usernames this server doesn't have ({shown}). "
                "Attackers work through lists of common names like admin, test and oracle.",
                "T1110.001", [ip], names, len(evs), evs[0].time, evs[-1].time))

    # 5. The one that matters most: a success after the failures
    for s in successes:
        since = s.time - SUCCESS_LOOKBACK
        same_ip = [e for e in by_ip.get(s.ip, []) if since <= e.time <= s.time]
        same_user = [e for e in by_user.get(s.user, []) if since <= e.time <= s.time]
        if len(same_ip) >= SUCCESS_AFTER_FAILS:
            findings.append(Finding(
                "Critical", f"Successful login after {len(same_ip)} failures",
                f"{s.ip} logged in as '{s.user}' at {_fmt(s.time)} ({s.method}), after {len(same_ip)} failed "
                f"attempts from the same address in the hour before. The attacker probably got in.",
                "T1078", [s.ip], [s.user], len(same_ip), same_ip[0].time, s.time))
        elif len(same_user) >= SUCCESS_AFTER_FAILS:
            ips = sorted({e.ip for e in same_user})
            findings.append(Finding(
                "Critical", f"'{s.user}' logged in during an attack",
                f"'{s.user}' logged in from {s.ip} at {_fmt(s.time)}, while {len(same_user)} failed attempts "
                f"from {len(ips)} address(es) were hitting that account. Check this login was really them.",
                "T1078", [s.ip] + [i for i in ips if i != s.ip], [s.user], len(same_user), same_user[0].time, s.time))

    # 6. Windows account lockouts (4740): one is often a forgotten password;
    # several accounts locking at once is a sign of spraying or brute force
    lockouts = lockouts or []
    if lockouts:
        n, users, start, end = _spread(lockouts, lambda e: e.user, LOCKOUT_WINDOW)
        clustered = set()
        if n >= LOCKOUT_ACCOUNTS:
            clustered = set(users)
            callers = sorted({e.ip for e in lockouts if e.user in clustered and e.ip})
            findings.append(Finding(
                "High", f"{n} accounts locked out",
                f"{n} different accounts were locked out within {_minutes(start, end)} ({', '.join(users[:6])})"
                + (f", from {', '.join(callers[:3])}" if callers else "") + ". "
                "One lockout is usually a forgotten password; several at once means someone is guessing.",
                "T1110", callers, users, n, start, end))
        # Lockouts outside that cluster: on their own, often just a forgotten password
        for user in sorted({e.user for e in lockouts} - clustered):
            evs = [e for e in lockouts if e.user == user]
            findings.append(Finding(
                "Low", f"'{user}' was locked out",
                (f"'{user}' was locked out at {_fmt(evs[0].time)}. " if len(evs) == 1 else
                 f"'{user}' was locked out {len(evs)} times, first at {_fmt(evs[0].time)}. ")
                + "Often a forgotten or recently changed password; "
                "check it against the failed logins above.",
                "T1110", [], [user], len(evs), evs[0].time, evs[-1].time))

    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], -(f.count or 0)))
    return findings


# ------------------------------------------------------------------- Windows
# Windows writes a Security event for every logon:
#   4625 = failed logon, 4624 = successful logon, 4740 = account locked out.
# Each event has named fields such as TargetUserName (the account),
# IpAddress (where it came from) and LogonType (how they tried to log in).
LOGON_TYPES = {
    "2": "Interactive (at the keyboard)", "3": "Network", "4": "Batch", "5": "Service",
    "7": "Unlock", "8": "Network (clear text)", "9": "New credentials", "10": "RDP (Remote Desktop)",
    "11": "Cached",
}
# Logons Windows makes for itself all day long; they'd drown the real ones
NOISE_TYPES = {"0", "4", "5"}
NOISE_ACCOUNTS = {"system", "local service", "network service", "anonymous logon", "-", ""}
NOISE_PREFIXES = ("dwm-", "umfd-", "font driver host")
# Why a 4625 failed. 0xC0000064 means the account doesn't exist.
FAILURE_REASONS = {
    "0xc0000064": "account doesn't exist", "0xc000006a": "wrong password",
    "0xc0000234": "account locked", "0xc0000072": "account disabled",
    "0xc000006f": "outside allowed hours", "0xc0000071": "password expired",
    "0xc0000193": "account expired", "0xc0000133": "clock out of sync",
}

# Different tools name the same field differently. Each list holds the names
# used by Event Viewer, PowerShell, Splunk and other SIEMs.
FIELD_NAMES = {
    "time": ["timecreated", "systemtime", "_time", "time", "timestamp", "date and time", "datetime", "@timestamp", "eventtime"],
    "event_id": ["eventid", "event_id", "eventcode", "id", "event id", "event_code"],
    "user": ["targetusername", "target_user_name", "account_name", "user", "username", "accountname", "targetuser"],
    "ip": ["ipaddress", "ip_address", "source_network_address", "src_ip", "sourceip", "source ip", "clientip", "src"],
    "logon_type": ["logontype", "logon_type"],
    "status": ["substatus", "sub_status", "status", "failure_code"],
    "host": ["computer", "computername", "machinename", "host", "hostname", "workstationname", "dest"],
}


def decode_log(raw: bytes) -> str:
    """Windows exports are often UTF-16; Linux logs are UTF-8."""
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace")
    if raw[:200].count(b"\x00") > 50:          # UTF-16 without the marker
        return raw.decode("utf-16-le", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


def _win_time(value: str) -> datetime | None:
    value = (value or "").strip().replace("Z", "+00:00")
    value = re.sub(r"(\.\d{6})\d+", r"\1", value)       # 7-digit fractions -> 6
    for attempt in (value, value.replace(" ", "T", 1)):
        try:
            return datetime.fromisoformat(attempt).replace(tzinfo=None)
        except ValueError:
            pass
    for fmt in ("%d/%m/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(value.split("+")[0].strip(), fmt)
        except ValueError:
            pass
    return None


def _win_event(fields: dict, line_no: int) -> tuple[str, LoginEvent | None]:
    """Turn one Windows event's fields into ("login" | "lockout" | "skip", event)."""
    event_id = str(fields.get("event_id", "")).strip()
    when = _win_time(fields.get("time", ""))
    if event_id not in ("4624", "4625", "4740") or when is None:
        return "skip", None
    user = (fields.get("user") or "").strip()
    host = (fields.get("host") or "").strip()
    if event_id == "4740":
        # The locked account; the "caller computer" is where the bad attempts came from
        return "lockout", LoginEvent(when, host, user, (fields.get("caller") or "").strip(), "lockout", line_no=line_no)

    ip = (fields.get("ip") or "").strip()
    logon_type = str(fields.get("logon_type") or "").strip()
    lowered = user.lower()
    if (logon_type in NOISE_TYPES or lowered in NOISE_ACCOUNTS or lowered.endswith("$")
            or lowered.startswith(NOISE_PREFIXES)):
        return "skip", None
    if ip in ("-", "", "::1"):
        ip = "127.0.0.1" if ip == "::1" else f"(local: {host or 'this computer'})"
    method = LOGON_TYPES.get(logon_type, f"Logon type {logon_type}" if logon_type else "")
    if event_id == "4624":
        return "login", LoginEvent(when, host, user, ip, "success", method=method, line_no=line_no)
    status = (fields.get("status") or "").strip().lower()
    return "login", LoginEvent(when, host, user, ip, "fail", invalid_user=status == "0xc0000064",
                               method=method, line_no=line_no)


def _finish(report: LogReport) -> LogReport:
    report.events.sort(key=lambda e: e.time)
    report.lockouts.sort(key=lambda e: e.time)
    report.findings = detect(report.events, report.lockouts)
    return report


def parse_windows_xml(text: str) -> LogReport:
    """Read events saved from Event Viewer as XML ("Save ... As", XML)."""
    report = LogReport(log_type="Windows Security events (XML)")
    body = re.sub(r"^\s*<\?xml[^>]*\?>", "", text)
    body = re.sub(r"""\sxmlns=(["'])[^"']+\1""", "", body)   # drop the namespace so tags read simply
    root = ET.fromstring(f"<root>{body}</root>")
    events = root.iter("Event")
    for n, ev in enumerate(events, start=1):
        report.total_lines += 1
        data = {d.get("Name", "").lower(): (d.text or "") for d in ev.iter("Data")}
        created = ev.find("System/TimeCreated")
        fields = {
            "event_id": (ev.findtext("System/EventID") or "").strip(),
            "time": created.get("SystemTime", "") if created is not None else "",
            "host": ev.findtext("System/Computer") or "",
            "user": data.get("targetusername", ""),
            "ip": data.get("ipaddress", ""),
            "logon_type": data.get("logontype", ""),
            "status": data.get("substatus") or data.get("status", ""),
            # 4740 puts the computer the bad attempts came from in TargetDomainName
            "caller": data.get("targetdomainname", ""),
        }
        kind, event = _win_event(fields, n)
        if kind == "login":
            report.events.append(event)
        elif kind == "lockout":
            report.lockouts.append(event)
        else:
            report.skipped_lines += 1
    return _finish(report)


def parse_windows_csv(text: str) -> LogReport:
    """Read a CSV of Windows logon events, from PowerShell or a SIEM such as Splunk."""
    report = LogReport(log_type="Windows Security events (CSV)")
    rows = csv.DictReader(io.StringIO(text))
    names = {h.strip().lower(): h for h in (rows.fieldnames or [])}
    column = {key: next((names[c] for c in options if c in names), None) for key, options in FIELD_NAMES.items()}
    for n, row in enumerate(rows, start=2):
        report.total_lines += 1
        fields = {key: row.get(col, "") if col else "" for key, col in column.items()}
        fields["caller"] = row.get(names.get("callercomputername", ""), "") if "callercomputername" in names else ""
        kind, event = _win_event(fields, n)
        if kind == "login":
            report.events.append(event)
        elif kind == "lockout":
            report.lockouts.append(event)
        else:
            report.skipped_lines += 1
    return _finish(report)


def parse_log(raw: bytes, year: int | None = None) -> LogReport:
    """Work out what kind of log this is, then read it."""
    text = decode_log(raw)
    start = text.lstrip()[:2000].lower()
    if start.startswith("<") and "<event" in start:
        return parse_windows_xml(text)
    first_line = start.splitlines()[0] if start else ""
    headers = {h.strip().strip('"').strip() for h in first_line.split(",")}
    if headers & set(FIELD_NAMES["event_id"]):
        return parse_windows_csv(text)
    return parse_linux_auth(text, year)


# ---------------------------------------------------------------- summaries
def ip_summary(report: LogReport) -> list[dict]:
    """One row per source address: fails, successes, accounts tried, first and last seen."""
    rows = defaultdict(lambda: {"fails": 0, "successes": 0, "users": set(), "first": None, "last": None})
    for e in report.events:
        r = rows[e.ip]
        r["fails" if e.outcome == "fail" else "successes"] += 1
        r["users"].add(e.user)
        r["first"] = min(r["first"] or e.time, e.time)
        r["last"] = max(r["last"] or e.time, e.time)
    out = [{"ip": ip, "internal": is_private_ip(ip), **r, "users": sorted(r["users"])} for ip, r in rows.items()]
    return sorted(out, key=lambda r: (-r["fails"], -r["successes"]))


def user_summary(report: LogReport) -> list[dict]:
    """One row per account: fails, successes, addresses it was tried from."""
    rows = defaultdict(lambda: {"fails": 0, "successes": 0, "ips": set(), "invalid": False})
    for e in report.events:
        r = rows[e.user]
        r["fails" if e.outcome == "fail" else "successes"] += 1
        r["ips"].add(e.ip)
        r["invalid"] = r["invalid"] or e.invalid_user
    out = [{"user": u, **r, "ips": sorted(r["ips"])} for u, r in rows.items()]
    return sorted(out, key=lambda r: (-r["fails"], -r["successes"]))


# ------------------------------------------------------------------ timeline
# Bucket sizes to choose from, in minutes. The smallest one that gives no more
# than MAX_BUCKETS bars is used, so a 10-minute attack and a month of logs
# both make a readable chart.
BUCKET_CHOICES = [1, 5, 15, 30, 60, 180, 360, 1440]
MAX_BUCKETS = 150


def bucket_size(start: datetime, end: datetime) -> int:
    span = max((end - start).total_seconds() / 60, 1)
    return next((b for b in BUCKET_CHOICES if span / b <= MAX_BUCKETS), BUCKET_CHOICES[-1])


def _floor(t: datetime, minutes: int) -> datetime:
    """Round a time down to the start of its bucket (e.g. 09:14 -> 09:10 for 5-minute buckets)."""
    since_midnight = t.hour * 60 + t.minute
    floored = since_midnight - since_midnight % minutes if minutes < 1440 else 0
    return t.replace(hour=floored // 60, minute=floored % 60, second=0, microsecond=0)


def timeline(report: LogReport, ip: str | None = None) -> tuple[int, list[dict]]:
    """
    Count failed logins, successful logins and lockouts per time bucket.
    Returns (bucket size in minutes, rows). Empty buckets are included, so quiet
    periods show as gaps and an attack stands out as a spike.
    `ip` limits the chart to one source address.
    """
    events = [e for e in report.events if ip is None or e.ip == ip]
    lockouts = report.lockouts if ip is None else []
    everything = events + lockouts
    if not everything:
        return 1, []
    start, end = min(e.time for e in everything), max(e.time for e in everything)
    size = bucket_size(start, end)
    counts = defaultdict(lambda: {"Failed": 0, "Successful": 0, "Locked out": 0})
    for e in events:
        counts[_floor(e.time, size)]["Failed" if e.outcome == "fail" else "Successful"] += 1
    for e in lockouts:
        counts[_floor(e.time, size)]["Locked out"] += 1
    rows, t, last = [], _floor(start, size), _floor(end, size)
    while t <= last:
        rows.append({"time": t, **counts[t]})
        t += timedelta(minutes=size)
    return size, rows


TICK_CHOICES = [1, 2, 5, 10, 15, 30, 60, 120, 180, 360, 720, 1440, 2880, 10080]


def tick_step(rows: list[dict], bucket: int) -> tuple[str, int]:
    """
    How far apart the time labels under the chart should be, as (unit, step),
    e.g. ("minute", 15). About 10 labels, always on whole minutes, hours or
    days, so a label never repeats (09:14, 09:14, 09:14...).
    """
    span = (rows[-1]["time"] - rows[0]["time"]).total_seconds() / 60 if len(rows) > 1 else bucket
    step = next((t for t in TICK_CHOICES if t >= max(span / 10, bucket)), TICK_CHOICES[-1])
    if step < 60:
        return "minute", step
    if step < 1440:
        return "hour", step // 60
    return "day", step // 1440


def tick_times(rows: list[dict], bucket: int) -> list[datetime]:
    """The exact times to label under the chart: every tick_step(), from the first bar to the last."""
    if not rows:
        return []
    unit, step = tick_step(rows, bucket)
    minutes = step * {"minute": 1, "hour": 60, "day": 1440}[unit]
    first, last = rows[0]["time"], rows[-1]["time"]
    t = _floor(first, minutes) if minutes < 1440 else first.replace(hour=0, minute=0)
    if t < first:
        t += timedelta(minutes=minutes)
    ticks = []
    while t <= last + timedelta(minutes=bucket):
        ticks.append(t)
        t += timedelta(minutes=minutes)
    return ticks

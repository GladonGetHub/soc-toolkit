"""
Log Parser, part 1: reading Linux login logs and spotting password attacks.

Every login attempt leaves a line in a log, like a signature in a building's
visitor book. One failed login is a typo. Hundreds from the same address in a
few minutes is a machine guessing passwords, and a success at the end means
the guess worked.

This file reads the lines (parse), then looks for the patterns an analyst
would hunt for by hand (detect). Each finding is mapped to MITRE ATT&CK
T1110 (Brute Force) and its sub-techniques.
"""

import re
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
    method: str = ""          # password, publickey, ...
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
        return min((e.time for e in self.events), default=None)

    @property
    def end(self):
        return max((e.time for e in self.events), default=None)


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

    report.events.sort(key=lambda e: e.time)
    report.findings = detect(report.events)
    return report


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


def detect(events: list[LoginEvent]) -> list[Finding]:
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
                    f"{_minutes(start, end)}. Spraying tries one common password on many accounts, so no "
                    "single account gets locked out.",
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

    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], -(f.count or 0)))
    return findings


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

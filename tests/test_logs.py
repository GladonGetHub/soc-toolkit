"""
Tests for the Log Parser (Linux auth.log). Log lines are written out here or
come from the fictional samples in samples/logs.
"""

import time
from datetime import datetime, timedelta
from pathlib import Path

from soc_toolkit.logs import ip_summary, parse_linux_auth

SAMPLES = Path(__file__).parent.parent / "samples" / "logs"
START = datetime(2026, 11, 16, 9, 0, 0)


def fail(t, user, ip, invalid=False):
    who = f"invalid user {user}" if invalid else user
    return f"{t:%b %d %H:%M:%S} web01 sshd[100]: Failed password for {who} from {ip} port 5000 ssh2"


def ok(t, user, ip):
    return f"{t:%b %d %H:%M:%S} web01 sshd[100]: Accepted password for {user} from {ip} port 5000 ssh2"


def parse(lines):
    return parse_linux_auth("\n".join(lines), year=2026)


def titles(report):
    return [f.title for f in report.findings]


def test_attack_sample_finds_all_five_patterns():
    r = parse_linux_auth((SAMPLES / "linux_auth_attack.log").read_text(), year=2026)
    assert [f.severity for f in r.findings][0] == "Critical"
    assert titles(r) == [
        "Successful login after 58 failures", "Brute force on 'admin'", "Distributed attack on 'root'",
        "Password spraying", "Guessing usernames that don't exist"]
    assert {f.technique for f in r.findings} == {"T1078", "T1110.001", "T1110.003", "T1110"}


def test_normal_day_has_no_findings():
    r = parse_linux_auth((SAMPLES / "linux_auth_normal.log").read_text(), year=2026)
    assert r.findings == [] and len(r.successes) == 5 and len(r.fails) == 2


def test_threshold_is_ten_failures():
    nine = [fail(START + timedelta(seconds=i * 5), "admin", "203.0.113.5") for i in range(9)]
    assert parse(nine).findings == []
    ten = nine + [fail(START + timedelta(seconds=50), "admin", "203.0.113.5")]
    assert titles(parse(ten)) == ["Brute force on 'admin'"]


def test_a_few_typos_then_success_is_not_an_alert():
    lines = [fail(START, "bob", "10.0.0.22"), fail(START + timedelta(seconds=10), "bob", "10.0.0.22"),
             ok(START + timedelta(seconds=20), "bob", "10.0.0.22")]
    assert parse(lines).findings == []


def test_message_repeated_lines_are_counted():
    line = (f"{START:%b %d %H:%M:%S} web01 sshd[100]: message repeated 4 times: "
            "[ Failed password for root from 203.0.113.9 port 22 ssh2]")
    assert len(parse([line]).fails) == 4


def test_new_style_timestamps():
    line = "2026-11-16T09:14:02.123456+00:00 web01 sshd[100]: Failed password for root from 203.0.113.9 port 22 ssh2"
    r = parse([line])
    assert r.fails[0].time == datetime(2026, 11, 16, 9, 14, 2) and r.fails[0].ip == "203.0.113.9"


def test_spraying_versus_brute_force_on_many_accounts():
    users = ["alice", "bob", "carol", "dave", "erin"]
    spray = [fail(START + timedelta(minutes=i), u, "203.0.113.7") for i, u in enumerate(users)]
    assert titles(parse(spray)) == ["Password spraying"]
    heavy = [fail(START + timedelta(seconds=i * 10), users[i % 5], "203.0.113.7") for i in range(25)]
    assert "Brute force across 5 accounts" in titles(parse(heavy))


def test_success_during_a_distributed_attack():
    lines = [fail(START + timedelta(seconds=i * 20), "root", f"198.51.100.{i % 6}") for i in range(12)]
    lines.append(ok(START + timedelta(minutes=5), "root", "198.51.100.3"))
    r = parse(lines)
    assert "Distributed attack on 'root'" in titles(r)
    assert any(f.severity == "Critical" for f in r.findings)


def test_ip_summary_and_internal_flag():
    rows = ip_summary(parse([fail(START, "bob", "10.0.0.22"), ok(START, "alice", "203.0.113.1")]))
    by_ip = {r["ip"]: r for r in rows}
    assert by_ip["10.0.0.22"]["internal"] and by_ip["10.0.0.22"]["fails"] == 1
    assert by_ip["203.0.113.1"]["successes"] == 1


def test_large_log_is_fast():
    lines = [fail(START + timedelta(seconds=i), "admin", "203.0.113.5") for i in range(20000)]
    began = time.time()
    r = parse(lines)
    assert len(r.fails) == 20000 and time.time() - began < 5

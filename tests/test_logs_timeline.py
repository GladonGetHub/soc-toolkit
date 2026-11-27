"""Tests for the login timeline: bucket sizes and counts."""

from datetime import datetime, timedelta
from pathlib import Path

from soc_toolkit.logs import bucket_size, parse_log, timeline

SAMPLES = Path(__file__).parent.parent / "samples" / "logs"
T = datetime(2026, 11, 16, 9, 0)


def test_bucket_size_fits_the_span():
    assert bucket_size(T, T + timedelta(minutes=30)) == 1
    assert bucket_size(T, T + timedelta(hours=8)) == 5
    assert bucket_size(T, T + timedelta(days=1)) == 15
    assert bucket_size(T, T + timedelta(days=60)) == 1440


def test_attack_shows_as_a_spike():
    r = parse_log((SAMPLES / "linux_auth_attack.log").read_bytes(), year=2026)
    size, rows = timeline(r)
    assert size == 5
    busiest = max(rows, key=lambda row: row["Failed"])
    assert busiest["time"].strftime("%H:%M") in ("09:10", "09:15")
    assert sum(row["Failed"] for row in rows) == len(r.fails)
    assert sum(row["Successful"] for row in rows) == len(r.successes)


def test_quiet_periods_are_kept_as_empty_buckets():
    r = parse_log((SAMPLES / "linux_auth_normal.log").read_bytes(), year=2026)
    _, rows = timeline(r)
    times = [row["time"] for row in rows]
    assert all(b - a == timedelta(minutes=5) for a, b in zip(times, times[1:]))
    assert any(row["Failed"] == row["Successful"] == 0 for row in rows)


def test_one_address_and_lockouts():
    r = parse_log((SAMPLES / "windows_security_attack.xml").read_bytes())
    _, rows = timeline(r)
    assert sum(row["Locked out"] for row in rows) == 4
    _, rdp = timeline(r, ip="185.220.101.55")
    assert sum(row["Failed"] for row in rdp) == 46 and sum(row["Successful"] for row in rdp) == 1

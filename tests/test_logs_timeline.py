"""Tests for the login timeline: bucket sizes and counts."""

from datetime import datetime, timedelta
from pathlib import Path

from soc_toolkit.logs import bucket_size, parse_log, tick_step, tick_times, timeline

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


def test_time_labels_never_repeat():
    r = parse_log((SAMPLES / "linux_auth_attack.log").read_bytes(), year=2026)
    size, rows = timeline(r, ip="185.220.101.55")        # about 6 minutes of 1-minute bars
    assert size == 1 and tick_step(rows, size) == ("minute", 1)
    size, rows = timeline(r)                              # a whole working day
    assert tick_step(rows, size) == ("hour", 1)


def test_tick_times_are_whole_minutes_and_hours():
    r = parse_log((SAMPLES / "linux_auth_attack.log").read_bytes(), year=2026)
    size, rows = timeline(r, ip="185.220.101.55")
    ticks = tick_times(rows, size)
    assert [t.strftime("%H:%M") for t in ticks][:3] == ["09:14", "09:15", "09:16"]
    assert len({t.strftime("%H:%M") for t in ticks}) == len(ticks)       # no repeats
    size, rows = timeline(r)
    assert all(t.minute == 0 for t in tick_times(rows, size))           # on the hour

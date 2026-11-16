"""
Tests for reading Windows Security events: Event Viewer XML and CSV exports
from PowerShell or a SIEM. Every event here is made up.
"""

from pathlib import Path

from soc_toolkit.logs import parse_log

SAMPLES = Path(__file__).parent.parent / "samples" / "logs"

SPLUNK_STYLE = """_time,EventCode,Account_Name,Source_Network_Address,Logon_Type,ComputerName
2026-11-16T09:00:00,4625,svc_backup,203.0.113.50,3,FS01
""" + "".join(f"2026-11-16T09:00:{i:02d},4625,svc_backup,203.0.113.50,3,FS01\n" for i in range(1, 12)) + \
    "2026-11-16T09:00:30,4624,svc_backup,203.0.113.50,3,FS01\n"

POWERSHELL_STYLE = """"TimeCreated","EventID","Computer","TargetUserName","IpAddress","LogonType","SubStatus"
"2026-11-16T10:00:00.1234567+00:00","4624","FS01","SYSTEM","-","5",""
"2026-11-16T10:00:01.0000000+00:00","4624","FS01","FS01$","10.0.1.5","3",""
"2026-11-16T10:00:02.0000000+00:00","4625","FS01","ghost","192.0.2.9","3","0xc0000064"
"2026-11-16T10:00:03.0000000+00:00","4624","FS01","jsmith","10.0.1.21","3",""
"""


def titles(report):
    return [f.title for f in report.findings]


def test_event_viewer_xml_sample():
    r = parse_log((SAMPLES / "windows_security_attack.xml").read_bytes())
    assert r.log_type == "Windows Security events (XML)"
    assert titles(r) == [
        "Successful login after 46 failures", "Brute force on 'Administrator'", "Password spraying",
        "3 accounts locked out", "Guessing usernames that don't exist", "'dbrown' was locked out"]
    rdp = [e for e in r.successes if e.user == "Administrator"][0]
    assert rdp.method == "RDP (Remote Desktop)" and rdp.ip == "185.220.101.55"


def test_windows_background_logons_are_ignored():
    r = parse_log((SAMPLES / "windows_security_attack.xml").read_bytes())
    users = {e.user for e in r.events}
    assert not users & {"SYSTEM", "FS01$", "DWM-1"}


def test_splunk_style_csv():
    r = parse_log(SPLUNK_STYLE.encode())
    assert r.log_type == "Windows Security events (CSV)"
    assert titles(r)[:2] == ["Successful login after 12 failures", "Brute force on 'svc_backup'"]


def test_powershell_csv_skips_noise_and_spots_unknown_accounts():
    r = parse_log(POWERSHELL_STYLE.encode())
    assert [(e.user, e.outcome) for e in r.events] == [("ghost", "fail"), ("jsmith", "success")]
    assert r.events[0].invalid_user                        # 0xC0000064 = no such account


def test_utf16_export_is_read():
    """Windows tools often save as UTF-16."""
    r = parse_log(POWERSHELL_STYLE.encode("utf-16"))
    assert len(r.events) == 2


def test_linux_log_with_commas_is_not_mistaken_for_csv():
    line = "Nov 16 09:00:00 web01 sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2, uid=0, id=1"
    assert parse_log(line.encode(), year=2026).log_type == "Linux auth.log (SSH)"

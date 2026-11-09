"""
Tests for the attachment checks. Every "file" here is a few harmless bytes
built in memory. A fake program is just the two letters "MZ" followed by
text: enough to show the check reads the bytes, not the name.
"""

import io
import zipfile
from email.message import EmailMessage
from pathlib import Path

from soc_toolkit.attachments import analyse_attachments, real_type
from soc_toolkit.email_analyser import analyse_email

SAMPLES = Path(__file__).parent.parent / "samples"
FAKE_PROGRAM = b"MZ" + b"harmless test bytes, not a real program" * 3
FAKE_PDF = b"%PDF-1.4\n%%EOF\n"


def problems(filename, data, maintype="application", subtype="octet-stream"):
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = "a@example.com", "b@example.net", "Test"
    msg.set_content("See attached.")
    msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    attachments, _ = analyse_attachments(msg)
    return attachments[0].problems


def make_zip(files, locked=False):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    data = bytearray(buf.getvalue())
    if locked:  # set the "encrypted" flag on the first entry, as a locked ZIP has
        data[6] |= 0x1
        central = data.find(b"PK\x01\x02")
        data[central + 8] |= 0x1
    return bytes(data)


def test_real_type_reads_bytes_not_names():
    assert real_type(FAKE_PROGRAM)[0] == "Windows program"
    assert real_type(FAKE_PDF)[0] == "PDF"
    assert real_type(b"<!DOCTYPE html><html></html>")[0] == "HTML page"


def test_program_disguised_as_pdf():
    p = problems("invoice.pdf", FAKE_PROGRAM)
    assert "program" in p and "disguised" in p


def test_double_extension_and_hidden_reversed_text():
    assert "double_ext" in problems("invoice.pdf.exe", FAKE_PROGRAM)
    assert "rtlo" in problems("invoice‮fdp.exe", FAKE_PROGRAM)


def test_genuine_pdf_and_image_are_fine():
    assert problems("report.pdf", FAKE_PDF) == []
    assert problems("logo.png", b"\x89PNG\r\n\x1a\nimage") == []


def test_office_macros():
    docm = make_zip({"[Content_Types].xml": "<Types/>", "word/vbaProject.bin": "x"})
    assert "macros" in problems("report.docx", docm)
    docx = make_zip({"[Content_Types].xml": "<Types/>", "word/document.xml": "<w/>"})
    assert problems("report.docx", docx) == []


def test_archives():
    assert "archive_program" in problems("files.zip", make_zip({"invoice.pdf.exe": "x"}))
    assert "locked_archive" in problems("files.zip", make_zip({"invoice.pdf": "x"}, locked=True))
    assert problems("files.zip", make_zip({"notes.txt": "x"})) == []


def test_shortcut_disk_image_html_and_pdf_javascript():
    assert "shortcut" in problems("Invoice.lnk", b"L\x00\x00\x00\x01\x14\x02\x00")
    assert "disk_image" in problems("Invoice.iso", b"\x00" * 10)
    assert "html" in problems("login.htm", b"<html><body>Sign in</body></html>")
    assert "pdf_active" in problems("invoice.pdf", b"%PDF-1.4\n/OpenAction << /JavaScript (x) >>")


def test_hashes_are_worked_out():
    msg = EmailMessage()
    msg["From"] = "a@example.com"
    msg.set_content("x")
    msg.add_attachment(b"abc", maintype="text", subtype="plain", filename="a.txt")
    att = analyse_attachments(msg)[0][0]
    assert att.sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert att.md5 == "900150983cd24fb0d6963f7d28e17f72"


def test_samples():
    phish = analyse_email((SAMPLES / "phishing_paypal_impersonation.eml").read_bytes())
    titles = [f.title for f in phish.flags if f.area == "Attachments"]
    assert "Double file extension" in titles and "HTML file attached" in titles
    genuine = analyse_email((SAMPLES / "genuine_newsletter.eml").read_bytes())
    assert genuine.score == 0 and genuine.attachments[0].real_type == "PDF"

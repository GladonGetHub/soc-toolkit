"""
Phishing Email Analyser, part 3: attachments.

A file's name is just a label, like the writing on a parcel. Anyone can
call a program "invoice.pdf". What a file really IS is decided by its first
few bytes, its "magic number": every PDF starts with %PDF, every Windows
program starts with MZ, and so on.

This file reads each attachment's bytes in memory to work out what it really
is, checks the name for tricks, and works out its hashes so it can be looked
up in malware databases. Nothing is ever opened, run, unpacked or saved.
"""

import hashlib
import io
import re
import zipfile
from dataclasses import dataclass, field

from .phishing import Flag

# First bytes -> what the file really is. Checked in this order.
MAGIC = [
    (b"MZ", "Windows program"),
    (b"\x7fELF", "Linux program"),
    (b"%PDF", "PDF"),
    (b"PK\x03\x04", "ZIP-based file"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "Old-style Office file"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"\x1f\x8b", "GZIP archive"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "Windows shortcut"),
    (b"{\\rtf", "RTF document"),
    (b"\x89PNG", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF8", "GIF image"),
]

# What each extension should really be
EXPECTED = {
    "pdf": {"PDF"},
    "doc": {"Old-style Office file", "RTF document"}, "xls": {"Old-style Office file"},
    "ppt": {"Old-style Office file"},
    "docx": {"Office document"}, "xlsx": {"Office document"}, "pptx": {"Office document"},
    "docm": {"Office document"}, "xlsm": {"Office document"}, "pptm": {"Office document"},
    "zip": {"ZIP archive", "Office document", "ZIP-based file"}, "rar": {"RAR archive"},
    "7z": {"7-Zip archive"}, "gz": {"GZIP archive"}, "rtf": {"RTF document"},
    "png": {"PNG image"}, "jpg": {"JPEG image"}, "jpeg": {"JPEG image"}, "gif": {"GIF image"},
    "txt": {"Text"}, "csv": {"Text"}, "htm": {"HTML page"}, "html": {"HTML page"},
}

PROGRAM_EXTS = {
    "exe", "scr", "com", "pif", "msi", "dll", "cpl", "bat", "cmd", "ps1", "vbs", "vbe",
    "js", "jse", "wsf", "wsh", "hta", "jar", "apk", "elf", "sh",
}
DISK_IMAGE_EXTS = {"iso", "img", "vhd", "vhdx"}
SHORTCUT_EXTS = {"lnk", "url"}
DOCUMENT_EXTS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "png", "csv"}
MACRO_EXTS = {"docm", "xlsm", "pptm", "dotm", "xltm"}

RTLO = "‮"   # an invisible character that writes the rest of the name backwards

# Points per kind of attachment problem. Each kind counts once per email.
ATTACH_WEIGHTS = {
    "program": 50, "shortcut": 45, "archive_program": 45, "double_ext": 40, "rtlo": 40,
    "macros": 40, "disguised": 35, "disk_image": 35, "html": 30, "locked_archive": 30,
    "pdf_active": 25,
}


# Short names for each problem, for tables and case notes
PROBLEM_LABELS = {
    "program": "Program", "shortcut": "Shortcut", "archive_program": "Archive hides a program",
    "double_ext": "Double extension", "rtlo": "Reversed name", "macros": "Macros",
    "disguised": "Type disguised", "disk_image": "Disk image", "html": "HTML page",
    "locked_archive": "Password-protected", "pdf_active": "Active PDF content",
}


@dataclass
class Attachment:
    name: str
    declared_type: str        # what the email says it is (Content-Type)
    size: int
    real_type: str = ""       # what its bytes say it is
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    inside: list = field(default_factory=list)     # file names inside an archive
    locked: bool = False                           # password-protected archive
    problems: list = field(default_factory=list)   # kinds from ATTACH_WEIGHTS

    @property
    def extension(self) -> str:
        clean = self.name.replace(RTLO, "").strip().rstrip(". ")
        return clean.rsplit(".", 1)[-1].lower() if "." in clean else ""


# ------------------------------------------------------------ real type
def _zip_contents(data: bytes) -> tuple[list[str], bool]:
    """Names inside a ZIP and whether any are password-protected. Nothing is unpacked."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            infos = z.infolist()
            return [i.filename for i in infos], any(i.flag_bits & 0x1 for i in infos)
    except (zipfile.BadZipFile, ValueError, OSError):
        return [], False


def real_type(data: bytes) -> tuple[str, list[str], bool]:
    """
    Return (what the file really is, names inside it if it's an archive,
    whether the archive is password-protected).
    """
    if len(data) > 0x8005 and data[0x8001:0x8006] == b"CD001":
        return "Disk image (ISO)", [], False
    for magic, kind in MAGIC:
        if data.startswith(magic):
            if kind == "ZIP-based file":
                names, locked = _zip_contents(data)
                if "[Content_Types].xml" in names:
                    return "Office document", names, locked
                if "META-INF/MANIFEST.MF" in names:
                    return "Java program", names, locked
                return "ZIP archive", names, locked
            return kind, [], False
    head = data[:2048].lstrip().lower()
    if head.startswith((b"<!doctype html", b"<html", b"<script", b"<svg")) or b"<html" in head:
        return "HTML page", [], False
    try:
        data[:4096].decode("utf-8")
        return "Text", [], False
    except UnicodeDecodeError:
        return "Unknown binary", [], False


def _has_macros(att: Attachment, data: bytes) -> bool:
    if att.real_type == "Office document":
        return any(n.lower().endswith("vbaproject.bin") for n in att.inside)
    if att.real_type == "Old-style Office file":
        return b"_VBA_PROJECT" in data or b"V\x00B\x00A\x00" in data
    return False


# ------------------------------------------------------------- checking
def check_attachment(att: Attachment, data: bytes) -> Attachment:
    ext = att.extension
    parts = att.name.replace(RTLO, "").lower().split(".")
    p = att.problems

    if att.real_type in ("Windows program", "Linux program", "Java program") or ext in PROGRAM_EXTS:
        p.append("program")
    if ext in SHORTCUT_EXTS or att.real_type == "Windows shortcut":
        p.append("shortcut")
    if ext in DISK_IMAGE_EXTS or att.real_type == "Disk image (ISO)":
        p.append("disk_image")
    if ext in ("htm", "html", "shtml", "svg") or att.real_type == "HTML page":
        p.append("html")
    if RTLO in att.name:
        p.append("rtlo")
    # invoice.pdf.exe: looks like a document, ends as something risky
    risky_end = ext in PROGRAM_EXTS | SHORTCUT_EXTS | DISK_IMAGE_EXTS | {"htm", "html"}
    if len(parts) >= 3 and parts[-2] in DOCUMENT_EXTS and risky_end:
        p.append("double_ext")
    # The name says one thing, the bytes say another
    expected = EXPECTED.get(ext)
    if expected and att.real_type not in expected and att.real_type not in ("Text", "Unknown binary"):
        p.append("disguised")
    if ext in MACRO_EXTS or _has_macros(att, data):
        p.append("macros")
    if att.inside:
        inner = [n.rsplit(".", 1)[-1].lower() for n in att.inside if "." in n]
        if any(e in PROGRAM_EXTS | SHORTCUT_EXTS | DISK_IMAGE_EXTS for e in inner) and att.real_type != "Office document":
            p.append("archive_program")
    if att.locked:
        p.append("locked_archive")
    if att.real_type == "PDF" and re.search(rb"/(JavaScript|JS|Launch|EmbeddedFile)\b", data):
        p.append("pdf_active")
    return att


def extract_attachments(msg) -> list[Attachment]:
    """Every attached file, read into memory only."""
    found = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        name = part.get_filename()
        if not name and part.get_content_disposition() != "attachment":
            continue
        data = part.get_payload(decode=True) or b""
        kind, inside, locked = real_type(data)
        att = Attachment(
            name=name or "(no name)",
            declared_type=part.get_content_type(),
            size=len(data),
            real_type=kind,
            md5=hashlib.md5(data).hexdigest(),
            sha1=hashlib.sha1(data).hexdigest(),
            sha256=hashlib.sha256(data).hexdigest(),
            inside=inside,
            locked=locked,
        )
        found.append(check_attachment(att, data))
    return found


# ------------------------------------------------------------ red flags
def _what_it_is(att: Attachment) -> str:
    if "program" in att.real_type:
        return "a " + att.real_type.replace("Program", "program")
    return f"a .{att.extension} file"


def _explain(kind: str, att: Attachment, count: int) -> Flag:
    name = att.name.replace(RTLO, "[hidden character]")
    more = f" ({count} files like this)" if count > 1 else ""
    text = {
        "program": ("Attachment is a program",
                    f"\"{name}\" is {_what_it_is(att)} that runs code when opened{more}. "
                    "Genuine senders almost never email programs."),
        "shortcut": ("Attachment is a shortcut",
                     f"\"{name}\" is a shortcut that can run any command when double-clicked{more}."),
        "archive_program": ("Archive hides a program",
                            f"\"{name}\" contains {', '.join(att.inside[:3])}, which can run code when opened."),
        "double_ext": ("Double file extension",
                       f"\"{name}\" is made to look like a .{att.name.lower().split('.')[-2]} file, "
                       f"but really ends in .{att.extension}. Windows hides the last part by default."),
        "rtlo": ("Reversed text hidden in the file name",
                 f"\"{name}\" contains an invisible character that makes the end of the name display backwards, "
                 "so \"exe.pdf\" can appear as \"fdp.exe\"."),
        "macros": ("Office file with macros",
                   f"\"{name}\" contains macros, small programs that can run when the file is opened. "
                   "Never click \"Enable content\" on a file you weren't expecting."),
        "disguised": ("File type disguised",
                      f"\"{name}\" is named as a .{att.extension} file, but its contents show it's really a "
                      f"{att.real_type.lower()}{more}."),
        "disk_image": ("Disk image attached",
                       f"\"{name}\" is a disk image. Attackers use these to get past email filters, "
                       "because files inside often aren't scanned."),
        "html": ("HTML file attached",
                 f"\"{name}\" is a web page. Opening it shows a page from your own computer, which is a common "
                 "way to show a fake login page without any link for filters to catch."),
        "locked_archive": ("Password-protected archive",
                           f"\"{name}\" is locked with a password, often given in the email. Email security "
                           "can't look inside, which is exactly why attackers do it."),
        "pdf_active": ("PDF with active content",
                       f"\"{name}\" contains JavaScript, an embedded file or a command to launch something. "
                       "Ordinary PDFs such as invoices don't need these."),
    }[kind]
    return Flag(ATTACH_WEIGHTS[kind], *text, area="Attachments")


def attachment_flags(attachments: list[Attachment]) -> list[Flag]:
    by_kind = {}
    for att in attachments:
        for kind in att.problems:
            by_kind.setdefault(kind, []).append(att)
    return [_explain(kind, atts[0], len(atts)) for kind, atts in by_kind.items()]


def analyse_attachments(msg) -> tuple[list[Attachment], list[Flag]]:
    attachments = extract_attachments(msg)
    return attachments, attachment_flags(attachments)

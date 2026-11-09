"""
Showing text from an email safely on the page.

Streamlit turns text into formatted Markdown, which means an email address
or web address becomes a clickable link, and characters like [ ] ( ) * $
change how text looks. Text taken from a suspicious email must never become
clickable, so it goes through safe_text() first.
"""

import re

from .ioc import defang

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
URL_RE = re.compile(r"(?:https?://|www\.)\S+", re.I)
# Characters that mean something in Markdown (and $ for maths in Streamlit)
MARKDOWN_CHARS = re.compile(r"([\\`*_{}\[\]()<>#+!|~$:])")


def safe_text(text: str) -> str:
    """Defang addresses and links, then stop any Markdown formatting."""
    text = URL_RE.sub(lambda m: defang(m.group(0)) if "[.]" not in m.group(0) else m.group(0), text)
    text = EMAIL_RE.sub(lambda m: m.group(0).replace(".", "[.]"), text)
    return MARKDOWN_CHARS.sub(r"\\\1", text)

"""
Settings: API keys and which mode the app runs in.

Two modes:

  Private  - running on your own machine with keys in a .env file next to
             app.py. Every source with a key is switched on. No limits.

  Public   - running as a public website with no keys on the server. The
             free no-key sources are switched on for everyone, and each
             visitor can paste their own keys, which last only for their
             browser session. Visitors can't use anyone else's quota.

Keys never go in the code, so they never end up on GitHub.
"""

import os

from dotenv import load_dotenv

from .sources import (OTX, AbuseIPDB, CIRCLHashlookup, GreyNoise, MalwareBazaar,
                      ShodanInternetDB, ThreatFox, URLhaus, VirusTotal)

load_dotenv()

# Source name -> the line in .env that holds its key
KEY_NAMES = {
    "VirusTotal": "VT_API_KEY",
    "AbuseIPDB": "ABUSEIPDB_API_KEY",
    "OTX": "OTX_API_KEY",
    "abuse.ch": "ABUSECH_API_KEY",
    "GreyNoise": "GREYNOISE_API_KEY",  # optional, works without one
}
MAIN_SOURCES = ["VirusTotal", "AbuseIPDB", "OTX", "abuse.ch"]

# Limits for the public website, so one visitor can't hog the free services
PUBLIC_MAX_PER_LOOKUP = 10
PUBLIC_MAX_PER_SESSION = 50


def get_keys() -> dict:
    """Keys from the .env file (empty strings for any that aren't set)."""
    return {source: os.getenv(env, "").strip() for source, env in KEY_NAMES.items()}


def is_public() -> bool:
    """Public mode means the server has none of the main keys in its .env."""
    keys = get_keys()
    return not any(keys[s] for s in MAIN_SOURCES)


def build_providers(visitor_keys: dict | None = None) -> tuple[list, bool]:
    """
    Return (providers, public_mode).

    Private mode uses the .env keys and ignores visitor_keys.
    Public mode ignores the .env completely and uses only the keys the
    visitor pasted in, plus the free no-key sources.
    """
    public = is_public()
    if public:
        keys = {s: "" for s in KEY_NAMES}
        keys.update({s: (v or "").strip() for s, v in (visitor_keys or {}).items() if s in KEY_NAMES})
    else:
        keys = get_keys()

    providers = []
    if keys["VirusTotal"]:
        providers.append(VirusTotal(keys["VirusTotal"]))
    if keys["AbuseIPDB"]:
        providers.append(AbuseIPDB(keys["AbuseIPDB"]))
    if keys["OTX"]:
        providers.append(OTX(keys["OTX"]))
    if keys["abuse.ch"]:
        providers += [MalwareBazaar(keys["abuse.ch"]), URLhaus(keys["abuse.ch"]), ThreatFox(keys["abuse.ch"])]
    providers += [GreyNoise(keys["GreyNoise"]), ShodanInternetDB(), CIRCLHashlookup()]
    return providers, public

"""
Settings and API keys.

Keys live in a file called .env next to app.py, never in the code, so they
don't end up on GitHub. Copy .env.example to .env and paste your keys in.
"""

import os

from dotenv import load_dotenv

from .sources import (OTX, AbuseIPDB, CIRCLHashlookup, Demo, GreyNoise, MalwareBazaar,
                      ShodanInternetDB, ThreatFox, URLhaus, VirusTotal)

load_dotenv()


def get_keys() -> dict:
    return {
        "VirusTotal": os.getenv("VT_API_KEY", "").strip(),
        "AbuseIPDB": os.getenv("ABUSEIPDB_API_KEY", "").strip(),
        "OTX": os.getenv("OTX_API_KEY", "").strip(),
        "abuse.ch": os.getenv("ABUSECH_API_KEY", "").strip(),
        "GreyNoise": os.getenv("GREYNOISE_API_KEY", "").strip(),  # optional
    }


def build_providers() -> tuple[list, bool]:
    """
    Return (providers, demo_mode).

    Sources that need a key are added when their key is set. Once at least one
    key is set, the free no-key sources (GreyNoise, Shodan InternetDB, CIRCL)
    are added too. With no keys at all, the app falls back to demo data.
    """
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
    if not providers:
        return [Demo()], True
    providers += [GreyNoise(keys["GreyNoise"]), ShodanInternetDB(), CIRCLHashlookup()]
    return providers, False

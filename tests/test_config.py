"""
Checks which sources are switched on in private mode (keys in .env) and
public mode (no keys on the server, visitors bring their own).
"""

from soc_toolkit import config

FREE = ["GreyNoise", "Shodan InternetDB", "CIRCL hashlookup"]


def set_env(monkeypatch, **keys):
    """Pretend the .env holds exactly these keys and nothing else."""
    for env in config.KEY_NAMES.values():
        monkeypatch.delenv(env, raising=False)
    for env, value in keys.items():
        monkeypatch.setenv(env, value)


def names(providers):
    return [p.name for p in providers]


def test_public_mode_free_sources_only(monkeypatch):
    set_env(monkeypatch)
    providers, public = config.build_providers()
    assert public is True
    assert names(providers) == FREE


def test_public_mode_visitor_keys(monkeypatch):
    set_env(monkeypatch)
    providers, public = config.build_providers({"VirusTotal": " abc ", "abuse.ch": "xyz"})
    assert public is True
    assert names(providers)[:4] == ["VirusTotal", "MalwareBazaar", "URLhaus", "ThreatFox"]
    assert providers[0].headers["x-apikey"] == "abc"


def test_private_mode_ignores_visitor_keys(monkeypatch):
    set_env(monkeypatch, VT_API_KEY="mine")
    providers, public = config.build_providers({"AbuseIPDB": "theirs"})
    assert public is False
    assert names(providers) == ["VirusTotal"] + FREE
    assert providers[0].headers["x-apikey"] == "mine"


def test_greynoise_key_alone_stays_public(monkeypatch):
    set_env(monkeypatch, GREYNOISE_API_KEY="gn")
    assert config.is_public() is True

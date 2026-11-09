from soc_toolkit.display import safe_text


def test_addresses_and_links_are_defanged():
    out = safe_text("The name shows service@paypal.com and links to https://evil.example/login")
    assert "paypal.com" not in out and "evil.example" not in out
    assert "hxxps" in out


def test_markdown_tricks_are_neutralised():
    # A display name built to look like a clickable link must stay plain text
    out = safe_text("[Click me](https://evil.example)")
    assert "](" not in out and out.startswith("\\[")

import pytest
from notte_browser.errors import InvalidURLError
from notte_browser.window import _normalize_goto_url


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://example.com", "https://example.com"),
        ("http://example.com", "http://example.com"),
        ("file:///tmp/page.html", "file:///tmp/page.html"),
        ("example.com", "https://example.com"),
        ("localhost:3000", "https://localhost:3000"),
        ("example.com:8443/path", "https://example.com:8443/path"),
    ],
)
def test_normalize_goto_url_supported_schemes(url: str, expected: str) -> None:
    assert _normalize_goto_url(url) == expected


@pytest.mark.parametrize("url", ["ftp://example.com", "mailto:hello@example.com"])
def test_normalize_goto_url_rejects_unsupported_schemes(url: str) -> None:
    with pytest.raises(InvalidURLError):
        _normalize_goto_url(url)

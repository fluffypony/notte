import sys
import types

import pytest
from notte_browser.playwright import PlaywrightManager
from notte_browser.window import BrowserResource, BrowserWindow, BrowserWindowOptions


def _make_options(**overrides):
    data = {
        "headless": True,
        "solve_captchas": False,
        "user_agent": None,
        "proxy": None,
        "viewport_width": 1280,
        "viewport_height": 720,
        "browser_type": "camoufox",
        "chrome_args": None,
        "web_security": True,
        "cdp_url": None,
        "debug_port": None,
        "custom_devtools_frontend": None,
        "extra_http_headers": None,
    }
    data.update(overrides)
    return BrowserWindowOptions(**data)


def test_camoufox_has_no_chrome_args():
    options = _make_options()
    assert options.get_chrome_args() == []


def test_camoufox_is_not_chromium_based():
    class FakePage:
        def __init__(self):
            self.url = "about:blank"
            self.context = types.SimpleNamespace(pages=[])

        def set_default_timeout(self, _timeout):
            return None

        def on(self, *_args, **_kwargs):
            return None

        def is_closed(self):
            return False

    resource = BrowserResource.model_construct(page=FakePage(), options=_make_options())
    window = BrowserWindow(resource=resource)
    assert window.is_chromium_based is False


@pytest.mark.asyncio
async def test_create_playwright_browser_uses_async_camoufox(monkeypatch: pytest.MonkeyPatch):
    fake_browser = object()
    created_kwargs: dict[str, object] = {}

    class FakeAsyncCamoufox:
        def __init__(self, **kwargs):
            created_kwargs.update(kwargs)

        async def __aenter__(self):
            return fake_browser

        async def __aexit__(self, *_args):
            return None

    camoufox_pkg = types.ModuleType("camoufox")
    camoufox_async_api = types.ModuleType("camoufox.async_api")
    camoufox_async_api.AsyncCamoufox = FakeAsyncCamoufox
    camoufox_pkg.async_api = camoufox_async_api
    monkeypatch.setitem(sys.modules, "camoufox", camoufox_pkg)
    monkeypatch.setitem(sys.modules, "camoufox.async_api", camoufox_async_api)

    manager = PlaywrightManager()
    browser = await manager.create_playwright_browser(_make_options())

    assert browser is fake_browser
    assert manager._camoufox_context_manager is not None
    assert created_kwargs["headless"] is True
    assert created_kwargs["proxy"] is None


@pytest.mark.asyncio
async def test_get_browser_resource_omits_user_agent_for_camoufox():
    class FakePage:
        pass

    class FakeContext:
        def __init__(self):
            self.pages = []

        async def new_page(self):
            page = FakePage()
            self.pages.append(page)
            return page

    class FakeBrowser:
        def __init__(self):
            self.context_kwargs = None

        async def new_context(self, **kwargs):
            self.context_kwargs = kwargs
            return FakeContext()

    manager = PlaywrightManager()
    browser = FakeBrowser()

    resource = await manager.get_browser_resource(_make_options(), browser)

    assert resource.page is not None
    assert browser.context_kwargs["permissions"] == []
    assert browser.context_kwargs["no_viewport"] is False
    assert "user_agent" not in browser.context_kwargs

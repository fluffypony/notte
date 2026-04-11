import sys
import types
from collections.abc import Callable
from enum import Enum
from types import SimpleNamespace

import pytest
from notte_browser.captcha import CaptchaHandler
from notte_core.actions import CaptchaSolveAction


def _install_fake_captcha_modules(
    monkeypatch: pytest.MonkeyPatch,
    outcomes: dict[object, object] | Callable[[type[Enum]], dict[object, object]] | None = None,
):
    state = {
        "api_keys": [],
        "frameworks": [],
        "calls": [],
        "instances": 0,
    }

    class CaptchaType(Enum):
        CLOUDFLARE_INTERSTITIAL = "cloudflare_interstitial"
        CLOUDFLARE_TURNSTILE = "cloudflare_turnstile"
        RECAPTCHA_V2 = "recaptcha_v2"
        RECAPTCHA_V3 = "recaptcha_v3"

    class FrameworkType(Enum):
        PLAYWRIGHT = "playwright"
        CAMOUFOX = "camoufox"
        PATCHRIGHT = "patchright"

    outcomes = outcomes(CaptchaType) if callable(outcomes) else (outcomes or {})

    class AsyncTwoCaptcha:
        def __init__(self, api_key: str):
            state["api_keys"].append(api_key)

    class TwoCaptchaSolver:
        def __init__(self, framework, page, async_two_captcha_client):
            state["frameworks"].append(framework)
            state["instances"] += 1
            self.page = page
            self.async_two_captcha_client = async_two_captcha_client

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def solve_captcha(self, captcha_container, captcha_type):
            state["calls"].append(captcha_type)
            outcome = outcomes.get(captcha_type, True)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

    playwright_captcha = types.ModuleType("playwright_captcha")
    playwright_captcha.CaptchaType = CaptchaType
    playwright_captcha.FrameworkType = FrameworkType
    playwright_captcha.TwoCaptchaSolver = TwoCaptchaSolver
    monkeypatch.setitem(sys.modules, "playwright_captcha", playwright_captcha)

    twocaptcha = types.ModuleType("twocaptcha")
    twocaptcha.AsyncTwoCaptcha = AsyncTwoCaptcha
    monkeypatch.setitem(sys.modules, "twocaptcha", twocaptcha)

    return state, CaptchaType, FrameworkType


class _DummyWindow:
    def __init__(self, browser_type: str = "chrome"):
        self.page = object()
        self.wait_calls = 0
        self.resource = SimpleNamespace(options=SimpleNamespace(browser_type=browser_type))

    async def long_wait(self):
        self.wait_calls += 1


def test_check_available_requires_api_key(monkeypatch: pytest.MonkeyPatch):
    _install_fake_captcha_modules(monkeypatch)
    monkeypatch.delenv("TWOCAPTCHA_API_KEY", raising=False)
    monkeypatch.delenv("TWO_CAPTCHA_API_KEY", raising=False)
    assert CaptchaHandler._check_available() is False

    monkeypatch.setenv("TWOCAPTCHA_API_KEY", "test-key")
    assert CaptchaHandler._check_available() is True


@pytest.mark.asyncio
async def test_handle_captchas_uses_recaptcha_solver(monkeypatch: pytest.MonkeyPatch):
    state, captcha_type_enum, framework_type_enum = _install_fake_captcha_modules(monkeypatch)
    monkeypatch.setenv("TWOCAPTCHA_API_KEY", "test-key")
    window = _DummyWindow(browser_type="camoufox")

    result = await CaptchaHandler.handle_captchas(window, CaptchaSolveAction(captcha_type="recaptcha"))

    assert result is True
    assert window.wait_calls == 1
    assert state["api_keys"] == ["test-key"]
    assert state["frameworks"] == [framework_type_enum.CAMOUFOX]
    assert state["calls"] == [captcha_type_enum.RECAPTCHA_V2]


@pytest.mark.asyncio
async def test_handle_captchas_falls_back_across_cloudflare_candidates(monkeypatch: pytest.MonkeyPatch):
    state, captcha_type_enum, framework_type_enum = _install_fake_captcha_modules(
        monkeypatch,
        outcomes=lambda captcha_type: {
            captcha_type.CLOUDFLARE_TURNSTILE: RuntimeError("not found"),
            captcha_type.CLOUDFLARE_INTERSTITIAL: True,
        },
    )
    monkeypatch.setenv("TWOCAPTCHA_API_KEY", "test-key")
    window = _DummyWindow(browser_type="chrome")

    result = await CaptchaHandler.handle_captchas(window, CaptchaSolveAction(captcha_type="cloudflare"))

    assert result is True
    assert window.wait_calls == 1
    assert state["frameworks"] == [framework_type_enum.PATCHRIGHT]
    assert state["calls"] == [
        captcha_type_enum.CLOUDFLARE_TURNSTILE,
        captcha_type_enum.CLOUDFLARE_INTERSTITIAL,
    ]


@pytest.mark.asyncio
async def test_handle_captchas_returns_true_for_unsupported_hint(monkeypatch: pytest.MonkeyPatch):
    state, _, _ = _install_fake_captcha_modules(monkeypatch)
    monkeypatch.setenv("TWOCAPTCHA_API_KEY", "test-key")
    window = _DummyWindow(browser_type="chrome")

    result = await CaptchaHandler.handle_captchas(window, CaptchaSolveAction(captcha_type="hcaptcha"))

    assert result is True
    assert window.wait_calls == 1
    assert state["instances"] == 0
    assert state["calls"] == []

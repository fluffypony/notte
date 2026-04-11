import sys
import types
from types import SimpleNamespace

import pytest
from notte_browser.captcha import CaptchaHandler
from notte_core.actions import CaptchaSolveAction


def _install_fake_twocaptcha(monkeypatch: pytest.MonkeyPatch):
    """Install a fake twocaptcha module so _check_available works without the real SDK."""
    twocaptcha_mod = types.ModuleType("twocaptcha")

    class FakeTwoCaptcha:
        def __init__(self, api_key, **kwargs):
            self.api_key = api_key

    twocaptcha_mod.TwoCaptcha = FakeTwoCaptcha
    monkeypatch.setitem(sys.modules, "twocaptcha", twocaptcha_mod)
    return FakeTwoCaptcha


def test_check_available_requires_api_key(monkeypatch: pytest.MonkeyPatch):
    _install_fake_twocaptcha(monkeypatch)
    monkeypatch.delenv("TWOCAPTCHA_API_KEY", raising=False)
    monkeypatch.delenv("TWO_CAPTCHA_API_KEY", raising=False)
    assert CaptchaHandler._check_available() is False

    monkeypatch.setenv("TWOCAPTCHA_API_KEY", "test-key")
    assert CaptchaHandler._check_available() is True


def test_check_available_accepts_alternate_env_var(monkeypatch: pytest.MonkeyPatch):
    _install_fake_twocaptcha(monkeypatch)
    monkeypatch.delenv("TWOCAPTCHA_API_KEY", raising=False)
    monkeypatch.delenv("TWO_CAPTCHA_API_KEY", raising=False)

    monkeypatch.setenv("TWO_CAPTCHA_API_KEY", "alt-key")
    assert CaptchaHandler._check_available() is True


def test_normalize_type_aliases():
    assert CaptchaHandler._normalize_type("cloudflare") == "turnstile"
    assert CaptchaHandler._normalize_type("arkose labs") == "funcaptcha"
    assert CaptchaHandler._normalize_type("CLOUDFLARE") == "turnstile"
    assert CaptchaHandler._normalize_type("press&hold") == "press_hold"
    assert CaptchaHandler._normalize_type("recaptcha_v2") == "recaptcha"
    assert CaptchaHandler._normalize_type("recaptcha_v3") == "recaptcha"
    assert CaptchaHandler._normalize_type("recaptcha enterprise") == "recaptcha"
    assert CaptchaHandler._normalize_type("cf") == "turnstile"
    assert CaptchaHandler._normalize_type("friendly") == "friendly_captcha"
    assert CaptchaHandler._normalize_type("amazon") == "amazon_waf"
    assert CaptchaHandler._normalize_type(None) == "unknown"
    assert CaptchaHandler._normalize_type("") == "unknown"
    assert CaptchaHandler._normalize_type("recaptcha") == "recaptcha"
    assert CaptchaHandler._normalize_type("hcaptcha") == "hcaptcha"


def test_captcha_solve_action_fields():
    action = CaptchaSolveAction(captcha_type="recaptcha")
    assert action.captcha_type == "recaptcha"
    assert action.captcha_element_id is None
    assert action.solved_text is None

    dumped = action.model_dump()
    assert "solved_text" not in dumped
    assert "captcha_element_id" in dumped


def test_captcha_solve_action_execution_message_with_solved_text():
    action = CaptchaSolveAction(captcha_type="image")
    action.solved_text = "XY42Z"
    msg = action.execution_message()
    assert "XY42Z" in msg
    assert "fill" in msg.lower()


def test_captcha_solve_action_execution_message_without_solved_text():
    action = CaptchaSolveAction(captcha_type="recaptcha")
    msg = action.execution_message()
    assert "recaptcha" in msg.lower()
    assert "solved" not in msg.lower() or "Solved" in msg


@pytest.mark.asyncio
async def test_handle_captchas_raises_without_api_key(monkeypatch: pytest.MonkeyPatch):
    from notte_browser.errors import CaptchaSolverNotAvailableError

    monkeypatch.delenv("TWOCAPTCHA_API_KEY", raising=False)
    monkeypatch.delenv("TWO_CAPTCHA_API_KEY", raising=False)

    window = SimpleNamespace(page=object(), resource=SimpleNamespace(options=SimpleNamespace()))

    with pytest.raises(CaptchaSolverNotAvailableError):
        await CaptchaHandler.handle_captchas(window, CaptchaSolveAction(captcha_type="recaptcha"))

import os
from typing import Any, ClassVar

from notte_core.actions import CaptchaSolveAction
from notte_core.common.config import BrowserBackend, config
from notte_core.common.logging import logger

from notte_browser.errors import CaptchaSolverNotAvailableError
from notte_browser.window import BrowserWindow


class CaptchaHandler:
    is_available: ClassVar[bool] = False
    _API_KEY_ENV_VARS: ClassVar[tuple[str, str]] = ("TWOCAPTCHA_API_KEY", "TWO_CAPTCHA_API_KEY")

    @classmethod
    def _get_api_key(cls) -> str | None:
        for env_var in cls._API_KEY_ENV_VARS:
            api_key = os.getenv(env_var)
            if api_key:
                return api_key
        return None

    @classmethod
    def _check_available(cls) -> bool:
        """Check if captcha solving dependencies and API key are available."""
        try:
            import playwright_captcha  # noqa: F401
            from twocaptcha import AsyncTwoCaptcha  # noqa: F401
        except ImportError:
            return False
        return cls._get_api_key() is not None

    @staticmethod
    def _get_framework_type(window: BrowserWindow, framework_type_enum: Any) -> Any:
        if window.resource.options.browser_type == "camoufox":
            return framework_type_enum.CAMOUFOX
        if config.browser_backend == BrowserBackend.PATCHRIGHT:
            return framework_type_enum.PATCHRIGHT
        return framework_type_enum.PLAYWRIGHT

    @staticmethod
    def _get_candidates(captcha_type: str | None, captcha_type_enum: Any) -> list[Any]:
        match captcha_type:
            case "recaptcha":
                return [captcha_type_enum.RECAPTCHA_V2, captcha_type_enum.RECAPTCHA_V3]
            case "cloudflare":
                return [
                    captcha_type_enum.CLOUDFLARE_TURNSTILE,
                    captcha_type_enum.CLOUDFLARE_INTERSTITIAL,
                ]
            case None | "unknown":
                return [
                    captcha_type_enum.RECAPTCHA_V2,
                    captcha_type_enum.CLOUDFLARE_TURNSTILE,
                    captcha_type_enum.CLOUDFLARE_INTERSTITIAL,
                    captcha_type_enum.RECAPTCHA_V3,
                ]
            case _:
                return []

    @staticmethod
    async def handle_captchas(window: BrowserWindow, action: CaptchaSolveAction) -> bool:
        """
        Solve a captcha on the current page using playwright-captcha and 2Captcha.

        The agent visually detects captchas via screenshots and emits CaptchaSolveAction.
        This handler maps the agent's hint onto the captcha types supported by the current
        playwright-captcha release and lets the next observation confirm the result.
        """
        api_key = CaptchaHandler._get_api_key()
        if not api_key:
            raise CaptchaSolverNotAvailableError()

        try:
            from playwright_captcha import CaptchaType, FrameworkType, TwoCaptchaSolver
            from twocaptcha import AsyncTwoCaptcha
        except ImportError as exc:
            raise CaptchaSolverNotAvailableError() from exc

        page = window.page
        framework = CaptchaHandler._get_framework_type(window, FrameworkType)
        candidates = CaptchaHandler._get_candidates(action.captcha_type, CaptchaType)

        logger.info(
            f"🔓 Attempting to solve captcha (hint={action.captcha_type or 'auto-detect'}, framework={framework.value})..."
        )

        if not candidates:
            logger.warning(
                "⚠️ The requested captcha type is not supported by the current local solver. "
                "playwright-captcha currently supports reCAPTCHA v2/v3 and Cloudflare Turnstile/Interstitial. "
                "For unsupported captcha types, use the cloud SDK: client.Session(solve_captchas=True)."
            )
            await window.long_wait()
            return True

        solver_client = AsyncTwoCaptcha(api_key)
        last_error: Exception | None = None

        async with TwoCaptchaSolver(
            framework=framework,
            page=page,
            async_two_captcha_client=solver_client,
        ) as solver:
            for candidate in candidates:
                try:
                    await solver.solve_captcha(captcha_container=page, captcha_type=candidate)
                except Exception as exc:  # pragma: no cover - exercised with mocked failures
                    last_error = exc
                    logger.debug(f"Captcha solver could not solve {candidate.value}: {exc}")
                    continue

                logger.info(f"✅ {candidate.value} solved successfully")
                break
            else:
                logger.warning(
                    f"⚠️ Could not solve captcha for hint '{action.captcha_type or 'auto-detect'}'. "
                    "The agent will re-check the page state on the next observation."
                )
                if last_error is not None:
                    logger.debug(f"Last captcha solver error: {last_error}")

        await window.long_wait()
        return True


CaptchaHandler.is_available = CaptchaHandler._check_available()

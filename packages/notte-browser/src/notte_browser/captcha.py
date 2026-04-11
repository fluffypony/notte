"""Captcha solver using 2Captcha API directly for comprehensive captcha type coverage.

Replaces the previous playwright-captcha wrapper with direct 2captcha-python SDK calls.
Supports all 2Captcha task types including human/image solving.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import re
import tempfile
from typing import Any, ClassVar, TYPE_CHECKING

if TYPE_CHECKING:
    from notte_browser.window import BrowserWindow
    from notte_core.actions.actions import CaptchaSolveAction
    from notte_core.browser.snapshot import BrowserSnapshot

logger = logging.getLogger(__name__)


class CaptchaHandler:
    """Handles captcha detection, solving, and result injection using 2Captcha."""

    is_available: ClassVar[bool] = False

    # ══════════════════════════════════════════════════════════════════
    # JavaScript Constants
    # ══════════════════════════════════════════════════════════════════

    CAPTCHA_PROBE_INIT_JS = """
    (() => {
        if (window.__notte_captcha_ctx) return;
        window.__notte_captcha_ctx = {};
        const ctx = window.__notte_captcha_ctx;

        const hookRecaptcha = (obj, prefix) => {
            if (!obj) return;
            const origRender = obj.render;
            if (origRender) {
                obj.render = function(container, params) {
                    ctx[prefix + '_render'] = {
                        sitekey: params?.sitekey,
                        callback: params?.callback?.name || null,
                        action: params?.action || null,
                        size: params?.size || null,
                        badge: params?.badge || null,
                        's': params?.['s'] || null,
                    };
                    return origRender.apply(this, arguments);
                };
            }
            const origExecute = obj.execute;
            if (origExecute) {
                obj.execute = function(sitekey, opts) {
                    ctx[prefix + '_execute'] = { sitekey, action: opts?.action };
                    return origExecute.apply(this, arguments);
                };
            }
        };

        let _grecaptcha = window.grecaptcha;
        Object.defineProperty(window, 'grecaptcha', {
            get: () => _grecaptcha,
            set: (val) => {
                _grecaptcha = val;
                if (val) {
                    hookRecaptcha(val, 'recaptcha');
                    if (val.enterprise) hookRecaptcha(val.enterprise, 'recaptcha_enterprise');
                }
            },
            configurable: true,
        });

        let _turnstile = window.turnstile;
        Object.defineProperty(window, 'turnstile', {
            get: () => _turnstile,
            set: (val) => {
                _turnstile = val;
                if (val && val.render) {
                    const origRender = val.render;
                    val.render = function(container, params) {
                        ctx.turnstile_render = {
                            sitekey: params?.sitekey,
                            action: params?.action || null,
                            cData: params?.cData || null,
                            chlPageData: params?.chlPageData || null,
                            callback: params?.callback?.name || null,
                        };
                        return origRender.apply(this, arguments);
                    };
                }
            },
            configurable: true,
        });

        let _hcaptcha = window.hcaptcha;
        Object.defineProperty(window, 'hcaptcha', {
            get: () => _hcaptcha,
            set: (val) => {
                _hcaptcha = val;
                if (val && val.render) {
                    const origRender = val.render;
                    val.render = function(container, params) {
                        ctx.hcaptcha_render = {
                            sitekey: params?.sitekey,
                            callback: params?.callback?.name || null,
                        };
                        return origRender.apply(this, arguments);
                    };
                }
            },
            configurable: true,
        });

        const origInitGeetest = window.initGeetest;
        window.initGeetest = function(config, callback) {
            ctx.geetest_init = { gt: config?.gt, challenge: config?.challenge, product: config?.product };
            if (origInitGeetest) return origInitGeetest.apply(this, arguments);
        };
        const origInitGeetest4 = window.initGeetest4;
        window.initGeetest4 = function(config, callback) {
            ctx.geetest4_init = { captcha_id: config?.captcha_id, product: config?.product };
            if (origInitGeetest4) return origInitGeetest4.apply(this, arguments);
        };
    })();
    """

    DETECT_AND_EXTRACT_JS = """
    () => {
        const result = {
            type: null, sitekey: null, action: null,
            gt: null, challenge: null, captcha_id: null,
            captcha_url: null, publickey: null,
            iv: null, context: null, script_src: null,
            is_invisible: false, is_enterprise: false,
            extra: {}
        };

        const ctx = window.__notte_captcha_ctx || {};

        if (ctx.recaptcha_enterprise_render || ctx.recaptcha_enterprise_execute) {
            result.type = 'recaptcha';
            result.is_enterprise = true;
            const r = ctx.recaptcha_enterprise_render || {};
            const e = ctx.recaptcha_enterprise_execute || {};
            result.sitekey = r.sitekey || e.sitekey;
            result.action = r.action || e.action;
            result.is_invisible = r.size === 'invisible';
            result.extra.data_s = r.s || null;
            return result;
        }
        if (ctx.recaptcha_render || ctx.recaptcha_execute) {
            result.type = 'recaptcha';
            const r = ctx.recaptcha_render || {};
            const e = ctx.recaptcha_execute || {};
            result.sitekey = r.sitekey || e.sitekey;
            result.action = r.action || e.action;
            result.is_invisible = r.size === 'invisible';
            return result;
        }

        const recapEl = document.querySelector('.g-recaptcha[data-sitekey]');
        if (recapEl) {
            result.type = 'recaptcha';
            result.sitekey = recapEl.getAttribute('data-sitekey');
            result.action = recapEl.getAttribute('data-action');
            result.is_invisible = recapEl.getAttribute('data-size') === 'invisible';
            result.is_enterprise = !!document.querySelector('script[src*="enterprise"]');
            result.extra.data_s = recapEl.getAttribute('data-s');
            return result;
        }
        const recapIframe = document.querySelector('iframe[src*="recaptcha/api2"], iframe[src*="recaptcha/enterprise"]');
        if (recapIframe) {
            result.type = 'recaptcha';
            result.is_enterprise = recapIframe.src.includes('enterprise');
            const m = recapIframe.src.match(/[?&]k=([^&]+)/);
            if (m) result.sitekey = m[1];
            return result;
        }

        if (ctx.hcaptcha_render) {
            result.type = 'hcaptcha';
            result.sitekey = ctx.hcaptcha_render.sitekey;
            return result;
        }
        const hcapEl = document.querySelector('.h-captcha[data-sitekey], [data-hcaptcha-sitekey]');
        if (hcapEl) {
            result.type = 'hcaptcha';
            result.sitekey = hcapEl.getAttribute('data-sitekey') || hcapEl.getAttribute('data-hcaptcha-sitekey');
            return result;
        }
        const hcapIframe = document.querySelector('iframe[src*="hcaptcha.com"]');
        if (hcapIframe) {
            result.type = 'hcaptcha';
            const m = hcapIframe.src.match(/sitekey=([^&]+)/);
            if (m) result.sitekey = m[1];
            return result;
        }

        if (ctx.turnstile_render) {
            result.type = 'turnstile';
            result.sitekey = ctx.turnstile_render.sitekey;
            result.action = ctx.turnstile_render.action;
            result.extra.cData = ctx.turnstile_render.cData;
            result.extra.chlPageData = ctx.turnstile_render.chlPageData;
            return result;
        }
        const cfEl = document.querySelector('.cf-turnstile[data-sitekey], [data-turnstile-sitekey]');
        if (cfEl) {
            result.type = 'turnstile';
            result.sitekey = cfEl.getAttribute('data-sitekey') || cfEl.getAttribute('data-turnstile-sitekey');
            result.action = cfEl.getAttribute('data-action');
            return result;
        }
        if (document.querySelector('#challenge-form, #challenge-running, .ray_id, iframe[src*="challenges.cloudflare.com"]')) {
            result.type = 'turnstile';
            const sk = document.querySelector('[name="cf-turnstile-response"]');
            if (sk) {
                const parent = sk.closest('[data-sitekey]');
                if (parent) result.sitekey = parent.getAttribute('data-sitekey');
            }
            return result;
        }

        const arkoseEl = document.querySelector('[data-pkey]');
        if (arkoseEl) {
            result.type = 'funcaptcha';
            result.publickey = arkoseEl.getAttribute('data-pkey');
            return result;
        }
        const arkoseIframe = document.querySelector('iframe[src*="arkoselabs.com"], iframe[src*="funcaptcha.com"]');
        if (arkoseIframe) {
            result.type = 'funcaptcha';
            const m = arkoseIframe.src.match(/pk=([^&]+)/);
            if (m) result.publickey = m[1];
            return result;
        }

        if (ctx.geetest_init) {
            result.type = 'geetest';
            result.gt = ctx.geetest_init.gt;
            result.challenge = ctx.geetest_init.challenge;
            return result;
        }
        const geetestEl = document.querySelector('.geetest_holder, .geetest_captcha, .geetest_radar_tip');
        if (geetestEl) {
            result.type = 'geetest';
            const gtEl = document.querySelector('[data-gt]');
            if (gtEl) {
                result.gt = gtEl.getAttribute('data-gt');
                result.challenge = gtEl.getAttribute('data-challenge');
            }
            if (!result.gt) {
                for (const s of document.querySelectorAll('script')) {
                    const text = s.textContent || '';
                    const gtM = text.match(/gt["']?\\s*[:=]\\s*["']([a-f0-9]{32})["']/);
                    if (gtM) result.gt = gtM[1];
                    const chM = text.match(/challenge["']?\\s*[:=]\\s*["']([a-f0-9]+)["']/);
                    if (chM) result.challenge = chM[1];
                }
            }
            return result;
        }

        if (ctx.geetest4_init) {
            result.type = 'geetest_v4';
            result.captcha_id = ctx.geetest4_init.captcha_id;
            return result;
        }
        if (document.querySelector('[class*="geetest_v4"]') || window.initGeetest4) {
            result.type = 'geetest_v4';
            if (window.captcha_id) result.captcha_id = window.captcha_id;
            return result;
        }

        const ddIframe = document.querySelector('iframe[src*="datadome"], iframe[src*="captcha-delivery"], iframe[src*="interstitial"]');
        if (ddIframe) {
            result.type = 'datadome';
            result.captcha_url = ddIframe.src;
            return result;
        }
        if (document.querySelector('#datadome-captcha, [data-datadome], .dd-captcha')) {
            result.type = 'datadome';
            result.captcha_url = window.location.href;
            return result;
        }

        const awsEl = document.querySelector('#captcha-container[data-sitekey], script[src*="awswaf"]');
        if (awsEl) {
            result.type = 'amazon_waf';
            const container = document.querySelector('#captcha-container');
            if (container) {
                result.sitekey = container.getAttribute('data-sitekey');
                result.iv = container.getAttribute('data-iv') || '';
                result.context = container.getAttribute('data-context') || '';
            }
            const awsScript = document.querySelector('script[src*="awswaf"], script[src*="captcha.js"], script[src*="jsapi.js"]');
            if (awsScript) result.script_src = awsScript.src;
            return result;
        }

        const mtEl = document.querySelector('[data-mtcaptcha-key], .mtcaptcha');
        if (mtEl) {
            result.type = 'mtcaptcha';
            result.sitekey = mtEl.getAttribute('data-mtcaptcha-key') ||
                document.querySelector('[data-mtcaptcha-key]')?.getAttribute('data-mtcaptcha-key');
            return result;
        }

        const fcEl = document.querySelector('.frc-captcha[data-sitekey], [data-frc-captcha-sitekey]');
        if (fcEl) {
            result.type = 'friendly_captcha';
            result.sitekey = fcEl.getAttribute('data-sitekey') || fcEl.getAttribute('data-frc-captcha-sitekey');
            return result;
        }

        if (document.querySelector('#div_for_keycaptcha, script[src*="keycaptcha"]')) {
            result.type = 'keycaptcha';
            return result;
        }

        const csEl = document.querySelector('[data-masterurlid]');
        if (csEl) {
            result.type = 'cybersiara';
            result.extra.master_url_id = csEl.getAttribute('data-masterurlid');
            return result;
        }

        const cutEl = document.querySelector('[data-misery-key]');
        if (cutEl) {
            result.type = 'cutcaptcha';
            result.extra.misery_key = cutEl.getAttribute('data-misery-key');
            result.extra.api_key = cutEl.getAttribute('data-api-key');
            return result;
        }

        if (document.querySelector('#TencentCaptcha, [data-appid]')) {
            result.type = 'tencent';
            const tEl = document.querySelector('[data-appid]');
            if (tEl) result.sitekey = tEl.getAttribute('data-appid');
            return result;
        }

        const captchaImg = document.querySelector('img[src*="captcha" i], img[alt*="captcha" i], img[id*="captcha" i]');
        if (captchaImg) {
            result.type = 'image';
            result.extra.img_src = captchaImg.src;
            return result;
        }

        if (document.cookie.includes('datadome=')) {
            result.type = 'datadome';
            result.captcha_url = window.location.href;
            return result;
        }

        return result;
    }
    """

    INJECT_TOKEN_JS = """
    (args) => {
        const [token, captchaType] = args;

        document.querySelectorAll(
            '#g-recaptcha-response, [name="g-recaptcha-response"], textarea[name="g-recaptcha-response"]'
        ).forEach(el => {
            el.value = token;
            el.innerHTML = token;
            el.style.display = 'block';
            el.dispatchEvent(new Event('input', {bubbles: true}));
            el.dispatchEvent(new Event('change', {bubbles: true}));
        });

        if (typeof ___grecaptcha_cfg !== 'undefined' && ___grecaptcha_cfg.clients) {
            Object.values(___grecaptcha_cfg.clients).forEach(client => {
                function findAndCall(obj, depth) {
                    if (!obj || typeof obj !== 'object' || depth > 5) return;
                    Object.values(obj).forEach(v => {
                        if (typeof v === 'object' && v !== null) {
                            if (typeof v.callback === 'function') {
                                try { v.callback(token); } catch(e) {}
                            } else {
                                findAndCall(v, depth + 1);
                            }
                        }
                    });
                }
                findAndCall(client, 0);
            });
        }
        if (typeof grecaptcha !== 'undefined') {
            try { grecaptcha.enterprise?.execute?.(); } catch(e) {}
            try { grecaptcha.execute?.(); } catch(e) {}
        }

        document.querySelectorAll(
            '[name="h-captcha-response"], textarea[name="h-captcha-response"]'
        ).forEach(el => {
            el.value = token;
            el.innerHTML = token;
        });
        if (typeof hcaptcha !== 'undefined') {
            try { hcaptcha.execute(); } catch(e) {}
        }

        document.querySelectorAll(
            '[name="cf-turnstile-response"], input[name*="turnstile"]'
        ).forEach(el => { el.value = token; });
        if (typeof turnstile !== 'undefined') {
            try { turnstile.execute(); } catch(e) {}
        }

        const fcToken = document.querySelector('#FunCaptcha-Token, [name="fc-token"]');
        if (fcToken) fcToken.value = token;
        if (typeof ArkoseEnforcement !== 'undefined' && ArkoseEnforcement.callback) {
            try { ArkoseEnforcement.callback(token); } catch(e) {}
        }

        const responseEl = document.querySelector(
            '[name="g-recaptcha-response"], [name="h-captcha-response"], [name="cf-turnstile-response"]'
        );
        if (responseEl) {
            const form = responseEl.closest('form');
            if (form) {
                const submitBtn = form.querySelector('[type="submit"], button:not([type="button"])');
                if (submitBtn) submitBtn.click();
                else form.dispatchEvent(new Event('submit', {bubbles: true}));
            }
        }
    }
    """

    # ══════════════════════════════════════════════════════════════════
    # Type Alias Normalization
    # ══════════════════════════════════════════════════════════════════

    _TYPE_ALIASES: ClassVar[dict[str, str]] = {
        "cloudflare": "turnstile",
        "arkose labs": "funcaptcha",
        "arkose": "funcaptcha",
        "press&hold": "press_hold",
        "press-and-hold": "press_hold",
        "auth0": "unknown",
        "normal": "image",
        "recaptcha_v2": "recaptcha",
        "recaptcha_v3": "recaptcha",
        "recaptcha enterprise": "recaptcha",
        "recaptcha_enterprise": "recaptcha",
        "cf": "turnstile",
        "friendly": "friendly_captcha",
        "amazon": "amazon_waf",
    }

    # ══════════════════════════════════════════════════════════════════
    # Availability & Setup
    # ══════════════════════════════════════════════════════════════════

    @classmethod
    def _check_available(cls) -> bool:
        try:
            from twocaptcha import TwoCaptcha  # noqa: F401
        except ImportError:
            return False
        return cls._get_api_key() is not None

    @staticmethod
    def _get_api_key() -> str | None:
        return os.environ.get("TWOCAPTCHA_API_KEY") or os.environ.get("TWO_CAPTCHA_API_KEY")

    @staticmethod
    def _create_solver() -> Any:
        from twocaptcha import TwoCaptcha

        api_key = CaptchaHandler._get_api_key()
        if not api_key:
            from notte_browser.errors import CaptchaSolverNotAvailableError

            raise CaptchaSolverNotAvailableError()
        return TwoCaptcha(api_key, defaultTimeout=180, pollingInterval=10)

    @classmethod
    def _normalize_type(cls, hint: str | None) -> str:
        if not hint:
            return "unknown"
        normalized = hint.strip().lower()
        return cls._TYPE_ALIASES.get(normalized, normalized)

    @staticmethod
    async def _get_browser_user_agent(page: Any) -> str:
        try:
            return await page.evaluate("navigator.userAgent")
        except Exception:
            return ""

    @staticmethod
    def _get_proxy_for_2captcha(window: "BrowserWindow") -> dict[str, str] | None:
        try:
            resource = window.resource
            if hasattr(resource, "options") and hasattr(resource.options, "proxy"):
                proxy = resource.options.proxy
                if proxy:
                    return {"type": "HTTP", "uri": str(proxy)}
        except Exception:
            pass
        return None

    # ══════════════════════════════════════════════════════════════════
    # Detection & Extraction
    # ══════════════════════════════════════════════════════════════════

    @staticmethod
    async def _detect_and_extract(page: Any) -> dict[str, Any]:
        try:
            return await page.evaluate(CaptchaHandler.DETECT_AND_EXTRACT_JS)
        except Exception as e:
            logger.debug(f"Captcha detection JS failed: {e}")
            return {"type": None, "sitekey": None}

    # ══════════════════════════════════════════════════════════════════
    # Token-based Solving (Direct 2Captcha API)
    # ══════════════════════════════════════════════════════════════════

    @staticmethod
    async def _solve_token_captcha(
        solver: Any,
        captcha_type: str,
        params: dict[str, Any],
        page_url: str,
        user_agent: str = "",
        proxy: dict[str, str] | None = None,
    ) -> str | None:
        sitekey = params.get("sitekey") or ""
        extra = params.get("extra", {})

        if not sitekey and captcha_type not in (
            "geetest", "geetest_v4", "datadome", "keycaptcha", "cybersiara", "cutcaptcha",
        ):
            return None

        try:
            result = None
            match captcha_type:
                case "recaptcha":
                    kwargs: dict[str, Any] = {"sitekey": sitekey, "url": page_url}
                    if params.get("is_enterprise"):
                        kwargs["enterprise"] = 1
                    if params.get("is_invisible") or params.get("action"):
                        kwargs["version"] = "v3"
                        kwargs["action"] = params.get("action") or "verify"
                    if extra.get("data_s"):
                        kwargs["data_s"] = extra["data_s"]
                    result = await asyncio.to_thread(solver.recaptcha, **kwargs)

                case "hcaptcha":
                    kwargs = {"sitekey": sitekey, "url": page_url}
                    result = await asyncio.to_thread(solver.hcaptcha, **kwargs)

                case "turnstile":
                    kwargs = {"sitekey": sitekey, "url": page_url}
                    if params.get("action"):
                        kwargs["action"] = params["action"]
                    if extra.get("cData"):
                        kwargs["data"] = extra["cData"]
                    result = await asyncio.to_thread(solver.turnstile, **kwargs)

                case "funcaptcha":
                    pk = params.get("publickey") or sitekey
                    kwargs = {"sitekey": pk, "url": page_url}
                    result = await asyncio.to_thread(solver.funcaptcha, **kwargs)

                case "geetest":
                    gt = params.get("gt")
                    challenge = params.get("challenge")
                    if gt:
                        result = await asyncio.to_thread(
                            solver.geetest, gt=gt, challenge=challenge or "", url=page_url
                        )

                case "geetest_v4":
                    cid = params.get("captcha_id")
                    if cid:
                        result = await asyncio.to_thread(
                            solver.geetest_v4, captcha_id=cid, url=page_url
                        )

                case "amazon_waf":
                    iv = params.get("iv", "")
                    context = params.get("context", "")
                    if iv and context:
                        result = await asyncio.to_thread(
                            solver.amazon_waf,
                            sitekey=sitekey, url=page_url, iv=iv, context=context,
                        )

                case "mtcaptcha":
                    result = await asyncio.to_thread(
                        solver.mtcaptcha, sitekey=sitekey, url=page_url
                    )

                case "keycaptcha":
                    try:
                        result = await asyncio.to_thread(
                            solver.keycaptcha, s_s_c_user_id="", s_s_c_session_id="",
                            s_s_c_web_server_sign="", s_s_c_web_server_sign2="", url=page_url,
                        )
                    except Exception:
                        return None

                case "lemin":
                    if sitekey:
                        result = await asyncio.to_thread(
                            solver.lemin, captcha_id=sitekey, url=page_url
                        )

                case "capy":
                    if sitekey:
                        result = await asyncio.to_thread(
                            solver.capy, sitekey=sitekey, url=page_url
                        )

                case "cybersiara":
                    master_url_id = extra.get("master_url_id")
                    if master_url_id:
                        result = await asyncio.to_thread(
                            solver.cybersiara, master_url_id=master_url_id, url=page_url
                        )

                case "cutcaptcha":
                    misery_key = extra.get("misery_key")
                    api_key = extra.get("api_key")
                    if misery_key:
                        result = await asyncio.to_thread(
                            solver.cutcaptcha, misery_key=misery_key, api_key=api_key or "", url=page_url,
                        )

                case "tencent":
                    if sitekey:
                        result = await asyncio.to_thread(
                            solver.tencent, app_id=sitekey, url=page_url
                        )

                case "atbcaptcha":
                    if sitekey:
                        result = await asyncio.to_thread(
                            solver.atb_captcha, app_id=sitekey, url=page_url
                        )

                case "captchafox":
                    if sitekey:
                        kwargs = {"sitekey": sitekey, "url": page_url}
                        if proxy:
                            kwargs["proxy"] = proxy
                        result = await asyncio.to_thread(solver.captcha_fox, **kwargs)

                case "prosopo":
                    if sitekey:
                        result = await asyncio.to_thread(
                            solver.prosopo, websiteURL=page_url, websiteKey=sitekey
                        )

                case "altcha":
                    if sitekey:
                        try:
                            result = await asyncio.to_thread(solver.altcha, sitekey=sitekey, url=page_url)
                        except (AttributeError, TypeError):
                            return None

                case _:
                    return None

            if result is None:
                return None
            if isinstance(result, dict):
                return result.get("code") or result.get("token") or str(result)
            return str(result)

        except Exception as e:
            logger.debug(f"Token-based solve failed for {captcha_type}: {e}")
            return None

    @staticmethod
    async def _inject_token(page: Any, token: str, captcha_type: str) -> bool:
        try:
            await page.evaluate(CaptchaHandler.INJECT_TOKEN_JS, [token, captcha_type])
            return True
        except Exception as e:
            logger.warning(f"Token injection failed for {captcha_type}: {e}")
            return False

    # ══════════════════════════════════════════════════════════════════
    # Provider-Specific Handlers
    # ══════════════════════════════════════════════════════════════════

    @staticmethod
    async def _handle_datadome(
        solver: Any, page: Any, params: dict[str, Any], proxy: dict[str, str] | None
    ) -> bool:
        captcha_url = params.get("captcha_url")
        if not captcha_url:
            logger.warning("DataDome: no captcha_url found")
            return False

        if "t=bv" in captcha_url:
            logger.error(
                "DataDome: IP appears banned (t=bv in captcha URL). "
                "Change proxy before retrying."
            )
            return False

        user_agent = await CaptchaHandler._get_browser_user_agent(page)

        kwargs: dict[str, Any] = {
            "websiteURL": page.url,
            "captchaUrl": captcha_url,
            "userAgent": user_agent,
        }
        if proxy:
            kwargs["proxy"] = proxy
        else:
            logger.warning("DataDome: no proxy configured; solving may fail due to IP mismatch.")

        try:
            result = await asyncio.to_thread(solver.datadome, **kwargs)
            cookie_value = result.get("cookie") if isinstance(result, dict) else str(result)
            if cookie_value:
                if "datadome=" in cookie_value:
                    cookie_value = cookie_value.split("datadome=")[1].split(";")[0]
                domain = "." + page.url.split("//")[1].split("/")[0]
                await page.context.add_cookies([{
                    "name": "datadome",
                    "value": cookie_value,
                    "domain": domain,
                    "path": "/",
                }])
                await page.reload()
                logger.info("DataDome: cookie injected and page reloaded")
                return True
        except Exception as e:
            logger.warning(f"DataDome solving failed: {e}")
        return False

    @staticmethod
    async def _handle_friendly_captcha(
        solver: Any, page: Any, params: dict[str, Any]
    ) -> bool:
        sitekey = params.get("sitekey")
        if not sitekey:
            return False

        try:
            await page.route(
                re.compile(r"friendlycaptcha.*module.*\.js", re.IGNORECASE),
                lambda route: route.abort(),
            )
            await page.reload()
            await page.wait_for_load_state("domcontentloaded")
            await page.wait_for_timeout(1000)

            result = await asyncio.to_thread(
                solver.friendly_captcha, sitekey=sitekey, url=page.url
            )
            token = result.get("code") if isinstance(result, dict) else str(result)
            if token:
                await page.evaluate("""(token) => {
                    const el = document.querySelector('[name="frc-captcha-solution"], .frc-captcha-solution');
                    if (el) { el.value = token; el.dispatchEvent(new Event('input', {bubbles: true})); }
                    const widget = document.querySelector('.frc-captcha');
                    if (widget) {
                        const cb = widget.getAttribute('data-callback');
                        if (cb && typeof window[cb] === 'function') window[cb](token);
                    }
                }""", token)
                logger.info("FriendlyCaptcha: solved and token injected")
                return True
        except Exception as e:
            logger.warning(f"FriendlyCaptcha solving failed: {e}")
        return False

    # ══════════════════════════════════════════════════════════════════
    # Screenshot-based Solving (Human Fallback)
    # ══════════════════════════════════════════════════════════════════

    @staticmethod
    async def _resolve_element_locator(
        page: Any, captcha_element_id: str, prev_snapshot: "BrowserSnapshot | None"
    ) -> Any | None:
        if not captcha_element_id or not prev_snapshot:
            return None
        try:
            node = prev_snapshot.dom_node.find(captcha_element_id)
            if node and node.computed_attributes and node.computed_attributes.selectors:
                from notte_browser.dom.locate import locate_element

                return await locate_element(page, node.computed_attributes.selectors)
        except Exception as e:
            logger.debug(f"Could not resolve element {captcha_element_id}: {e}")
        return None

    @staticmethod
    async def _capture_captcha_image(
        page: Any,
        locator: Any | None,
    ) -> bytes:
        if locator is not None:
            try:
                return await locator.screenshot()
            except Exception as e:
                logger.debug(f"Element screenshot failed, falling back to page screenshot: {e}")
        return await page.screenshot(type="png")

    @staticmethod
    async def _solve_via_screenshot(
        solver: Any,
        window: "BrowserWindow",
        action: "CaptchaSolveAction",
        prev_snapshot: "BrowserSnapshot | None",
        effective_type: str,
    ) -> bool:
        page = window.page

        locator = None
        if action.captcha_element_id:
            locator = await CaptchaHandler._resolve_element_locator(
                page, action.captcha_element_id, prev_snapshot
            )

        try:
            # Audio captcha
            if effective_type == "audio":
                audio_src = None
                if locator:
                    audio_src = await locator.get_attribute("src")
                if not audio_src:
                    audio_src = await page.evaluate(
                        "() => { const a = document.querySelector('audio[src], source[src]'); return a ? a.src || a.getAttribute('src') : null; }"
                    )
                if audio_src:
                    resp = await page.context.request.get(audio_src)
                    audio_bytes = await resp.body()
                    with tempfile.NamedTemporaryFile(suffix=".mp3", delete=False) as f:
                        f.write(audio_bytes)
                        tmp_path = f.name
                    try:
                        result = await asyncio.to_thread(solver.audio, tmp_path)
                        answer = result.get("code") if isinstance(result, dict) else str(result)
                        if answer:
                            filled = await CaptchaHandler._apply_text_answer(page, answer)
                            if not filled:
                                action.solved_text = answer
                            return True
                    finally:
                        os.unlink(tmp_path)
                return False

            # Capture image
            image_bytes = await CaptchaHandler._capture_captcha_image(page, locator)
            b64_image = base64.b64encode(image_bytes).decode("utf-8")

            # Grid captcha (tile selection)
            if effective_type == "grid":
                result = await asyncio.to_thread(
                    solver.grid,
                    file=f"base64:{b64_image}",
                    hintText="Select all matching tiles",
                )
                if result:
                    code = result.get("code") if isinstance(result, dict) else str(result)
                    logger.info(f"Grid captcha result: {code}")
                    return True

            # Coordinates / Click / Rotate captcha
            if effective_type in ("coordinates", "rotate"):
                method = solver.coordinates if effective_type == "coordinates" else solver.rotate
                hint_text = (
                    "Click on the correct areas to solve this captcha"
                    if effective_type == "coordinates"
                    else "Rotate the image to the correct orientation"
                )
                result = await asyncio.to_thread(
                    method, file=f"base64:{b64_image}", hintText=hint_text,
                )
                code = result.get("code") if isinstance(result, dict) else str(result)
                if code:
                    await CaptchaHandler._apply_coordinate_clicks(
                        page, code, await locator.bounding_box() if locator else None
                    )
                    return True

            # Default: normal image-to-text (human solving)
            hint = f"Solve the captcha. Type: {effective_type or 'unknown'}"
            result = await asyncio.to_thread(
                solver.normal, file=f"base64:{b64_image}", hintText=hint,
                caseSensitive=1,
            )
            answer = result.get("code") if isinstance(result, dict) else str(result)
            if answer:
                filled = await CaptchaHandler._apply_text_answer(page, answer)
                if not filled:
                    action.solved_text = answer
                    logger.info(f"Image captcha solved (text='{answer}'), could not auto-fill. "
                                "Agent will receive the text in execution message.")
                else:
                    logger.info("Image captcha solved and auto-filled")
                return True

        except Exception as e:
            logger.warning(f"Screenshot-based captcha solving failed: {e}")

        return False

    @staticmethod
    async def _apply_text_answer(page: Any, answer: str) -> bool:
        try:
            filled = await page.evaluate("""(answer) => {
                const selectors = [
                    'input[name*="captcha" i]', 'input[id*="captcha" i]',
                    'input[placeholder*="captcha" i]', 'input[aria-label*="captcha" i]',
                    'input[name*="answer" i]', 'input[id*="answer" i]',
                    'input[name*="code" i]', 'input[id*="verification" i]',
                    'input[class*="captcha" i]',
                ];
                for (const sel of selectors) {
                    const el = document.querySelector(sel);
                    if (el && el.offsetParent !== null) {
                        el.value = answer;
                        el.dispatchEvent(new Event('input', {bubbles: true}));
                        el.dispatchEvent(new Event('change', {bubbles: true}));
                        return true;
                    }
                }
                const inputs = document.querySelectorAll('input[type="text"]:not([type="hidden"])');
                for (const input of inputs) {
                    if (input.offsetParent !== null && !input.name.match(/email|password|user|login|search/i)) {
                        input.value = answer;
                        input.dispatchEvent(new Event('input', {bubbles: true}));
                        input.dispatchEvent(new Event('change', {bubbles: true}));
                        return true;
                    }
                }
                return false;
            }""", answer)
            if filled:
                await page.evaluate("""() => {
                    const btn = document.querySelector(
                        'button[type="submit"], input[type="submit"], button:not([type])'
                    );
                    if (btn && btn.offsetParent !== null) btn.click();
                }""")
            return bool(filled)
        except Exception as e:
            logger.debug(f"Auto-fill failed: {e}")
            return False

    @staticmethod
    async def _apply_coordinate_clicks(
        page: Any, coords_str: str, element_bbox: dict[str, float] | None = None
    ) -> None:
        offset_x = element_bbox["x"] if element_bbox else 0
        offset_y = element_bbox["y"] if element_bbox else 0

        points: list[tuple[float, float]] = []

        xy_matches = re.findall(r"x=(\d+),?\s*y=(\d+)", coords_str)
        if xy_matches:
            points = [(float(x), float(y)) for x, y in xy_matches]
        else:
            colon_matches = re.findall(r"(\d+):(\d+)", coords_str)
            if colon_matches:
                points = [(float(x), float(y)) for x, y in colon_matches]

        for x, y in points:
            await page.mouse.click(offset_x + x, offset_y + y)
            await page.wait_for_timeout(300)

    # ══════════════════════════════════════════════════════════════════
    # Result Reporting
    # ══════════════════════════════════════════════════════════════════

    @staticmethod
    async def _report_result(solver: Any, captcha_id: str | None, correct: bool) -> None:
        if not captcha_id:
            return
        try:
            await asyncio.to_thread(solver.report, captcha_id, correct)
        except Exception:
            pass

    # ══════════════════════════════════════════════════════════════════
    # Main Entry Point
    # ══════════════════════════════════════════════════════════════════

    @staticmethod
    async def handle_captchas(
        window: "BrowserWindow",
        action: "CaptchaSolveAction",
        prev_snapshot: "BrowserSnapshot | None" = None,
    ) -> bool:
        from notte_browser.errors import CaptchaSolverNotAvailableError

        api_key = CaptchaHandler._get_api_key()
        if not api_key:
            raise CaptchaSolverNotAvailableError()

        try:
            solver = CaptchaHandler._create_solver()
        except Exception as exc:
            raise CaptchaSolverNotAvailableError() from exc

        page = window.page
        hint = CaptchaHandler._normalize_type(action.captcha_type)
        proxy = CaptchaHandler._get_proxy_for_2captcha(window)
        user_agent = await CaptchaHandler._get_browser_user_agent(page)

        logger.info(f"Attempting to solve captcha (agent_hint='{action.captcha_type}', "
                     f"normalized='{hint}')...")

        # Step 1: Detect captcha type and extract params from DOM
        params = await CaptchaHandler._detect_and_extract(page)
        detected_type = params.get("type")

        effective_type = detected_type or hint
        effective_type = CaptchaHandler._normalize_type(effective_type)

        logger.info(f"   DOM detected: type='{detected_type}', sitekey={bool(params.get('sitekey'))}")

        # Step 2: Provider-specific handlers
        if effective_type == "datadome":
            if await CaptchaHandler._handle_datadome(solver, page, params, proxy):
                await window.long_wait()
                return True

        if effective_type == "friendly_captcha":
            if await CaptchaHandler._handle_friendly_captcha(solver, page, params):
                await window.long_wait()
                return True

        # Step 3: Token-based solving
        token = await CaptchaHandler._solve_token_captcha(
            solver, effective_type, params, page.url,
            user_agent=user_agent, proxy=proxy,
        )
        if token:
            injected = await CaptchaHandler._inject_token(page, token, effective_type)
            if injected:
                logger.info(f"{effective_type} captcha solved via token injection")
                await window.long_wait()
                return True
            else:
                logger.warning(f"Token obtained for {effective_type} but injection failed")

        # Step 4: If token solving failed and params were missing, try one reload
        if not token and not params.get("sitekey") and effective_type not in (
            "image", "text", "audio", "coordinates", "grid", "rotate",
            "press_hold", "unknown",
        ):
            logger.info("Reloading page to capture captcha init params...")
            try:
                await page.evaluate(CaptchaHandler.CAPTCHA_PROBE_INIT_JS)
                await page.reload()
                await page.wait_for_load_state("domcontentloaded")
                await window.short_wait()

                params = await CaptchaHandler._detect_and_extract(page)
                detected_type = params.get("type")
                if detected_type:
                    effective_type = CaptchaHandler._normalize_type(detected_type)
                    token = await CaptchaHandler._solve_token_captcha(
                        solver, effective_type, params, page.url,
                        user_agent=user_agent, proxy=proxy,
                    )
                    if token:
                        injected = await CaptchaHandler._inject_token(page, token, effective_type)
                        if injected:
                            logger.info(f"{effective_type} captcha solved after reload")
                            await window.long_wait()
                            return True
            except Exception as e:
                logger.debug(f"Reload-based retry failed: {e}")

        # Step 5: Screenshot-based human solving (universal fallback)
        logger.info("Falling back to screenshot-based human solving...")
        solved = await CaptchaHandler._solve_via_screenshot(
            solver, window, action, prev_snapshot, effective_type
        )
        if solved:
            logger.info("Captcha solved via screenshot-based human solving")
            await window.long_wait()
            return True

        # Failed all tiers
        logger.warning(
            f"Could not solve captcha (type='{effective_type}'). "
            "The agent will re-check the page state on the next observation."
        )
        await window.long_wait()
        return True


CaptchaHandler.is_available = CaptchaHandler._check_available()

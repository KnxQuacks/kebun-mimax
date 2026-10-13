#!/usr/bin/env python3
"""Client for the local captcha-solver sidecar (waguriagentic/captcha-solver).

Replaces the old in-browser TCaptcha slider solver. MiniMax's unified-login
now guards /v1/api/user/login/sms/send with reCAPTCHA Enterprise (invisible),
executing:

    grecaptcha.enterprise.execute(SITEKEY, {action: "send_code"})

and posting the resulting token as the `ticket` field of

    POST /v1/api/user/login/sms/send
    {"email": ..., "phone": "", "randStr": "", "ticket": "<recaptcha token>"}

Verified live 2026-10-13: action=send_code, token prefix 0cAFcWeA, len ~2400.

The sidecar runs standalone on Windows (no docker) — see run_sidecar.py.
Solve with real_page=True + classifier=yolo: MintMax's Enterprise invisible
sitekey rejects the render=<sitekey> stub form, and the invisible flow never
escalates to an image challenge, so the local ONNX model is enough (no Mistral
key required).

Env:
    CAPTCHA_SOLVER_URL   sidecar base (default http://127.0.0.1:8877)
    CAPTCHA_SOLVER_TOKEN Bearer token, if the sidecar enforces one
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

SOLVER_URL = os.environ.get("CAPTCHA_SOLVER_URL", "http://127.0.0.1:8877")

# MiniMax unified-login reCAPTCHA Enterprise config.
# The sitekey is the target page's public render key — set it via env (it is
# also visible in the page's enterprise.js?render=<sitekey> request) rather than
# baking it into the repo.
MINIMAX_SITEKEY = os.environ.get("MINIMAX_SITEKEY", "")
MINIMAX_LOGIN_URL = os.environ.get("MINIMAX_LOGIN_URL",
                                   "https://account.minimax.io/unified-login")
MINIMAX_CAPTCHA_ACTION = os.environ.get("MINIMAX_CAPTCHA_ACTION", "send_code")


def solve_recaptcha_send_code(solver_url: str = SOLVER_URL,
                              token: str | None = None,
                              sitekey: str = MINIMAX_SITEKEY,
                              url: str = MINIMAX_LOGIN_URL,
                              action: str = MINIMAX_CAPTCHA_ACTION,
                              proxy: str | None = None,
                              timeout_s: int = 120) -> str:
    """Return a fresh reCAPTCHA Enterprise token for MiniMax's sms/send gate.

    Raises RuntimeError on transport error or an unsolved challenge.
    """
    body = {
        "type": "recaptcha",
        "version": "invisible",
        "enterprise": True,
        "sitekey": sitekey,
        "url": url,
        "action": action,
        "real_page": True,
        "classifier": "yolo",
        "timeout_s": timeout_s,
    }
    if proxy:
        body["proxy"] = proxy
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        f"{solver_url.rstrip('/')}/solve",
        data=json.dumps(body).encode("utf-8"),
        headers=headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s + 60) as resp:
            payload = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise RuntimeError(
            f"captcha sidecar HTTP {e.code}: {e.read().decode(errors='replace')[:300]}"
        ) from None
    except Exception as e:
        raise RuntimeError(
            f"captcha sidecar unreachable at {solver_url}: {e}"
        ) from None
    if not payload.get("solved") or not payload.get("token"):
        raise RuntimeError(
            f"captcha not solved: {payload.get('error') or payload}"
        )
    return payload["token"]


if __name__ == "__main__":
    import os
    tok = solve_recaptcha_send_code(
        solver_url=os.environ.get("CAPTCHA_SOLVER_URL", SOLVER_URL),
        token=os.environ.get("CAPTCHA_SOLVER_TOKEN"),
        proxy=os.environ.get("CAPTCHA_PROXY"),
    )
    print(f"token len={len(tok)} prefix={tok[:24]}")

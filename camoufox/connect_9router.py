#!/usr/bin/env python3
"""Connect a MiniMax account to 9router as provider `minimax-code-global`.

Runs 9router's own device-code flow end to end:

  1. GET  /api/oauth/minimax-code-global/device-code   -> user_code + device_code
     + codeVerifier + verification_uri (the URL you'd authorize in a browser)
  2. Drive the MiniMax unified-login through the browser with that user_code as
     the login_redirect target: allocate an inbox, create the account, solve the
     reCAPTCHA via the local sidecar, submit the OTP, approve the device consent.
  3. POST /api/oauth/minimax-code-global/poll           -> 9router exchanges the
     device code for tokens and persists the provider connection itself.

Result: a new `minimax-code-global` connection appears in 9router.

Auth: logs into the 9router dashboard with NINEROUTER_PASSWORD and keeps the
session cookie. No direct DB writes — 9router owns persistence.

Usage:
    python connect_9router.py
    python connect_9router.py --proxy http://... --headed

Env:
    NINEROUTER_URL       default http://localhost:20128
    NINEROUTER_PASSWORD  dashboard password (required)
    MINIMAX_PROXY        egress proxy for the MiniMax browser (optional)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from http.cookiejar import CookieJar

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import minimax_camoufox as M  # noqa: E402

NINEROUTER_URL = os.environ.get("NINEROUTER_URL", "http://localhost:20128").rstrip("/")
NINEROUTER_PASSWORD = os.environ.get("NINEROUTER_PASSWORD", "")
PROVIDER = "minimax-code-global"


def _opener() -> urllib.request.OpenerDirector:
    jar = CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def _req(opener, method: str, path: str, body: dict | None = None,
         timeout: int = 30) -> dict:
    url = f"{NINEROUTER_URL}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with opener.open(req, timeout=timeout) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{method} {path} -> HTTP {e.code}: "
                           f"{e.read().decode(errors='replace')[:300]}") from None


def login(opener) -> None:
    if not NINEROUTER_PASSWORD:
        raise RuntimeError("NINEROUTER_PASSWORD is not set")
    res = _req(opener, "POST", "/api/auth/login", {"password": NINEROUTER_PASSWORD})
    if not res.get("success"):
        raise RuntimeError(f"9router login failed: {res}")
    print(f"[9r] logged in (mustChangePassword={res.get('mustChangePassword')})")


def start_device_code(opener) -> dict:
    res = _req(opener, "GET", f"/api/oauth/{PROVIDER}/device-code")
    print(f"[9r] device code: user_code={res.get('user_code')} "
          f"interval={res.get('interval')}s expires_in={res.get('expires_in')}s")
    print(f"[9r] authorize URL: {res.get('verification_uri')}")
    return res


def poll(opener, dc: dict, timeout_s: int = 300) -> dict:
    interval = int(dc.get("interval") or 5)
    deadline = time.time() + timeout_s
    extra = {"_minimaxPollByUser": dc.get("_minimaxPollByUser", False)}
    while time.time() < deadline:
        time.sleep(interval)
        res = _req(opener, "POST", f"/api/oauth/{PROVIDER}/poll", {
            "deviceCode": dc["device_code"],
            "codeVerifier": dc["codeVerifier"],
            "extraData": extra,
        })
        if res.get("success"):
            return res
        err = res.get("error")
        print(f"[9r] poll: {err}")
        if err == "slow_down":
            interval = min(interval + 5, 30)
        elif err in ("expired_token", "access_denied") or res.get("fatal"):
            raise RuntimeError(f"device flow failed: {res.get('errorDescription') or err}")
    raise RuntimeError("device flow timed out before authorization")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--proxy", default=os.environ.get("MINIMAX_PROXY") or None)
    ap.add_argument("--headed", action="store_true")
    ap.add_argument("--domain-index", type=int, default=0)
    args = ap.parse_args()

    opener = _opener()
    login(opener)

    # 1. 9router mints the device code it will poll.
    dc = start_device_code(opener)
    device_info = {
        "user_code": dc["user_code"],
        "device_code": dc["device_code"],
        "verifier": dc["codeVerifier"],
    }

    # 2. Browser creates + authorizes the account against that exact device code.
    print("[mmx] creating + authorizing account in browser...")
    rec = M.farm_one_account(
        proxy=args.proxy,
        headless=not args.headed,
        domain_index=args.domain_index,
        device_info=device_info,
    )
    print(f"[mmx] account authorized: {rec.get('email')}")

    # 3. 9router exchanges the device code and persists the connection.
    print("[9r] polling for token exchange...")
    result = poll(opener, dc)
    conn = result.get("connection") or {}
    print(f"[9r] SUCCESS — connection id={conn.get('id')} "
          f"provider={conn.get('provider')} email={conn.get('email')}")
    print(json.dumps(result, indent=2, ensure_ascii=False)[:800])
    return 0


if __name__ == "__main__":
    sys.exit(main())

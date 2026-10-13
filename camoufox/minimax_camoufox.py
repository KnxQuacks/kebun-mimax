#!/usr/bin/env python3
"""MiniMax in-browser account farmer (CloakBrowser + reCAPTCHA sidecar).

Everything happens inside ONE browser session on account.minimax.io:
  1. allocate a disposable inbox (mail.cx → tempik fallback)
  2. POST /oauth2/device/code (PKCE) to get device_code + user_code, the same
     way the mcode client does
  3. load /unified-login?login_redirect=/oauth-authorize?client_id=...&user_code=...
     so the browser lands on the real OAuth consent screen after login
  4. fill the email, click Continue — for a fresh inbox the server routes to
     the create-password screen (statusInfo 1200056)
  5. fill the password, click Continue — that handler runs
     grecaptcha.enterprise.execute(SITEKEY, {action: "send_code"}) and posts
     /v1/api/user/login/sms/send with the token as `ticket`
  6. we mint that token out of band via the local captcha-solver sidecar
     (waguriagentic/captcha-solver, no docker) and submit sms/send ourselves
     from the same browser session
  7. poll the inbox for the OTP, POST /oauth2/login
  8. exchange the device code for access_token/refresh_token (PKCE verifier)

The sidecar replaces the old in-browser TCaptcha slider: MiniMax migrated to
reCAPTCHA Enterprise (invisible) on 2026-10-13, so there is no slider to drag.

Usage:
    python minimax_camoufox.py --count 1
    python minimax_camoufox.py --count 5 --proxy "$MINIMAX_PROXY" --headed

Env:
    MINIMAX_PROXY        egress proxy (standing rule: never the home IP)
    CAPTCHA_SOLVER_URL   sidecar base URL (default http://127.0.0.1:8877)
    CAPTCHA_SOLVER_TOKEN Bearer token, if the sidecar enforces one
    TEMPIK_URL           self-hosted tempik base (optional fallback inbox)
    TEMPIK_SESSION_FILE  persisted session id (inboxes are session-scoped)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import random
import re
import secrets
import string
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Optional

# Make sibling modules importable regardless of CWD.
HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# Parent dir has mail_providers.py (mail.cx primary + tempik fallback)
_PARENT = os.path.dirname(HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import cloakbrowser  # noqa: E402
import captcha_client  # noqa: E402
import mail_providers  # noqa: E402

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ACCOUNT_BASE = "https://account.minimax.io"
UNIFIED_LOGIN = f"{ACCOUNT_BASE}/unified-login"

# OAuth device-code flow — identical to the mcode client (see
# minimax_farmer.py, proven against this exact endpoint).
OAUTH_CLIENT_ID = "mcode-public"
OAUTH_SCOPE = "agent.default"
OAUTH_AUDIENCE = "agent-backend"

# tempik — self-hosted CF Worker temp mail (same contract as mail_providers.py).
TEMPIK_BASE = os.environ.get("TEMPIK_URL", "").rstrip("/")
TEMPIK_DOMAINS = (
    os.environ.get("TEMPIK_DOMAINS") or ""
).split(",")
TEMPIK_SESSION_FILE = os.environ.get(
    "TEMPIK_SESSION_FILE", os.path.join(HERE, ".tempik-session")
)

CREDS_FILE = os.path.join(os.path.dirname(HERE), "minimax_accounts.jsonl")
CREDS_WRITE_LOCK = threading.Lock()
WIB = timezone(timedelta(hours=7))

DEFAULT_PROXY = os.environ.get(
    "MINIMAX_PROXY",
    "http://user-XXXXX"
    "XXXXX@proxy.example.com:10080",
)

# Local captcha-solver sidecar (waguriagentic/captcha-solver), no docker.
CAPTCHA_SOLVER_URL = os.environ.get("CAPTCHA_SOLVER_URL", "http://127.0.0.1:8877")
CAPTCHA_SOLVER_TOKEN = os.environ.get("CAPTCHA_SOLVER_TOKEN")

# MiniMax request-signing secret (the x-signature key embedded in the page
# bundle: md5(timestamp_s + SECRET + body)). Set via env; leave empty to skip
# signing (the OTP/oauth steps will then fail server-side).
SIGN_SECRET = os.environ.get("MINIMAX_SIGN_SECRET", "")

_log_lock = threading.Lock()


def log(msg: str) -> None:
    with _log_lock:
        print(f"[mma-ib] {msg}", flush=True)


def wib_now() -> str:
    return datetime.now(WIB).strftime("%Y-%m-%d %H:%M:%S WIB")


# ---------------------------------------------------------------------------
# 1. Disposable email (tempik) — session-scoped, persisted to disk
# ---------------------------------------------------------------------------

_tempik_sid: Optional[str] = None


def _tempik_http(method: str, path: str, payload=None, headers=None, timeout=15):
    url = f"{TEMPIK_BASE}{path}"
    data = None
    hdrs = {"Accept": "application/json", "User-Agent": "Mozilla/5.0"}
    if headers:
        hdrs.update(headers)
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def _persist_sid(sid: str) -> None:
    try:
        with open(TEMPIK_SESSION_FILE, "w", encoding="utf-8") as f:
            f.write(sid)
        os.chmod(TEMPIK_SESSION_FILE, 0o600)
    except OSError:
        pass


def tempik_session() -> str:
    """Return a session id, creating and persisting one if needed.

    Inboxes are scoped to the session, so the id must survive across process
    invocations — otherwise every inbox becomes unreadable and every account
    farmed with it is orphaned.
    """
    global _tempik_sid
    if _tempik_sid:
        return _tempik_sid
    try:
        with open(TEMPIK_SESSION_FILE, "r", encoding="utf-8") as f:
            saved = f.read().strip()
        if saved:
            _tempik_sid = saved
            return saved
    except OSError:
        pass
    status, body = _tempik_http("GET", "/api/session")
    if status != 200:
        raise RuntimeError(f"tempik /api/session HTTP {status}: {body[:120]}")
    sid = (json.loads(body) or {}).get("sessionId")
    if not sid:
        raise RuntimeError(f"tempik /api/session returned no sessionId: {body[:120]}")
    _tempik_sid = sid
    _persist_sid(sid)
    return sid


def allocate_tempik(domain_index: int = 0) -> tuple[str, str]:
    """Create an inbox. Returns (email, session_id)."""
    sid = tempik_session()
    domain = TEMPIK_DOMAINS[domain_index % len(TEMPIK_DOMAINS)]
    status, body = _tempik_http(
        "POST", "/api/inboxes", payload={"domain": domain},
        headers={"x-session-id": sid},
    )
    if status not in (200, 201):
        raise RuntimeError(f"tempik /api/inboxes HTTP {status}: {body[:120]}")
    address = (json.loads(body) or {}).get("address")
    if not address:
        raise RuntimeError(f"tempik returned no address: {body[:120]}")
    return address, sid


def _extract_otp(text: str) -> Optional[str]:
    """Pull a 6-digit code out of a tempik message body."""
    text = text or ""
    # Prefer a code introduced by a keyword so random numbers in footers
    # cannot win over the real code.
    m = re.search(
        r"(?:verification code|verify code|code is|your code|验证码)[^\d]{0,40}(\d{6})",
        text, re.IGNORECASE,
    )
    if m:
        return m.group(1)
    m = re.search(r"\b(\d{6})\b", text)
    return m.group(1) if m else None


def poll_tempik(email: str, sid: str, timeout: int = 120) -> Optional[str]:
    """Poll the inbox for MiniMax's OTP. Returns None on timeout."""
    url_path = f"/api/inboxes/{urllib.parse.quote(email, safe='')}/messages"
    deadline = time.time() + timeout
    seen: set = set()
    while time.time() < deadline:
        status, body = _tempik_http(
            "GET", url_path, headers={"x-session-id": sid}, timeout=20
        )
        if status == 200:
            try:
                msgs = json.loads(body)
            except json.JSONDecodeError:
                msgs = []
            if not isinstance(msgs, list):
                msgs = []
            for msg in msgs:
                if not isinstance(msg, dict):
                    continue
                mid = msg.get("id") or msg.get("message_id") or msg.get("subject")
                if mid is not None:
                    if mid in seen:
                        continue
                    seen.add(mid)
                blob = " ".join(
                    str(msg.get(k) or "")
                    for k in ("subject", "body", "text", "html",
                              "text_body", "html_body")
                )
                # strip tags so markup-borne digits cannot leak into the code
                blob = re.sub(r"<[^>]+>", " ", blob)
                code = _extract_otp(blob)
                if code:
                    return code
        time.sleep(2.5)
    return None


# ---------------------------------------------------------------------------
# 2. OAuth device code (same request the mcode client makes)
# ---------------------------------------------------------------------------


def _http_post_form(url: str, fields: dict, proxy: Optional[str] = None, timeout=20):
    """urlencoded POST via urllib, optionally through the farm proxy."""
    data = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/148.0.0.0 Safari/537.36"),
            "Origin": ACCOUNT_BASE,
            "Referer": UNIFIED_LOGIN,
        },
    )
    if proxy:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        )
    else:
        opener = urllib.request.build_opener()
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def request_device_code(proxy: Optional[str]) -> tuple[str, str, dict]:
    """PKCE device-code request. Returns (device_code, user_code, full_json)."""
    verifier = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).decode().rstrip("=")
    status, body = _http_post_form(
        f"{ACCOUNT_BASE}/oauth2/device/code",
        {
            "client_id": OAUTH_CLIENT_ID,
            "scope": OAUTH_SCOPE,
            "audience": OAUTH_AUDIENCE,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        proxy=proxy,
    )
    if status != 200:
        raise RuntimeError(f"device/code HTTP {status}: {body[:200]}")
    data = json.loads(body)
    device_code = data.get("device_code")
    user_code = data.get("user_code")
    if not device_code or not user_code:
        raise RuntimeError(f"device/code missing fields: {body[:200]}")
    return device_code, user_code, {"verifier": verifier, "challenge": challenge,
                                    "raw": data}


def exchange_device_code(device_code: str, verifier: str,
                         proxy: Optional[str]) -> Optional[dict]:
    """Mint the token pair with the PKCE verifier."""
    status, body = _http_post_form(
        f"{ACCOUNT_BASE}/oauth2/token",
        {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
            "client_id": OAUTH_CLIENT_ID,
            "code_verifier": verifier,
        },
        proxy=proxy,
    )
    if status != 200:
        log(f"oauth2/token HTTP {status}: {body[:200]}")
        return None
    return json.loads(body)


# ---------------------------------------------------------------------------
# 3. The in-browser flow
# ---------------------------------------------------------------------------


def _gen_password(length: int = 14) -> str:
    """A password MiniMax's create-password screen accepts: >= 6 chars with
    upper, lower, digit and symbol. t8 returns early below 6 chars and never
    calls the captcha otherwise."""
    import string
    rng = random.SystemRandom()
    pools = [
        string.ascii_uppercase,
        string.ascii_lowercase,
        string.digits,
        "!@#$%^&*",
    ]
    chars = [rng.choice(p) for p in pools]
    allpool = "".join(pools)
    chars += [rng.choice(allpool) for _ in range(length - len(pools))]
    rng.shuffle(chars)
    return "".join(chars)


def _human_sleep(lo: float = 0.4, hi: float = 1.1):
    time.sleep(random.uniform(lo, hi))


class MiniMaxBrowserFarmer:
    """One browser context = one account."""

    def __init__(self, proxy_url: Optional[str] = None, headless: bool = False):
        self.proxy_url = proxy_url
        self.headless = headless
        self.browser = None
        self.page = None
        self.context = None
        self.solver_url = CAPTCHA_SOLVER_URL
        self.solver_token = CAPTCHA_SOLVER_TOKEN
        self.email: Optional[str] = None
        self.device_code: Optional[str] = None
        self.user_code: Optional[str] = None
        self.verifier: Optional[str] = None
        self.captcha_attempts = 0
        self.password = _gen_password()

    # -- lifecycle ---------------------------------------------------------
    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.close()

    def start(self):
        # CloakBrowser (anti-detect Chromium) — same engine the local captcha
        # sidecar uses. humanize=True for mouse/scroll cadence.
        self.browser = cloakbrowser.launch(
            headless=self.headless,
            humanize=True,
            proxy=self.proxy_url or None,
        )
        self.context = self.browser.new_context()
        self.page = self.context.new_page()
        return self

    def close(self):
        if self.browser:
            try:
                self.browser.close()
            except Exception:
                pass
        self.browser = self.context = self.page = None

    # -- steps -------------------------------------------------------------
    def _goto_login(self):
        """Open the login page with the OAuth consent as the redirect target.

        The server validates `login_redirect` on /oauth2/login. Without a real
        device code the request fails with 1000021 "invalid scoped login
        context request", so mint one here if none is set yet.
        """
        if not self.user_code:
            self.device_code, self.user_code, pkce = request_device_code(
                self.proxy_url)
            self.verifier = pkce["verifier"]
            log(f"device code: user_code={self.user_code}")
        redirect = (
            f"/oauth-authorize?client_id={OAUTH_CLIENT_ID}"
            f"&user_code={self.user_code}"
        )
        url = (f"{UNIFIED_LOGIN}?login_redirect="
               f"{urllib.parse.quote(redirect, safe='')}")
        log(f"goto {url}")
        self.page.goto(url, wait_until="domcontentloaded", timeout=45000)
        try:
            self.page.wait_for_load_state("networkidle", timeout=20000)
        except Exception:
            pass

    def _fill_email(self, email: str):
        sel = ("input[type='email'], input[placeholder*='mail' i], "
               "input[name*='email' i], input[id*='email' i]")
        el = self.page.locator(sel).first
        el.hover(timeout=4000)
        _human_sleep(0.1, 0.3)
        el.click(delay=random.randint(60, 140))
        # type char by char — .fill() is detectable
        for ch in email:
            self.page.keyboard.type(ch, delay=random.randint(55, 150))
            if random.random() < 0.06:
                time.sleep(random.uniform(0.2, 0.5))
        log(f"email filled: {email}")

    def _agree_terms(self):
        """Tick the "I have read and agree" control on the entry screen.

        The control is a custom <button> (not an <input type=checkbox>) whose
        onClick flips agreedToTerms. The entry screen's Continue handler
        returns early unless it is ticked, and it is only rendered for the
        en locale (the zh login does not require it), so a missing row is
        not an error.
        """
        js = r"""
        () => {
          // The agreement control is a small 16px custom <button> next to the
          // terms text. Find the terms text element first, then its button.
          const txt = [...document.querySelectorAll('p, span, label, div')]
            .find(e => {
              const t = (e.innerText || '').trim();
              return /^I have read and agree/.test(t)
                  && t.length < 220
                  && !e.querySelector('p, span, label');
            });
          if (!txt) return { found: false };
          // walk up to the row that holds the button, then back down
          let host = txt;
          for (let i = 0; i < 4 && host; i += 1) {
            if (host.querySelector('button')) break;
            host = host.parentElement;
          }
          const btn = host && host.querySelector('button');
          if (!btn) return { found: false, txt: (txt.innerText||'').slice(0,60) };
          const r = btn.getBoundingClientRect();
          // empty circle = unticked, svg check icon = ticked
          const circle = btn.querySelector('div[class*="rounded-full"]');
          return { found: true, ticked: !circle && !!btn.querySelector('svg'),
                   x: r.x + r.width / 2, y: r.y + r.height / 2,
                   r: { w: Math.round(r.width), h: Math.round(r.height) },
                   txt: (txt.innerText||'').trim().slice(0, 60) };
        }
        """
        try:
            st = self.page.evaluate(js)
        except Exception as e:
            log(f"terms lookup failed ({e}); continuing")
            return
        if not st or not st.get("found"):
            log("terms: no agreement row found on this screen — skipping")
            return
        if st.get("ticked"):
            log("terms: already ticked")
            return
        _human_sleep(0.15, 0.35)
        self.page.mouse.move(st["x"], st["y"])
        _human_sleep(0.1, 0.25)
        self.page.mouse.click(st["x"], st["y"])
        # The onClick flips agreedToTerms; re-read until the check icon
        # replaces the empty circle, since the entry handler gates on the
        # React state, not on the DOM.
        after = None
        for _ in range(10):
            _human_sleep(0.25, 0.45)
            try:
                after = self.page.evaluate(js)
            except Exception:
                break
            if after and after.get("found") and after.get("ticked"):
                break
        if after and after.get("found"):
            log(f"terms ticked: {bool(after.get('ticked'))}")
        else:
            log("terms ticked (state unreadable)")

    def _wait_create_password(self, timeout: int = 30) -> bool:
        """True once /oauth2/login routed a new account to create-password.

        A fresh inbox gets statusInfo code 1200056 ("New user has not set a
        password"), which flips authMode to "create_password". That screen's
        Continue handler is the one that runs the reCAPTCHA execute + sms/send.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                n = self.page.locator("input[type='password']").count()
            except Exception:
                n = 0
            if n:
                return True
            time.sleep(0.5)
        return False

    def _fill_password(self):
        """Type the generated password into every password field on the
        create-password screen."""
        pw = self.password
        try:
            inputs = self.page.locator("input[type='password']")
            n = inputs.count()
            for i in range(n):
                el = inputs.nth(i)
                el.click(delay=random.randint(60, 140))
                for ch in pw:
                    self.page.keyboard.type(ch, delay=random.randint(45, 120))
                _human_sleep(0.1, 0.3)
            log(f"password filled into {n} field(s)")
            # t8 reads eK (the password state) at click time. React has not
            # necessarily flushed the last keystroke when keyboard.type()
            # returns, and the button's onClick closure captures the stale
            # value, so give the state a beat to settle before clicking.
            _human_sleep(0.6, 1.1)
        except Exception as e:
            raise RuntimeError(f"could not fill the password field: {e}")

    def _click_continue(self):
        el = self.page.locator("button:has-text('Continue')").first
        el.hover(timeout=2000)
        _human_sleep(0.08, 0.25)
        el.click(delay=random.randint(60, 160))
        log("clicked Continue")

    def _wait_otp_screen(self, timeout: int = 25) -> bool:
        """True once the page moved to the code-entry step.

        The page's own captcha callback has already called sms/send by then,
        so seeing the OTP inputs means the captcha + send both succeeded.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                n = self.page.locator(
                    "input[maxlength='1'], input[inputmode='numeric'], "
                    "input[type='tel'], input[placeholder*='code' i]"
                ).count()
            except Exception:
                n = 0
            # MiniMax now uses a single auto-advancing code input, so >=1 is the
            # signal (older builds split it across N per-digit boxes).
            if n >= 1:
                return True
            time.sleep(0.5)
        return False

    def _fill_otp(self, otp: str):
        """Type the code into the OTP inputs (one input per digit)."""
        try:
            inputs = self.page.locator(
                "input[maxlength='1'], input[inputmode='numeric'], input[type='tel']"
            )
            n = inputs.count()
            if n >= len(otp):
                for i, ch in enumerate(otp):
                    inputs.nth(i).click(delay=random.randint(40, 100))
                    self.page.keyboard.type(ch, delay=random.randint(60, 160))
                log(f"otp typed into {n} digit inputs")
                return
        except Exception:
            pass
        # single input fallback — wait_for_selector returns an ElementHandle,
        # which has .click()/.type() directly (wrapping it in page.locator()
        # yields the bogus "JSHandle@node" selector error).
        el = self.page.wait_for_selector(
            "input[placeholder*='code' i], input[name*='code' i], "
            "input[inputmode='numeric'], input[maxlength='1'], input[type='tel']",
            timeout=8000,
        )
        el.click()
        for ch in otp:
            self.page.keyboard.type(ch, delay=random.randint(60, 160))
        log("otp typed into single input")

    def _approve_consent(self):
        """If the OAuth consent screen appears after login, approve it in-page."""
        # The page redirects to /oauth-authorize?client_id=...&user_code=...
        deadline = time.time() + 40
        landed = False
        while time.time() < deadline:
            try:
                u = self.page.url or ""
            except Exception:
                u = ""
            if "oauth-authorize" in u:
                landed = True
                break
            time.sleep(0.5)
        if not landed:
            log("consent: oauth-authorize page never appeared")
            return
        log(f"consent screen: {self.page.url}")
        for sel in [
            "button:has-text('Approve')", "button:has-text('Authorize')",
            "button:has-text('Allow')", "button:has-text('Confirm')",
            "button:has-text('Continue')", "button[type='submit']",
        ]:
            try:
                el = self.page.locator(sel).first
                if el.is_visible(timeout=3000):
                    el.hover(timeout=2000)
                    _human_sleep(0.15, 0.4)
                    el.click(delay=random.randint(60, 160))
                    log(f"consent: clicked {sel}")
                    _human_sleep(1.5, 3.0)
                    return
            except Exception:
                continue
        log("consent: no approve button found (auto-approved or not required)")

    # -- the flow ----------------------------------------------------------
    def farm_one(self, domain_index: int = 0, max_captcha_rounds: int = 4,
                 device_info: Optional[dict] = None) -> dict:
        """Create one account entirely in-browser. Returns a record dict.

        device_info: when supplied, use an EXTERNAL device code (e.g. one minted
        by 9router's /api/oauth/minimax-code-global/device-code) instead of
        minting our own. The browser login then authorizes that exact device via
        the login_redirect, and the caller (9router) polls /oauth2/token for the
        tokens itself — so we skip our own token exchange. Keys:
        {"user_code", "device_code", "verifier"}.
        """
        t0 = time.time()
        record = {
            "email": None,
            "access_token": None,
            "refresh_token": None,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "method": "cloakbrowser-sidecar",
        }
        external_device = bool(device_info)

        # 1. Email — mail.cx primary, tempik fallback (via mail_providers)
        import requests as _rq
        _s = _rq.Session()
        self.email, mail_provider, sid = mail_providers.allocate_email(_s, domain_index)
        record["email"] = self.email
        log(f"email: {self.email} [{mail_provider}]")

        # 2. Device code (PKCE) — same request the mcode client makes. The
        #    browser later logs in with this user_code in the redirect, so the
        #    consent it approves is this device code's. _goto_login also mints
        #    one if called directly, so this is idempotent.
        #    With device_info, adopt the caller's device code instead.
        if external_device:
            self.user_code = device_info["user_code"]
            self.device_code = device_info.get("device_code")
            self.verifier = device_info.get("verifier")
            log(f"using external device code: user_code={self.user_code}")
        else:
            self.device_code, self.user_code, pkce = request_device_code(self.proxy_url)
            self.verifier = pkce["verifier"]
            log(f"device code: user_code={self.user_code}")

        # 3. Load the login page with the consent screen as the redirect.
        self._goto_login()

        # 4. Fill the email, tick the agreement control, click Continue.
        #    The entry handler calls /oauth2/login, which for a fresh inbox
        #    returns 1200056 "New user has not set a password" and routes to
        #    the create-password screen.
        self._fill_email(self.email)
        _human_sleep()
        self._agree_terms()
        _human_sleep()
        self._click_continue()

        # 5. If the account is new, the server routes to create-password.
        #    That screen's Continue handler is the one that runs the
        #    reCAPTCHA Enterprise execute + sms/send; the entry screen does not.
        if self._wait_create_password(timeout=30):
            log("routed to create_password")
            self._fill_password()
            _human_sleep()
            self._click_continue()
        else:
            log("no create_password screen (existing account?) — "
                "continuing to the captcha")

        # 6. Mint the reCAPTCHA Enterprise token via the local solver sidecar.
        #    MiniMax guards /v1/api/user/login/sms/send with
        #    grecaptcha.enterprise.execute(sitekey, {action: "send_code"}); the
        #    widget only fires from the create-password screen's Continue
        #    handler (the entry screen does not). We skip the in-page widget and
        #    ask the sidecar for a token directly, then post it as `ticket`.
        solved = False
        ticket = ""
        for round_no in range(1, max_captcha_rounds + 1):
            self.captcha_attempts = round_no
            try:
                ticket = captcha_client.solve_recaptcha_send_code(
                    solver_url=self.solver_url,
                    token=self.solver_token,
                    proxy=self.proxy_url,
                )
                log(f"captcha solved via sidecar (attempt {round_no}), "
                    f"token len={len(ticket)}")
                solved = True
                break
            except Exception as e:
                log(f"captcha round {round_no} failed: {e}")
        if not solved:
            raise RuntimeError(f"captcha not solved after {max_captcha_rounds} rounds")

        # 7. Call the send API directly using page context — the page's own
        #    callback would do this after the widget fires, but we minted the
        #    token out of band, so we submit it ourselves. This keeps cookies
        #    and headers correct (same browser session that will log in).
        #    randStr is empty: TCaptcha is gone, the token rides in `ticket`.
        if solved and ticket:
            log("captcha solved - calling send API directly")
            try:
                api_result = self.page.evaluate("""
                    async ({email, ticket, randstr, signSecret}) => {
                        try {
                            // Replicate the page's request signing
                            const now = Date.now();
                            const nowS = Math.floor(now / 1000);
                            const body = JSON.stringify({
                                email: email,
                                phone: '',
                                randStr: randstr,
                                ticket: ticket
                            }).replace(/[\\s]+/g, '');  // Remove all whitespace
                            
                            // Build query params matching the working farmer
                            const deviceId = Math.floor(10000000 + Math.random() * 90000000).toString();
                            const params = new URLSearchParams({
                                device_platform: 'web',
                                biz_id: '3',
                                app_id: '3001',
                                version_code: '22201',
                                unix: now.toString(),
                                timezone_offset: '-420',
                                sys_language: 'en',
                                lang: 'en',
                                device_id: deviceId,
                                client: 'web'
                            });
                            
                            const path = '/v1/api/user/login/sms/send?' + params.toString();
                            
                            // Simple MD5 implementation (pure JS, no crypto.subtle)
                            function md5(str) {
                                // Use a simple MD5 implementation
                                // For production, include a full MD5 library
                                function safeAdd(x, y) {
                                    const lsw = (x & 0xFFFF) + (y & 0xFFFF);
                                    const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
                                    return (msw << 16) | (lsw & 0xFFFF);
                                }
                                function bitRol(num, cnt) { return (num << cnt) | (num >>> (32 - cnt)); }
                                function md5cmn(q, a, b, x, s, t) { return safeAdd(bitRol(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b); }
                                function md5ff(a, b, c, d, x, s, t) { return md5cmn((b & c) | ((~b) & d), a, b, x, s, t); }
                                function md5gg(a, b, c, d, x, s, t) { return md5cmn((b & d) | (c & (~d)), a, b, x, s, t); }
                                function md5hh(a, b, c, d, x, s, t) { return md5cmn(b ^ c ^ d, a, b, x, s, t); }
                                function md5ii(a, b, c, d, x, s, t) { return md5cmn(c ^ (b | (~d)), a, b, x, s, t); }
                                
                                function binlMD5(x, len) {
                                    x[len >> 5] |= 0x80 << (len % 32);
                                    x[(((len + 64) >>> 9) << 4) + 14] = len;
                                    let a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;
                                    for (let i = 0; i < x.length; i += 16) {
                                        const olda = a, oldb = b, oldc = c, oldd = d;
                                        a = md5ff(a, b, c, d, x[i], 7, -680876936); d = md5ff(d, a, b, c, x[i+1], 12, -389564586);
                                        c = md5ff(c, d, a, b, x[i+2], 17, 606105819); b = md5ff(b, c, d, a, x[i+3], 22, -1044525330);
                                        a = md5ff(a, b, c, d, x[i+4], 7, -176418897); d = md5ff(d, a, b, c, x[i+5], 12, 1200080426);
                                        c = md5ff(c, d, a, b, x[i+6], 17, -1473231341); b = md5ff(b, c, d, a, x[i+7], 22, -45705983);
                                        a = md5ff(a, b, c, d, x[i+8], 7, 1770035416); d = md5ff(d, a, b, c, x[i+9], 12, -1958414417);
                                        c = md5ff(c, d, a, b, x[i+10], 17, -42063); b = md5ff(b, c, d, a, x[i+11], 22, -1990404162);
                                        a = md5ff(a, b, c, d, x[i+12], 7, 1804603682); d = md5ff(d, a, b, c, x[i+13], 12, -40341101);
                                        c = md5ff(c, d, a, b, x[i+14], 17, -1502002290); b = md5ff(b, c, d, a, x[i+15], 22, 1236535329);
                                        a = md5gg(a, b, c, d, x[i+1], 5, -165796510); d = md5gg(d, a, b, c, x[i+6], 9, -1069501632);
                                        c = md5gg(c, d, a, b, x[i+11], 14, 643717713); b = md5gg(b, c, d, a, x[i+0], 20, -373897302);
                                        a = md5gg(a, b, c, d, x[i+5], 5, -701558691); d = md5gg(d, a, b, c, x[i+10], 9, 38016083);
                                        c = md5gg(c, d, a, b, x[i+15], 14, -660478335); b = md5gg(b, c, d, a, x[i+4], 20, -405537848);
                                        a = md5gg(a, b, c, d, x[i+9], 5, 568446438); d = md5gg(d, a, b, c, x[i+14], 9, -1019803690);
                                        c = md5gg(c, d, a, b, x[i+3], 14, -187363961); b = md5gg(b, c, d, a, x[i+8], 20, 1163531501);
                                        a = md5gg(a, b, c, d, x[i+13], 5, -1444681467); d = md5gg(d, a, b, c, x[i+2], 9, -51403784);
                                        c = md5gg(c, d, a, b, x[i+7], 14, 1735328473); b = md5gg(b, c, d, a, x[i+12], 20, -1926607734);
                                        a = md5hh(a, b, c, d, x[i+5], 4, -378558); d = md5hh(d, a, b, c, x[i+8], 11, -2022574463);
                                        c = md5hh(c, d, a, b, x[i+11], 16, 1839030562); b = md5hh(b, c, d, a, x[i+14], 23, -35309556);
                                        a = md5hh(a, b, c, d, x[i+1], 4, -1530992060); d = md5hh(d, a, b, c, x[i+4], 11, 1272893353);
                                        c = md5hh(c, d, a, b, x[i+7], 16, -155497632); b = md5hh(b, c, d, a, x[i+10], 23, -1094730640);
                                        a = md5hh(a, b, c, d, x[i+13], 4, 681279174); d = md5hh(d, a, b, c, x[i+0], 11, -358537222);
                                        c = md5hh(c, d, a, b, x[i+3], 16, -722521979); b = md5hh(b, c, d, a, x[i+6], 23, 76029189);
                                        a = md5hh(a, b, c, d, x[i+9], 4, -640364487); d = md5hh(d, a, b, c, x[i+12], 11, -421815835);
                                        c = md5hh(c, d, a, b, x[i+15], 16, 530742520); b = md5hh(b, c, d, a, x[i+2], 23, -995338651);
                                        a = md5ii(a, b, c, d, x[i+0], 6, -198630844); d = md5ii(d, a, b, c, x[i+7], 10, 1126891415);
                                        c = md5ii(c, d, a, b, x[i+14], 15, -1416354905); b = md5ii(b, c, d, a, x[i+5], 21, -57434055);
                                        a = md5ii(a, b, c, d, x[i+12], 6, 1700485571); d = md5ii(d, a, b, c, x[i+3], 10, -1894986606);
                                        c = md5ii(c, d, a, b, x[i+10], 15, -1051523); b = md5ii(b, c, d, a, x[i+1], 21, -2054922799);
                                        a = md5ii(a, b, c, d, x[i+8], 6, 1873313359); d = md5ii(d, a, b, c, x[i+15], 10, -30611744);
                                        c = md5ii(c, d, a, b, x[i+6], 15, -1560198380); b = md5ii(b, c, d, a, x[i+13], 21, 1309151649);
                                        a = md5ii(a, b, c, d, x[i+4], 6, -145523070); d = md5ii(d, a, b, c, x[i+11], 10, -1120210379);
                                        c = md5ii(c, d, a, b, x[i+2], 15, 718787259); b = md5ii(b, c, d, a, x[i+9], 21, -343485551);
                                        a = safeAdd(a, olda); b = safeAdd(b, oldb); c = safeAdd(c, oldc); d = safeAdd(d, oldd);
                                    }
                                    return [a, b, c, d];
                                }
                                
                                function binl2rstr(input) {
                                    let output = '';
                                    for (let i = 0; i < input.length * 32; i += 8) {
                                        output += String.fromCharCode((input[i >> 5] >>> (i % 32)) & 0xFF);
                                    }
                                    return output;
                                }
                                
                                function rstr2binl(input) {
                                    const output = [];
                                    output[(input.length >> 2) - 1] = undefined;
                                    for (let i = 0; i < output.length; i += 1) output[i] = 0;
                                    for (let i = 0; i < input.length * 8; i += 8) {
                                        output[i >> 5] |= (input.charCodeAt(i / 8) & 0xFF) << (i % 32);
                                    }
                                    return output;
                                }
                                
                                function rstrMD5(s) { return binl2rstr(binlMD5(rstr2binl(s), s.length * 8)); }
                                function hexMD5(s) {
                                    const r = rstrMD5(s);
                                    let hex = '';
                                    for (let i = 0; i < r.length; i++) {
                                        const c = r.charCodeAt(i).toString(16);
                                        hex += c.length === 1 ? '0' + c : c;
                                    }
                                    return hex;
                                }
                                return hexMD5(str);
                            }
                            
                            // Verify MD5 implementation
                            const testMd5 = md5('hello');
                            if (testMd5 !== '5d41402abc4b2a76b9719d911017c592') {
                                return {error: 'MD5 incorrect: ' + testMd5};
                            }
                            
                            // Calculate yy signature (matching working farmer)
                            // yy = md5(encodeURIComponent(path) + "_" + body + md5(timestamp) + "ooui")
                            const md5Time = md5(now.toString());
                            const encodedPath = encodeURIComponent(path);
                            const yy = md5(encodedPath + '_' + body + md5Time + 'ooui');
                            
                            // Calculate x-signature (md5(timestamp_s + SECRET + body));
                            // SECRET is supplied as the `signSecret` evaluate arg.
                            const xsig = md5(nowS.toString() + signSecret + body);
                            
                            // Debug: log the exact request
                            console.log('Request path:', path);
                            console.log('Request body:', body);
                            console.log('yy:', yy);
                            console.log('x-signature:', xsig);
                            console.log('x-timestamp:', nowS.toString());
                            
                            const resp = await fetch(path, {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json',
                                    'yy': yy,
                                    'x-timestamp': nowS.toString(),
                                    'x-signature': xsig
                                },
                                credentials: 'include',
                                body: body
                            });
                            const data2 = await resp.json();
                            return {
                                status: resp.status, 
                                ok: resp.ok, 
                                data: data2,
                                debug: {
                                    path: path,
                                    body: body,
                                    yy: yy,
                                    xsig: xsig,
                                    timestamp: nowS
                                }
                            };
                        } catch (e) {
                            return {error: e.message};
                        }
                    }
                """, {
                    "email": self.email,
                    "ticket": ticket,
                    "randstr": "",
                    "signSecret": SIGN_SECRET,
                })
                log(f"send API result: {api_result}")
                
                # If API succeeded, continue with HTTP flow (like working farmer)
                if api_result.get('ok') or (api_result.get('data', {}).get('statusInfo', {}).get('code') == 0):
                    log("send API succeeded - continuing with HTTP flow")
                    
                    # Poll for OTP via mail_providers (mail.cx or tempik)
                    otp = mail_providers.poll_otp(_s, self.email, mail_provider, sid, timeout=120)
                    if not otp:
                        raise RuntimeError(f"OTP never arrived for {self.email}")
                    log(f"otp received: {otp}")

                    # Now do the rest via HTTP (faster and more reliable)
                    import requests as http_requests
                    import hashlib
                    import urllib.parse
                    import json
                    
                    # Login
                    now_ms = int(time.time() * 1000)
                    now_s = now_ms // 1000
                    device_id = str(10000000 + int(time.time() * 1000) % 90000000)
                    
                    login_body = {
                        "loginType": "21",
                        "email": self.email,
                        "code": otp,
                        "deviceID": device_id,
                        "login_redirect": f"/oauth-authorize?client_id=mcode-public&user_code={self.user_code}"
                    }
                    login_json = json.dumps(login_body, separators=(',', ':'))
                    
                    params = {
                        "device_platform": "web",
                        "biz_id": "3",
                        "app_id": "3001",
                        "version_code": "22201",
                        "unix": str(now_ms),
                        "timezone_offset": "-420",
                        "sys_language": "en",
                        "lang": "en",
                        "device_id": device_id,
                        "client": "web"
                    }
                    login_query = urllib.parse.urlencode(params)
                    login_path = f"/oauth2/login?{login_query}"
                    
                    # x-signature secret — from the page bundle: md5(timestamp_s + SECRET + body).
                    md5_time = hashlib.md5(str(now_ms).encode()).hexdigest()
                    yy = hashlib.md5((urllib.parse.quote(login_path, safe='') + "_" + login_json + md5_time + "ooui").encode()).hexdigest()
                    sig = hashlib.md5((str(now_s) + SIGN_SECRET + login_json).encode()).hexdigest()
                    
                    # Use the browser's session cookies
                    cookies = self.page.context.cookies()
                    session = http_requests.Session()
                    for c in cookies:
                        session.cookies.set(c['name'], c['value'], domain=c.get('domain', ''))
                    
                    headers = {
                        "Content-Type": "application/json",
                        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                        "x-timestamp": str(now_s),
                        "x-signature": sig,
                        "yy": yy,
                        "Referer": "https://account.minimax.io/unified-login"
                    }
                    
                    login_url = f"https://account.minimax.io{login_path}"
                    r_login = session.post(login_url, data=login_json, headers=headers)
                    log(f"login response: {r_login.status_code}")
                    
                    if r_login.status_code != 200:
                        raise RuntimeError(f"Login failed: {r_login.text[:200]}")
                    
                    # Approve device
                    r_info = session.get(f"https://account.minimax.io/oauth2/device/authorize?user_code={self.user_code}&app_id=3001")
                    info_data = r_info.json()
                    groups = info_data.get("groups", [])
                    if groups:
                        group_id = groups[0].get("group_id")
                        r_app = session.post(
                            "https://account.minimax.io/oauth2/device/authorize",
                            json={"user_code": self.user_code, "decision": "approve", "group_id": group_id},
                            headers={"Content-Type": "application/json", "Referer": f"https://account.minimax.io/oauth-authorize?user_code={self.user_code}"}
                        )
                        log(f"approve response: {r_app.status_code}")
                    
                    # EXTERNAL device (9router): the caller owns the token
                    # exchange (it polls /oauth2/token itself). Exchanging here
                    # would consume the device_code and 9router would see
                    # expired_token. We have already logged in + approved the
                    # device; stop before the exchange.
                    if external_device:
                        record["authorized"] = True
                        record["user_code"] = self.user_code
                        record["elapsed_s"] = round(time.time() - t0, 1)
                        log("external device authorized — caller polls for tokens")
                        return record

                    # Get token
                    r_token = session.post("https://account.minimax.io/oauth2/token", data={
                        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                        "device_code": self.device_code,
                        "client_id": "mcode-public",
                        "code_verifier": self.verifier
                    })
                    token_data = r_token.json()
                    access_token = token_data.get("access_token")

                    if access_token:
                        record["access_token"] = access_token
                        record["refresh_token"] = token_data.get("refresh_token")
                        log(f"SUCCESS! access_token obtained")
                        return record
                    else:
                        raise RuntimeError(f"Token exchange failed: {token_data}")
                else:
                    log(f"send API failed: {api_result}")
                
            except Exception as e:
                log(f"API call failed: {e}")
        
        # Debug: check page state and errors after captcha solve
        try:
            page_state = self.page.evaluate("""
                () => {
                    // Collect any JS errors
                    const errors = [];
                    window.addEventListener('error', e => {
                        errors.push(e.message);
                    });
                    
                    return {
                        url: window.location.href,
                        hasOtpInputs: document.querySelectorAll('input[maxlength="1"], input[inputmode="numeric"]').length,
                        bodyText: document.body.innerText.substring(0, 200),
                        // Look for React fiber with pending state
                        reactRoot: !!document.querySelector('#__next')
                    };
                }
            """)
            log(f"page state after captcha: {page_state}")
            
            # Check browser console for errors
            # (This requires the console listener to be set up earlier)
            
        except Exception as e:
            log(f"could not read page state: {e}")
        
        if not self._wait_otp_screen(timeout=30):
            raise RuntimeError("page never reached the OTP step "
                               "(captcha ticket rejected or send failed)")
        log("page reached the OTP step — ticket accepted, OTP sent")

        # 7. Poll the inbox for the code, then type it in.
        otp = mail_providers.poll_otp(_s, self.email, mail_provider, sid, timeout=120)
        if not otp:
            raise RuntimeError(f"OTP never arrived for {self.email}")
        log(f"otp received: {otp}")
        self._fill_otp(otp)

        # 8. The page submits the login itself and redirects to the consent
        #    screen. Approve it.
        _human_sleep(1.0, 2.0)
        self._approve_consent()

        # 9. Exchange the device code for tokens. The browser approved the
        #    consent for this device_code, so the exchange succeeds.
        #    With an EXTERNAL device (9router), the caller owns the exchange —
        #    it polls /oauth2/token itself — so we stop here. We HAVE completed
        #    the HTTP login + device approve above, which is what makes the
        #    device authorized for the caller to exchange.
        if external_device:
            record["authorized"] = True
            record["user_code"] = self.user_code
            record["elapsed_s"] = round(time.time() - t0, 1)
            log("external device authorized — caller polls for tokens")
            return record

        tokens = exchange_device_code(self.device_code, self.verifier, self.proxy_url)
        if not tokens or not tokens.get("access_token"):
            raise RuntimeError(f"no access token for {self.email}: {tokens}")

        record["access_token"] = tokens["access_token"]
        record["refresh_token"] = tokens.get("refresh_token")
        record["token_data"] = tokens
        record["elapsed_s"] = round(time.time() - t0, 1)
        log(f"tokens minted: access={record['access_token'][:12]}...")
        return record


# ---------------------------------------------------------------------------
# 4. Output
# ---------------------------------------------------------------------------


def save_record(record: dict, path: str = CREDS_FILE) -> None:
    line = json.dumps(record, ensure_ascii=False)
    with CREDS_WRITE_LOCK:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def farm_one_account(proxy: Optional[str], headless: bool, domain_index: int = 0,
                     device_info: Optional[dict] = None) -> dict:
    with MiniMaxBrowserFarmer(proxy_url=proxy, headless=headless) as farmer:
        return farmer.farm_one(domain_index=domain_index, device_info=device_info)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--count", "-n", type=int, default=1, help="accounts to farm")
    ap.add_argument("--proxy", default=DEFAULT_PROXY,
                    help="egress proxy URL (never the home IP)")
    ap.add_argument("--headed", action="store_true",
                    help="show the browser (default: headless)")
    ap.add_argument("--out", default=CREDS_FILE, help="jsonl output file")
    ap.add_argument("--domain-index", type=int, default=0,
                    help="rotate tempik mail domain per account")
    args = ap.parse_args()

    print("=" * 66)
    print("MINIMAX AGENT — IN-BROWSER ACCOUNT FARMER (reCAPTCHA Enterprise via sidecar)")
    print(f"  time      : {wib_now()}")
    print(f"  count     : {args.count}")
    print(f"  headless  : {not args.headed}")
    print(f"  out       : {args.out}")
    print("=" * 66)

    ok = 0
    for i in range(args.count):
        print(f"\n--- account {i + 1}/{args.count} ---")
        try:
            rec = farm_one_account(
                proxy=args.proxy,
                headless=not args.headed,
                domain_index=args.domain_index + i,
            )
            save_record(rec, args.out)
            ok += 1
            log(f"OK  {rec['email']}  token={rec['access_token'][:14]}...  "
                f"({rec.get('elapsed_s')}s)")
        except Exception as e:
            log(f"FAIL account {i + 1}: {type(e).__name__}: {e}")
        if i + 1 < args.count:
            cooldown = random.uniform(8, 20)
            log(f"cooldown {cooldown:.0f}s")
            time.sleep(cooldown)

    print(f"\nDone: {ok}/{args.count} accounts farmed.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

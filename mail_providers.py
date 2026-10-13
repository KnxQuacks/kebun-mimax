#!/usr/bin/env python3
"""mail_providers.py — disposable email allocation + OTP polling for the MiniMax farm.

Two providers, in priority order:

1. mail.cx (PRIMARY) — free disposable mail, no auth, no inbox-creation call.
   The mailbox is implicit: the moment SMTP accepts mail for
   ``<localpart>@<system_domain>`` it is buffered and readable by polling
   ``GET /v1/inbox/<address>`` (server long-polls ~25s, 204 = nothing yet).

2. tempik (FALLBACK) — self-hosted CF Worker temp mail (set TEMPIK_URL).
   Session-scoped: inboxes are created AND polled with an ``x-session-id``
   header, and the session id is persisted to ``TEMPIK_SESSION_FILE`` so an
   inbox stays readable across processes.

Public surface (consumed by minimax_farmer.py)::

    allocate_mailcx(s)                  -> email
    poll_mailcx(s, email, timeout=90)   -> otp | None
    tempik_session()                    -> sid
    allocate_tempik(domain_index=0)     -> (email, sid)
    poll_tempik(email, sid, timeout=90) -> otp | None
    allocate_email(s, domain_index=0)   -> (email, provider, sid)
    poll_otp(s, email, provider, sid=None, timeout=90) -> otp | None

HOST RULE — mail.cx ships a PAID "Pro" surface on the ``api.`` subdomain of the
same bare domain; it 401s (authentication_required) on every endpoint. The free
API is ``mail.cx/v1`` and needs no key. Rather than trusting ourselves to keep
the templates right, every URL here is *derived* from MAILCX_CONFIG_URL and
``_mailcx_get()`` re-checks the request host at call time, so this module
physically cannot talk to the paid host — not even after a bad edit to a
template string.
"""

from __future__ import annotations

import html
import os
import random
import re
import secrets
import string
import time
import urllib.parse

__all__ = [
    "allocate_mailcx",
    "poll_mailcx",
    "tempik_session",
    "allocate_tempik",
    "poll_tempik",
    "allocate_email",
    "poll_otp",
    "MailCxError",
    "TempikError",
    "MAILCX_CONFIG_URL",
    "MAILCX_INBOX_TMPL",
    "MAILCX_EMAIL_TMPL",
    "MAILCX_FALLBACK_DOMAINS",
    "TEMPIK_BASE",
    "TEMPIK_DOMAINS",
    "TEMPIK_SESSION_FILE",
]

# --------------------------------------------------------------------- mail.cx
MAILCX_CONFIG_URL = "https://mail.cx/v1/config"
# Every other mail.cx URL hangs off the config URL's origin, so a single
# constant defines the host we are willing to talk to.
MAILCX_BASE = MAILCX_CONFIG_URL[: -len("/config")]
MAILCX_INBOX_TMPL = MAILCX_BASE + "/inbox/{email}"
MAILCX_EMAIL_TMPL = MAILCX_BASE + "/email/{id}"

# Used only when /v1/config is unreachable. Live order as of 2026-09-24.
MAILCX_FALLBACK_DOMAINS = ["ddker.com", "9k3r.com", "uqu.me"]
"""Last-resort domain list if the /v1/config probe fails. These are mail.cx's
public system domains (not secrets); the live list is preferred and this is only
a fallback so allocation still has a domain to offer."""

_MAILCX_HOST = urllib.parse.urlparse(MAILCX_CONFIG_URL).netloc
assert _MAILCX_HOST == "mail.cx", "mail.cx free host only — see HOST RULE"
assert not MAILCX_BASE.startswith("https://api."), "mail.cx free host only — see HOST RULE"

# /v1/config local_part_rules: 2-20 chars of [a-z0-9._-], not reserved.
_LOCALPART_CHARS = string.ascii_lowercase + string.digits
_LOCALPART_MIN = 2
_LOCALPART_MAX = 20
_LOCALPART_RE = re.compile(r"[a-z0-9._-]{2,20}\Z")

# Local parts mail.cx rejects (subset; the full list comes from /v1/config).
_RESERVED_LOCALPARTS = {
    "abuse", "admin", "administrator", "billing", "compliance", "contact",
    "daemon", "do-not-reply", "donotreply", "finance", "ftp", "help",
    "helpdesk", "hostmaster", "info", "legal", "mail", "mailer",
    "mailer-daemon", "marketing", "no-reply", "nobody", "noreply",
    "payment", "postmaster", "privacy", "root", "sales", "secadmin",
    "security", "service", "ssl-admin", "support", "system", "webmaster",
    "www",
}

# /v1/config is the allocation probe: it answers instantly (unlike
# /v1/inbox/<addr>, which long-polls ~25s and would make a dead-inbox probe
# indistinguishable from a slow one). A 200 here proves the FREE host is
# serving us — the paid surface on the same bare domain 401s this endpoint —
# and hands us the system domains in the same response.
MAILCX_CONFIG_TIMEOUT = 15

_MAILCX_HEADERS = {"Accept": "application/json"}

# --------------------------------------------------------------------- tempik
# Self-hosted CF Worker temp mail (optional fallback). Point TEMPIK_URL at your
# own Worker; leave unset to run mail.cx only.
TEMPIK_BASE = os.environ.get("TEMPIK_URL", "").rstrip("/")
TEMPIK_DOMAINS = [
    d for d in (os.environ.get("TEMPIK_DOMAINS") or "").split(",") if d
]
TEMPIK_SESSION_FILE = os.environ.get("TEMPIK_SESSION_FILE",
                                     os.path.join(os.path.expanduser("~"),
                                                  ".tempik-session"))

_TEMPIK_HEADERS = {"Accept": "application/json"}

# ------------------------------------------------------------------ OTP mining
# mail.cx / tempik message dicts. The code MUST come from the full body fields
# — `preview`/`preview_text` is a short snippet that can carry a stale,
# truncated or placeholder code, so it is deliberately absent from BOTH lists.
_TEXT_FIELDS = ("text_body", "text", "body", "body_text")
_HTML_FIELDS = ("html_body", "html", "body_html")

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")

# Specific phrasing first, bare digits last (see the otp-email-automation
# skill: a bare \d{6} over raw mail matches invoice numbers and footers).
_OTP_PATTERNS = [
    re.compile(r"verification\s+code\D{0,30}(\d{6})", re.IGNORECASE),
    re.compile(r"\bcode\s*(?:is|:)?\D{0,20}(\d{6})", re.IGNORECASE),
    re.compile(r"\botp\D{0,20}(\d{6})", re.IGNORECASE),
    re.compile(r"\blogin\s+code\D{0,20}(\d{6})", re.IGNORECASE),
]
_BARE_OTP_RE = re.compile(r"\b\d{6}\b")

# Placeholder runs that raw markup/footers like to carry.
_BAD_CODES = {"000000", "111111", "123456", "654321", "999999", "121212", "112233"}


class MailCxError(RuntimeError):
    """mail.cx is unusable right now — caller should fall back to tempik."""


class TempikError(RuntimeError):
    """tempik API failure."""


# --------------------------------------------------------------- text helpers
def _strip_html(blob: str) -> str:
    """Tags -> spaces, entities -> characters, runs of whitespace collapsed.

    HTML is stripped *before* the digit regex runs: an html_body routinely
    carries six-digit junk inside markup (colours like #123456, widths) that a
    bare \\d{6} would happily return as the OTP.
    """
    plain = _TAG_RE.sub(" ", str(blob))
    plain = html.unescape(plain)
    return _WS_RE.sub(" ", plain).strip()


def _first_field(msg: dict, fields) -> str:
    for key in fields:
        val = msg.get(key)
        if val:
            return str(val)
    return ""


def _find_code(plain: str) -> str | None:
    for pattern in _OTP_PATTERNS:
        match = pattern.search(plain)
        if match and match.group(1) not in _BAD_CODES:
            return match.group(1)
    for match in _BARE_OTP_RE.finditer(plain):
        if match.group(0) not in _BAD_CODES:
            return match.group(0)
    return None


def _extract_otp(msg: dict) -> str | None:
    """Pull a 6-digit OTP out of a message's text_body/html_body.

    Never consults `preview` — see _TEXT_FIELDS / _HTML_FIELDS.
    """
    text = _first_field(msg, _TEXT_FIELDS)
    html_body = _first_field(msg, _HTML_FIELDS)
    for blob in (text, html_body):
        if not blob:
            continue
        code = _find_code(_strip_html(blob))
        if code:
            return code
    return None


# ------------------------------------------------------------------- mail.cx
_domains_cache: list[str] = []


def _mailcx_get(s, url: str, timeout: float):
    """GET a mail.cx URL on a caller-supplied session, host-guarded.

    The host is re-checked here (not just at import) so a URL built from a
    tampered or mis-edited template still cannot reach the paid surface.
    """
    if urllib.parse.urlparse(url).netloc != _MAILCX_HOST:
        raise MailCxError(
            "refusing mail.cx URL on a non-free host: %s" % url
        )
    return s.get(url, headers=_MAILCX_HEADERS, timeout=timeout)


def _mailcx_domains(s) -> list[str]:
    """Available system domains from /v1/config, cached per process."""
    global _domains_cache
    if _domains_cache:
        return _domains_cache
    try:
        resp = _mailcx_get(s, MAILCX_CONFIG_URL, 15)
        if getattr(resp, "status_code", 0) == 200:
            cfg = resp.json()
            domains = [
                d["domain"]
                for d in (cfg.get("system_domains") or [])
                if isinstance(d, dict) and d.get("domain")
            ]
            if domains:
                _domains_cache = domains
                return domains
    except Exception:
        pass
    _domains_cache = list(MAILCX_FALLBACK_DOMAINS)
    return _domains_cache


def _random_localpart() -> str:
    """2-20 chars of [a-z0-9], avoiding the reserved list."""
    for _ in range(64):
        length = random.randint(8, 14)
        cand = "".join(random.choices(_LOCALPART_CHARS, k=length))
        if cand not in _RESERVED_LOCALPARTS:
            return cand
    # Deterministic last resort: still valid, still unique-ish.
    return "m" + secrets.token_hex(6)


def allocate_mailcx(s) -> str:
    """Invent a mail.cx address and prove the free host will serve it.

    mail.cx has no inbox-creation call — the mailbox is implicit, so
    allocation is just "pick a localpart @ a system domain". The /v1/config
    probe is what makes the tempik fallback meaningful: without it we would
    hand back an unprobed address and only discover it is dead 90s later,
    after the OTP send has already cost a captcha solve.

    Raises ``MailCxError`` when mail.cx is refusing us, so ``allocate_email``
    can switch providers before any money is spent.
    """
    domain = random.choice(_mailcx_domains(s))
    local = _random_localpart()
    if not _LOCALPART_RE.match(local) or not (_LOCALPART_MIN <= len(local) <= _LOCALPART_MAX):
        raise MailCxError("generated localpart violates /config rules: %r" % local)
    email = f"{local}@{domain}"

    try:
        resp = _mailcx_get(s, MAILCX_CONFIG_URL, MAILCX_CONFIG_TIMEOUT)
    except Exception as exc:
        raise MailCxError("mail.cx unreachable: %s" % exc) from exc
    status = getattr(resp, "status_code", 0)
    if status != 200:
        raise MailCxError("mail.cx probe rejected us: HTTP %s" % status)
    return email


def _mailcx_messages(resp) -> list[dict]:
    """Normalise a /v1/inbox response into a message list."""
    status = getattr(resp, "status_code", 0)
    if status in (204, 429):
        # 204 = empty inbox (expected), 429 = alive but rate limited.
        return []
    if status != 200:
        raise MailCxError("mail.cx HTTP %s" % status)
    try:
        data = resp.json()
    except Exception:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if data.get("error"):
            raise MailCxError("mail.cx error: %s" % data["error"])
        for key in ("emails", "items", "messages"):
            if isinstance(data.get(key), list):
                return data[key]
    return []


def _mailcx_full(s, msg: dict) -> dict:
    """Fetch the full message via GET /v1/email/{id}, merged over the list item.

    Inbox-list items carry only id/from/subject/preview — the OTP lives in
    text_body/html_body, which requires this second fetch (proven live).
    On any failure returns the original item so extraction can still try.
    """
    mid = msg.get("id") if isinstance(msg, dict) else None
    if not mid:
        return msg if isinstance(msg, dict) else {}
    try:
        url = MAILCX_EMAIL_TMPL.format(id=urllib.parse.quote(str(mid), safe=""))
        resp = _mailcx_get(s, url, 20)
        if getattr(resp, "status_code", 0) != 200:
            return msg
        full = resp.json()
        if isinstance(full, dict):
            merged = dict(msg)
            merged.update(full)
            return merged
    except Exception:
        pass
    return msg


def poll_mailcx(s, email: str, timeout: int = 90) -> str | None:
    """Long-poll a mail.cx inbox for a 6-digit OTP. Returns None on timeout.

    The server holds each request open ~25s and returns 204 when nothing has
    arrived, so this loops until ``timeout`` rather than polling hot.
    Each inbox-list hit is resolved via GET /v1/email/{id} before extraction,
    because the OTP is only in the full text_body/html_body.
    """
    url = MAILCX_INBOX_TMPL.format(email=urllib.parse.quote(email, safe=""))
    deadline = time.time() + timeout
    seen: set[object] = set()
    while time.time() < deadline:
        remaining = deadline - time.time()
        try:
            resp = _mailcx_get(s, url, max(5.0, min(30.0, remaining)))
            messages = _mailcx_messages(resp)
        except MailCxError:
            messages = []
        except Exception:
            messages = []
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            mid = msg.get("id") or msg.get("message_id") or msg.get("subject")
            if mid is not None:
                if mid in seen:
                    continue
                seen.add(mid)
            msg = _mailcx_full(s, msg)
            code = _extract_otp(msg)
            if code:
                return code
        if time.time() >= deadline:
            break
        # A fast 204 (server gave up early) shouldn't spin the CPU.
        time.sleep(1.0)
    return None


# ------------------------------------------------------------------- tempik
_TEMPIK_HTTP = None
_tempik_sid: str | None = None


def _http_session():
    """tempik's own session — its endpoints are called without a caller `s`.

    Prefer curl_cffi (impersonation matches the rest of the farm); fall back
    to plain requests so this module stays importable everywhere.
    """
    global _TEMPIK_HTTP
    if _TEMPIK_HTTP is None:
        try:
            from curl_cffi import requests as _curl_requests

            _TEMPIK_HTTP = _curl_requests.Session(impersonate="chrome136")
        except Exception:
            import requests as _plain_requests

            _TEMPIK_HTTP = _plain_requests.Session()
    return _TEMPIK_HTTP


def _persist_tempik_session(sid: str) -> None:
    try:
        parent = os.path.dirname(TEMPIK_SESSION_FILE)
        if parent:
            os.makedirs(parent, exist_ok=True)
        fd = os.open(TEMPIK_SESSION_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, sid.encode("utf-8"))
        finally:
            os.close(fd)
    except OSError:
        pass


def tempik_session() -> str:
    """Return a tempik session id, creating and persisting one if needed.

    Inboxes are scoped to the session, so the id must survive across process
    invocations — otherwise every inbox becomes unreadable and every account
    farmed with it is orphaned.
    """
    global _tempik_sid
    if _tempik_sid:
        return _tempik_sid
    try:
        if os.path.exists(TEMPIK_SESSION_FILE):
            with open(TEMPIK_SESSION_FILE, "r", encoding="utf-8") as fh:
                saved = fh.read().strip()
            if saved:
                _tempik_sid = saved
                return saved
    except OSError:
        pass

    resp = _http_session().get(
        f"{TEMPIK_BASE}/api/session", headers=_TEMPIK_HEADERS, timeout=15
    )
    if getattr(resp, "status_code", 0) != 200:
        raise TempikError("tempik /api/session HTTP %s" % getattr(resp, "status_code", 0))
    try:
        sid = (resp.json() or {}).get("sessionId")
    except Exception as exc:
        raise TempikError("tempik /api/session unparseable: %s" % exc) from exc
    if not sid:
        raise TempikError("tempik /api/session returned no sessionId")
    _tempik_sid = sid
    _persist_tempik_session(sid)
    return sid


def allocate_tempik(domain_index: int = 0) -> tuple[str, str]:
    """Create a tempik inbox. Returns (email, session_id).

    ``domain_index`` rotates across TEMPIK_DOMAINS so consecutive accounts do
    not share a mail domain (a batch-scale correlation signal).
    """
    sid = tempik_session()
    domain = TEMPIK_DOMAINS[domain_index % len(TEMPIK_DOMAINS)]
    resp = _http_session().post(
        f"{TEMPIK_BASE}/api/inboxes",
        json={"domain": domain},
        headers={"x-session-id": sid, "Content-Type": "application/json", **_TEMPIK_HEADERS},
        timeout=15,
    )
    if getattr(resp, "status_code", 0) != 200:
        raise TempikError("tempik /api/inboxes HTTP %s" % getattr(resp, "status_code", 0))
    try:
        address = (resp.json() or {}).get("address")
    except Exception as exc:
        raise TempikError("tempik /api/inboxes unparseable: %s" % exc) from exc
    if not address:
        raise TempikError("tempik inbox creation returned no address")
    return address, sid


def poll_tempik(email: str, sid: str | None = None, timeout: int = 90) -> str | None:
    """Poll a tempik inbox for a 6-digit OTP. Returns None on timeout."""
    if not sid:
        sid = tempik_session()
    url = (
        f"{TEMPIK_BASE}/api/inboxes/"
        f"{urllib.parse.quote(email, safe='')}/messages"
    )
    deadline = time.time() + timeout
    seen: set[object] = set()
    while time.time() < deadline:
        remaining = deadline - time.time()
        try:
            resp = _http_session().get(
                url,
                headers={"x-session-id": sid, **_TEMPIK_HEADERS},
                timeout=max(5.0, min(20.0, remaining)),
            )
            if getattr(resp, "status_code", 0) == 200:
                data = resp.json()
                messages = data if isinstance(data, list) else []
            else:
                messages = []
        except Exception:
            messages = []
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            mid = msg.get("id") or msg.get("message_id") or msg.get("subject")
            if mid is not None:
                if mid in seen:
                    continue
                seen.add(mid)
            code = _extract_otp(msg)
            if code:
                return code
        if time.time() >= deadline:
            break
        time.sleep(2.0)
    return None


# ------------------------------------------------------------- unified facade
def allocate_email(s, domain_index: int = 0) -> tuple[str, str, str | None]:
    """Allocate a disposable inbox: mail.cx first, tempik on failure.

    Returns ``(email, provider, sid)`` where ``sid`` is None for mail.cx
    (stateless) and the tempik session id for tempik (needed to read the
    inbox back). The tuple shape feeds straight into ``poll_otp``.
    """
    try:
        email = allocate_mailcx(s)
    except Exception as exc:
        print(f"[!] mail.cx unusable ({exc}) — allocating a tempik inbox instead.")
        email = None
    if email:
        return email, "mailcx", None

    email, sid = allocate_tempik(domain_index)
    return email, "tempik", sid


def poll_otp(s, email: str, provider: str, sid: str | None = None,
             timeout: int = 90) -> str | None:
    """Poll the right inbox for the OTP, by the provider allocate_email chose."""
    provider = (provider or "mailcx").strip().lower()
    if provider == "tempik":
        return poll_tempik(email, sid, timeout=timeout)
    return poll_mailcx(s, email, timeout=timeout)


# ------------------------------------------------------------------ self-test
def _selftest() -> int:
    """Offline-only checks (no network) for the pure pieces of this module."""
    fails: list[str] = []

    # localpart rules hold over many draws
    for _ in range(500):
        local = _random_localpart()
        if not _LOCALPART_RE.match(local) or not (2 <= len(local) <= 20):
            fails.append("localpart violates /config rules: %r" % local)
            break
        if local in _RESERVED_LOCALPARTS:
            fails.append("localpart is reserved: %r" % local)
            break

    # templates compose correct URLs on the free host; addresses are f-strings
    addr = f"{'user'}@{'example.com'}"
    inbox = MAILCX_INBOX_TMPL.format(email="user@example.com")
    email_url = MAILCX_EMAIL_TMPL.format(id="m1")
    if addr != "user@example.com":
        fails.append("address compose wrong: %r" % addr)
    if inbox != "https://mail.cx/v1/inbox/user@example.com":
        fails.append("MAILCX_INBOX_TMPL wrong: %r" % inbox)
    if email_url != "https://mail.cx/v1/email/m1":
        fails.append("MAILCX_EMAIL_TMPL wrong: %r" % email_url)
    if urllib.parse.urlparse(inbox).netloc != _MAILCX_HOST:
        fails.append("inbox template is not on the free host")

    # _strip_html removes markup-borne digits before the regex sees them
    if _strip_html('<td bgcolor="#123456">code</td>') != "code":
        fails.append("_strip_html left markup behind")

    # OTP comes from the body, never from the preview
    got = _extract_otp({"preview": "Your code is 000000",
                        "text_body": "Your verification code is 482915",
                        "html_body": ""})
    if got != "482915":
        fails.append("preview leaked into OTP extraction: %r" % got)

    got = _extract_otp({"preview": "code 999999",
                        "text_body": "",
                        "html_body": "<p>code: <b>31337b</b> and 515023</p>"})
    if got != "515023":
        fails.append("html_body OTP extraction wrong: %r" % got)

    # bare digits only as a last resort, placeholders rejected
    got = _extract_otp({"text_body": "Order 4400771221 — code 261443", "html_body": ""})
    if got != "261443":
        fails.append("phrase pattern should have won: %r" % got)
    got = _extract_otp({"text_body": "footer 000000 end", "html_body": ""})
    if got is not None:
        fails.append("placeholder code accepted: %r" % got)

    print("MAIL_PROVIDERS SELFTEST: " + ("PASSED" if not fails else "FAILED"))
    for f in fails:
        print("  - " + f)
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(_selftest())

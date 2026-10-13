# minimax-farmer

Automated MiniMax account creation + OAuth device-flow authorization, wired to
[9router](https://github.com/9router) as a `minimax-code-global` provider.

The farmer drives a real anti-detect browser through the MiniMax web signup,
solves the login-gate CAPTCHA through a **local** (self-hosted, no per-solve
cost) solver sidecar, completes the email OTP step, and — in 9router mode —
authorizes a device code the router is polling, so the router persists the
resulting credentials itself.

> Use only against accounts/systems you are authorized to automate.

---

## How it works

```
┌────────────┐   1. device code    ┌──────────────────────┐
│  9router   │◄───────────────────►│  connect_9router.py  │
│  :20128    │   4. poll / solve   │  (orchestrator)      │
└────────────┘                     └──────────┬───────────┘
                                              │ 2. drive signup
                                              ▼
                                   ┌──────────────────────┐
                                   │  CloakBrowser        │
                                   │  (anti-detect Chromium)
                                   └──────────┬───────────┘
                                              │ 3. CAPTCHA token
                                              ▼
                                   ┌──────────────────────┐
                                   │  captcha-solver      │
                                   │  sidecar :8877       │
                                   └──────────────────────┘
```

1. **Email** — a disposable inbox is allocated (mail.cx primary; a self-hosted
   tempik Worker as fallback).
2. **Browser** — CloakBrowser (a stealth Chromium build) opens the MiniMax
   unified-login page and fills email → terms → create-password.
3. **CAPTCHA** — the create-password screen guards its `sms/send` call with
   reCAPTCHA Enterprise (invisible). The sidecar mints a token on the real page
   via `grecaptcha.enterprise.execute(...)`; the farmer submits it.
4. **OTP** — the inbox is polled for the email code, which is typed back in.
5. **Authorize** — in 9router mode the router mints a device code and polls
   `/oauth2/token` itself; the farmer only drives login + device-approve, then
   the connection appears in 9router.

### Components

| Path | Role |
| --- | --- |
| `camoufox/minimax_camoufox.py` | Orchestrator: browser, signup, CAPTCHA, OTP, token exchange. |
| `camoufox/captcha_client.py` | Thin client for the local captcha-solver sidecar. |
| `camoufox/connect_9router.py` | Runs 9router's device flow end to end → new provider connection. |
| `camoufox/test_captcha_client.py` | Assert-based smoke test for the sidecar. |
| `mail_providers.py` | Disposable-mailbox allocation + OTP polling. |
| `patches/` | Windows helpers for the third-party sidecar (see below). |

### The CAPTCHA sidecar

The login gate is solved by
[`waguriagentic/captcha-solver`](https://github.com/waguriagentic/captcha-solver)
— a self-hosted HTTP sidecar built on CloakBrowser that runs real-browser
challenges locally (no paid solver service). It supports Turnstile, reCAPTCHA
(v2/v3/invisible, incl. Enterprise), hCaptcha, Cloudflare, AWS WAF, DataDome,
PerimeterX, Akamai, Aliyun and Arkose.

This project only uses its **reCAPTCHA Enterprise (invisible)** path, with
`real_page=true` and a local ONNX tile classifier, so no third-party vision API
key is required.

`patches/` carries two Windows-only drop-ins:

- `run_sidecar.py` — a no-docker launcher (the upstream repo assumes systemd).
- `concurrency-windows.py` — replaces `common/concurrency.py` with a RAM-budget
  reader that works off `/proc/meminfo` **or** Windows `GlobalMemoryStatusEx`.

---

## Setup

### 1. Captcha sidecar

```bash
git clone https://github.com/waguriagentic/captcha-solver
cd captcha-solver
python -m venv venv
venv/Scripts/python.exe -m pip install fastapi uvicorn pydantic cloakbrowser \
    pillow onnxruntime opencv-python-headless numpy geoip2 socksio httpx

# apply the Windows patches
cp /path/to/minimax-farmer/patches/run_sidecar.py .
cp /path/to/minimax-farmer/patches/concurrency-windows.py common/concurrency.py

venv/Scripts/python.exe run_sidecar.py     # listens on 127.0.0.1:8877
```

Check it:

```bash
curl http://127.0.0.1:8877/health
# {"status":"ok","supported_types":[...]}
```

### 2. Farmer

```bash
cd minimax-farmer
python -m venv .venv && .venv/Scripts/python.exe -m pip install -r requirements.txt
cp .env.example .env        # fill in the values below
```

### 3. Configure

All configuration is via environment (see `.env.example`):

| Variable | Purpose |
| --- | --- |
| `MINIMAX_PROXY` | Residential egress proxy. Strongly recommended. |
| `MINIMAX_SITEKEY` | The login page's public reCAPTCHA Enterprise sitekey. |
| `MINIMAX_SIGN_SECRET` | Request-signing key for the OTP / oauth calls. |
| `CAPTCHA_SOLVER_URL` | Sidecar base URL (default `http://127.0.0.1:8877`). |
| `CAPTCHA_SOLVER_TOKEN` | Bearer token, only if the sidecar enforces one. |
| `NINEROUTER_URL` / `NINEROUTER_PASSWORD` | 9router dashboard access. |

`MINIMAX_SITEKEY` and `MINIMAX_SIGN_SECRET` are read straight from the live
login page's client bundle, so they can change when MiniMax ships a new build —
extract them from the page rather than hardcoding.

---

## Usage

### Create a standalone account

```bash
cd camoufox
MINIMAX_PROXY=... python minimax_camoufox.py --count 1 --headed
# -> appends {email, access_token, refresh_token, ...} to minimax_accounts.jsonl
```

### Connect an account to 9router

```bash
cd camoufox
NINEROUTER_PASSWORD=... python connect_9router.py            # headless
NINEROUTER_PASSWORD=... python connect_9router.py --headed   # watch it work
```

This creates a new `minimax-code-global` connection in 9router via its own OAuth
device flow. Verify the gateway serves it:

```bash
curl -s http://localhost:20128/v1/models \
  -H "Authorization: Bearer <9router-api-key>" | grep mmg/
# mmg/MiniMax-M3.1-Flash-Preview, mmg/MiniMax-M3, mmg/MiniMax-M2.7, ...
```

### Smoke-test the sidecar alone

```bash
captcha-solver/venv/Scripts/python.exe camoufox/test_captcha_client.py
# OK token len=... prefix=...
```

---

## Notes & limitations

- **Concurrency.** The sidecar's free CloakBrowser tier allows **one** live
  browser session. Run accounts sequentially; parallel solves need a license key
  and raise `SOLVER_MAX_CONCURRENT`.
- **Captcha action.** The current login gate uses `action=send_code` on an
  Enterprise **invisible** widget. If MiniMax changes the flow, re-probe the page
  (`grecaptcha.enterprise.execute`) and update `MINIMAX_CAPTCHA_ACTION`.
- **Server leniency.** The `sms/send` endpoint can return a business error code
  while still issuing the OTP; the farmer proceeds on the transport success.
- **No personal data.** This repository contains no API keys, sitekeys, signing
  secrets, proxy credentials, session files, or account tokens. Supply your own.

## License

MIT — see [LICENSE](LICENSE). The captcha sidecar is a separate project under
its own license.

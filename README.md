# MiniMax Farmer

> A browser-driven MiniMax account workflow with optional OAuth
> device-flow integration for [9Router](https://github.com/9router).

MiniMax Farmer is a Python project for experimenting with account
onboarding and connecting an authorized MiniMax account to a local
9Router instance. It separates browser orchestration, mailbox handling,
and router integration into small components so each part can be
inspected and maintained independently.

**Important:** Use this project only with accounts and systems you are
authorized to access. Respect MiniMax's terms, rate limits, identity
requirements, and anti-abuse controls. Do not use it to mass-create
accounts, evade account restrictions, or bypass CAPTCHA protections. For
production use, prefer MiniMax's documented authentication and API
options.

------------------------------------------------------------------------

## Table of Contents

-   [Overview](#overview)
-   [Workflow](#workflow)
-   [Project Structure](#project-structure)
-   [Requirements](#requirements)
-   [Setup](#setup)
-   [Configuration](#configuration)
-   [Usage](#usage)
-   [9Router Integration](#9router-integration)
-   [Troubleshooting](#troubleshooting)
-   [Security Notes](#security-notes)
-   [Limitations](#limitations)
-   [License](#license)

## Overview

The project is organized around three responsibilities:

  -----------------------------------------------------------------------
  Component                           Responsibility
  ----------------------------------- -----------------------------------
  Browser orchestrator                Guides the user through the
                                      supported MiniMax sign-in or
                                      onboarding flow.

  Mailbox adapter                     Retrieves a verification message
                                      from a mailbox the operator is
                                      authorized to use.

  9Router connector                   Coordinates an OAuth device-flow
                                      connection and lets 9Router store
                                      credentials through its own
                                      supported flow.
  -----------------------------------------------------------------------

### Design goals

-   **Inspectable:** Keep browser automation, mailbox access, and router
    integration separate.
-   **Configurable:** Use environment variables for local endpoints and
    credentials.
-   **Local-first development:** Run the orchestration and router on
    your own machine where practical.
-   **Credential hygiene:** Keep tokens and secrets out of source
    control and logs.

## Workflow

``` text
┌─────────────────┐       OAuth device flow       ┌────────────────────┐
│     9Router     │ ◄───────────────────────────► │  Router connector  │
│  Local gateway  │                               │   Orchestrator     │
└─────────────────┘                               └─────────┬──────────┘
                                                           │
                                                           ▼
                                                ┌────────────────────┐
                                                │ Browser sign-in or │
                                                │ user-assisted setup│
                                                └─────────┬──────────┘
                                                          │
                                                          ▼
                                                ┌────────────────────┐
                                                │ Authorized mailbox │
                                                │ verification step  │
                                                └────────────────────┘
```

1.  **Prepare access.** Use a mailbox and MiniMax account you are
    authorized to operate.
2.  **Sign in or complete onboarding.** Follow the current MiniMax flow.
    If an anti-abuse challenge appears, complete it through the
    service's intended user flow rather than attempting to defeat or
    evade it.
3.  **Verify the account.** Retrieve the verification message from the
    configured mailbox and enter the code as required.
4.  **Authorize 9Router.** If using the device flow, approve the request
    in the official browser page and allow 9Router to complete its own
    token exchange.
5.  **Verify the connection.** Confirm that the provider appears in
    9Router and that the expected models are available.

> **Flow changes:** MiniMax may change its login pages, verification
> steps, OAuth behavior, or available models. Treat the live service as
> authoritative.

## Project Structure

``` text
minimax-farmer/
├── camoufox/
│   ├── minimax_camoufox.py       # Browser workflow orchestration
│   ├── captcha_client.py         # Local challenge-service client, if configured
│   ├── connect_9router.py        # 9Router device-flow integration
│   └── test_captcha_client.py    # Client connectivity smoke test
├── mail_providers.py             # Mailbox adapter and verification polling
├── patches/                      # Platform-specific compatibility helpers
├── requirements.txt
├── .env.example
└── README.md
```

Names and files may differ by branch. Check the repository contents
before running a command.

## Requirements

-   Windows, Linux, or macOS with a supported Python version.
-   Git.
-   A MiniMax account and mailbox you are authorized to use.
-   A local 9Router installation, if you want router integration.
-   Any browser dependencies documented by the version of this
    repository you are using.

Check the upstream projects' current installation instructions before
installing third-party browser or challenge-handling components.

## Setup

### 1. Clone the repository

``` bash
git clone <your-repository-url>
cd minimax-farmer
```

### 2. Create a virtual environment

**Windows (PowerShell):**

``` powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

**Linux / macOS:**

``` bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 3. Configure environment variables

Copy the example file and fill in only the values needed for your setup.

**Windows (PowerShell):**

``` powershell
Copy-Item .env.example .env
```

**Linux / macOS:**

``` bash
cp .env.example .env
```

Do not commit `.env` or any file containing tokens, passwords, mailbox
credentials, or session data.

## Configuration

The exact variables depend on the current branch. Common settings may
include:

  -----------------------------------------------------------------------
  Variable                            Purpose
  ----------------------------------- -----------------------------------
  `CAPTCHA_SOLVER_URL`                Local endpoint for a
                                      challenge-service client, if the
                                      project supports one.

  `CAPTCHA_SOLVER_TOKEN`              Authentication token for a locally
                                      configured service, if required.

  `NINEROUTER_URL`                    Base URL of the local 9Router
                                      instance.

  `NINEROUTER_PASSWORD`               Password used to access the local
                                      9Router dashboard.
  -----------------------------------------------------------------------

Some branches may contain additional MiniMax-specific settings. Review
`.env.example` and the source code before enabling them. Do not copy
secrets from issue reports, screenshots, shell history, or public
examples.

## Usage

### Run the browser workflow

Run the script from the directory expected by the current branch. For
example:

``` bash
cd camoufox
python minimax_camoufox.py --help
```

Use the help output to confirm supported options before running the
workflow. Prefer a visible browser session while testing so you can
inspect each step and intervene when the service requests user action.

### Connect to 9Router

``` bash
cd camoufox
python connect_9router.py --help
```

Set the required `NINEROUTER_URL` and dashboard credential in your
environment, then follow the supported OAuth device-authorization flow.
Approve only authorization requests you initiated and recognize.

### Check a local service

If you have configured a local sidecar, verify its health endpoint
according to that service's documentation. A successful health check
confirms that the service responds; it does **not** prove that every
challenge type or browser flow is compatible.

## 9Router Integration

The intended integration is to let 9Router manage its own OAuth device
flow and credential persistence.

After authorization:

1.  Open the 9Router dashboard.
2.  Confirm that the expected MiniMax provider connection is listed.
3.  Check the gateway's model listing using the API key configured for
    your own instance.

Example request (adjust the URL and API key for your installation):

``` bash
curl -s http://localhost:20128/v1/models \
  -H "Authorization: Bearer <YOUR_9ROUTER_API_KEY>"
```

Keep API keys private. Do not publish unredacted command output if it
includes credentials or account identifiers.

## Troubleshooting

  -----------------------------------------------------------------------
  Symptom                             What to check
  ----------------------------------- -----------------------------------
  Browser does not launch             Confirm Python dependencies,
                                      browser binaries, and the working
                                      directory.

  Verification email does not arrive  Check the address, spam folder,
                                      provider availability, and whether
                                      the service permits that mailbox.

  OAuth approval does not complete    Confirm that the device code has
                                      not expired and that the same flow
                                      is still active in 9Router.

  Provider is missing in 9Router      Check dashboard logs, the
                                      configured router URL, and whether
                                      authorization completed
                                      successfully.

  Model listing is empty or           Check provider status and the
  unexpected                          current model names supported by
                                      your MiniMax account and router
                                      version.

  A service challenge blocks progress Complete the intended verification
                                      flow manually or contact the
                                      service operator. Do not attempt to
                                      circumvent the protection.
  -----------------------------------------------------------------------

When filing an issue, include the operating system, Python version,
relevant sanitized logs, and reproduction steps. Remove passwords, OAuth
codes, cookies, tokens, email addresses, and proxy credentials first.

## Security Notes

-   **Protect credentials.** Store secrets in environment variables or a
    dedicated secret manager; never commit them.
-   **Protect token files.** Treat account JSONL files, browser
    profiles, cookies, and OAuth artifacts as credentials.
-   **Use authorized accounts.** Do not automate access to accounts you
    do not own or administer.
-   **Respect service controls.** Do not use anti-detect techniques,
    disposable identities, proxy rotation, or challenge-solving
    automation to evade service safeguards.
-   **Review dependencies.** Install third-party packages only from
    sources you trust, pin versions where appropriate, and inspect
    changes before updating.
-   **Limit local exposure.** Bind local helper services to loopback
    unless remote access is genuinely required; add authentication if a
    service supports it.
-   **Rotate exposed secrets.** If a token, password, or session file is
    accidentally published, revoke it and issue a replacement.

## Limitations

-   MiniMax may change its login, verification, or OAuth flow without
    notice.
-   Browser automation can break when page structure or browser
    dependencies change.
-   Mailbox delivery times and provider availability are outside this
    project's control.
-   The project does not guarantee account creation, authentication,
    provider availability, or model access.
-   Third-party components have their own licenses, security properties,
    and operational constraints.

## License

This repository is distributed under the MIT License. See
[`LICENSE`](LICENSE) for the full text.

Third-party dependencies and separately maintained services remain
subject to their own licenses and terms.

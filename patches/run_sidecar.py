#!/usr/bin/env python3
"""Start the captcha-solver sidecar locally on Windows (no docker).

Drop this file into the root of a cloned waguriagentic/captcha-solver checkout
(same dir as server.py). Create the venv once:

    python -m venv venv
    venv\\Scripts\\python.exe -m pip install fastapi uvicorn pydantic ^
        cloakbrowser pillow onnxruntime opencv-python-headless numpy ^
        geoip2 socksio httpx

Then:

    venv\\Scripts\\python.exe run_sidecar.py

Listens on 127.0.0.1:8877. Set SOLVER_API_TOKEN to require a Bearer token, or
SOLVER_ALLOW_UNAUTHENTICATED=1 (the launcher's default) for a token-free dev box.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

os.environ.setdefault("PORT", "8877")
os.environ.setdefault("SOLVER_ALLOW_UNAUTHENTICATED", "1")

sys.path.insert(0, str(HERE))

if __name__ == "__main__":
    import uvicorn

    from server import app

    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8877"))
    print(f"captcha-solver sidecar on http://{host}:{port}", flush=True)
    uvicorn.run(app, host=host, port=port, log_level="info")

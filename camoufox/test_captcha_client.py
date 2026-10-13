"""Assert-based check: MiniMax reCAPTCHA Enterprise token via the sidecar.

Run with the sidecar up:

    captcha-solver/venv/Scripts/python.exe camoufox/test_captcha_client.py

Exit 0 = token minted with the expected shape.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import captcha_client  # noqa: E402


def main() -> int:
    tok = captcha_client.solve_recaptcha_send_code(
        solver_url=os.environ.get("CAPTCHA_SOLVER_URL", captcha_client.SOLVER_URL),
        token=os.environ.get("CAPTCHA_SOLVER_TOKEN"),
    )
    assert isinstance(tok, str), f"token not a str: {type(tok)}"
    assert len(tok) > 500, f"token too short ({len(tok)}) — not a real solve token"
    assert tok.startswith("0cAF"), f"unexpected token prefix: {tok[:8]!r}"
    print(f"OK token len={len(tok)} prefix={tok[:16]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

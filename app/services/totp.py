"""TOTP (RFC 6238) helpers for admin 2FA.

Secrets live in the `settings` table (keys `admin_totp_secret` and
`admin_totp_enabled`). A separate `admin_totp_secret_pending` key is used
during enrollment so that a half-finished enrollment doesn't lock the admin
out if they close the tab before confirming.

QR codes are rendered as inline SVG so the browser can render them without
a round trip and without needing PIL.

v1.10.0 — `verify_and_advance()` tracks the last-used counter to block
replay within the ±30 s validation window. A `tx_id`-sniffing attacker
could previously re-use the same 6-digit code for up to 90 s.
"""
import io
import time
from typing import Optional

import pyotp
import qrcode
import qrcode.image.svg

ISSUER = "SyslogHub"


def generate_secret() -> str:
    return pyotp.random_base32()


def build_uri(username: str, secret: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=username, issuer_name=ISSUER,
    )


def qr_svg(uri: str) -> str:
    """Render the provisioning URI as a self-contained SVG string."""
    qr = qrcode.QRCode(
        version=None, error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8, border=2,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(image_factory=qrcode.image.svg.SvgImage)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode("utf-8")


def verify(secret: str, code: str) -> bool:
    """Legacy helper kept for places that don't care about replay (e.g. the
    enrolment-confirmation step, where the secret is brand-new and has never
    been used — no prior counter exists)."""
    if not secret or not code:
        return False
    try:
        return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)
    except Exception:
        return False


def verify_and_advance(secret: str, code: str, last_counter: int) -> int | None:
    """Return the matched counter if `code` is valid AND strictly greater
    than `last_counter` (replay-proof), or None otherwise.

    Window: ±1 step (90 s total, same as `verify`). Caller persists the
    returned counter so the next attempt requires a fresh code."""
    if not secret or not code:
        return None
    try:
        totp = pyotp.TOTP(secret)  # interval=30 default
        now_ts = int(time.time())
        now_counter = now_ts // 30
        code = code.strip()
        # Accept the previous, current, and next slots. pyotp.TOTP.at(ts)
        # expects a unix timestamp, so we feed ts = counter * 30.
        for offset in (-1, 0, 1):
            counter = now_counter + offset
            if totp.at(counter * 30) == code:
                if counter <= last_counter:
                    return None  # replay — same or older slot already consumed
                return counter
        return None
    except Exception:
        return None

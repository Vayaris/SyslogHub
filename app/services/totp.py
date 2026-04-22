"""TOTP (RFC 6238) helpers for admin 2FA.

Secrets live in the `settings` table (keys `admin_totp_secret` and
`admin_totp_enabled`). A separate `admin_totp_secret_pending` key is used
during enrollment so that a half-finished enrollment doesn't lock the admin
out if they close the tab before confirming.

QR codes are rendered as inline SVG so the browser can render them without
a round trip and without needing PIL.
"""
import io
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
    if not secret or not code:
        return False
    try:
        return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)
    except Exception:
        return False

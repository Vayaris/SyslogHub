"""At-rest encryption for integration secrets stored in the DB.

SMTP password, OIDC client_secret and each space's Omada client_secret used
to live in the SQLite rows in plaintext. A backup leak, a filesystem
permission bug, or a read-only exploit would expose them all. v1.10.0
wraps them with Fernet (AES-128-CBC + HMAC-SHA-256, authenticated) using a
master key kept outside the DB.

Master key:
  - File: /opt/syslog-server/config/secrets.key
  - Content: 32 url-safe-base64 bytes (Fernet.generate_key())
  - Mode: 0400 root:root
  - Created at install time; regenerated (and audit-logged) if missing on a
    running instance.

Storage format: "fernet:v1:<urlsafe_b64_token>". Values without this
prefix are treated as legacy plaintext (returned as-is by `decrypt`) so
the migration path is seamless: any write rewrites the field encrypted,
and a one-shot `migrate_plaintext()` run at startup encrypts everything
found still in cleartext.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

log = logging.getLogger("syslog-server")

KEY_PATH = Path("/opt/syslog-server/config/secrets.key")
PREFIX = "fernet:v1:"

_cipher: Optional[Fernet] = None


def _load_or_create_key() -> bytes:
    if KEY_PATH.exists():
        data = KEY_PATH.read_bytes().strip()
        if data:
            return data
    # Create with a tight mode so the key itself is never world-readable.
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    # Write via os.open to guarantee 0600 on creation — otherwise a stale
    # umask could leak the file for a brief moment.
    fd = os.open(str(KEY_PATH), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, key + b"\n")
    finally:
        os.close(fd)
    os.chmod(KEY_PATH, 0o400)
    log.warning(f"crypto: generated new master key at {KEY_PATH}")
    return key


def _get_cipher() -> Fernet:
    global _cipher
    if _cipher is None:
        _cipher = Fernet(_load_or_create_key())
    return _cipher


def is_encrypted(value: Optional[str]) -> bool:
    return bool(value and value.startswith(PREFIX))


def encrypt(plain: Optional[str]) -> Optional[str]:
    """Wrap a cleartext secret. None / empty is returned as-is."""
    if plain is None or plain == "":
        return plain
    if is_encrypted(plain):
        return plain
    token = _get_cipher().encrypt(plain.encode("utf-8")).decode("ascii")
    return PREFIX + token


def decrypt(stored: Optional[str]) -> Optional[str]:
    """Unwrap a stored secret. Legacy plaintext (no prefix) passes through
    — callers can rely on this during the migration window."""
    if stored is None or stored == "":
        return stored
    if not is_encrypted(stored):
        return stored  # legacy plaintext — still usable, migration will rewrap it
    token = stored[len(PREFIX):]
    try:
        return _get_cipher().decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken:
        log.warning("crypto: InvalidToken on decrypt — key mismatch? secret lost.")
        return None
    except Exception as e:
        log.warning(f"crypto: decrypt failed: {e}")
        return None


def encrypt_bytes(data: bytes) -> bytes:
    """Used by the backup script to encrypt whole DB files. Returns the
    ciphertext as bytes; caller is responsible for writing it."""
    return _get_cipher().encrypt(data)


def decrypt_bytes(data: bytes) -> bytes:
    return _get_cipher().decrypt(data)


# ── Migration helpers ────────────────────────────────────────────────────

_SETTINGS_KEYS = ("smtp_password", "oidc_client_secret")


def migrate_plaintext(db) -> int:
    """Re-encrypt every plaintext secret in the DB. Idempotent — runs at
    every startup but only touches rows without the `fernet:v1:` prefix."""
    from ..models import Setting, Space

    migrated = 0
    for key in _SETTINGS_KEYS:
        row = db.query(Setting).filter(Setting.key == key).first()
        if not row or not row.value or is_encrypted(row.value):
            continue
        row.value = encrypt(row.value)
        migrated += 1

    for sp in db.query(Space).filter(Space.omada_client_secret.isnot(None)).all():
        if not sp.omada_client_secret or is_encrypted(sp.omada_client_secret):
            continue
        sp.omada_client_secret = encrypt(sp.omada_client_secret)
        migrated += 1

    if migrated:
        db.commit()
        log.warning(f"crypto: migrated {migrated} plaintext secret(s) to fernet:v1")
    return migrated

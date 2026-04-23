"""Minimal OIDC login integration via Authlib.

Config lives in the `settings` key/value table:
  - oidc_enabled            : "true" / "false"
  - oidc_discovery_url      : https://.../.well-known/openid-configuration
  - oidc_client_id
  - oidc_client_secret
  - oidc_allowlist          : comma-separated, e.g. "*@acme.com, bob@foo.com"
  - oidc_button_label       : optional, default "Se connecter via SSO"

Nothing here touches the IdP directly — Authlib handles discovery, PKCE,
state/nonce. We only call this service from the auth router to build /
tear down the OAuth client.
"""
import fnmatch
import logging
from typing import Optional

from authlib.integrations.starlette_client import OAuth
from sqlalchemy.orm import Session

from ..database import SessionLocal
from ..models import Setting
from . import crypto as _crypto

log = logging.getLogger("syslog-server")

OIDC_CLIENT_NAME = "sysloghub_idp"


def _get_all(db: Session) -> dict[str, str]:
    keys = (
        "oidc_enabled", "oidc_discovery_url", "oidc_client_id",
        "oidc_client_secret", "oidc_allowlist", "oidc_button_label",
    )
    rows = db.query(Setting).filter(Setting.key.in_(keys)).all()
    return {r.key: r.value for r in rows}


def is_enabled() -> bool:
    db = SessionLocal()
    try:
        row = db.query(Setting).filter(Setting.key == "oidc_enabled").first()
        if not row or row.value != "true":
            return False
        cfg = _get_all(db)
        return bool(
            cfg.get("oidc_discovery_url")
            and cfg.get("oidc_client_id")
            and cfg.get("oidc_client_secret")
        )
    finally:
        db.close()


def require_verified_email() -> bool:
    """v1.10.0 — default-true toggle. When true, the callback rejects
    users whose IdP doesn't set `email_verified=true`. Admin can disable
    it when the IdP simply doesn't emit the claim."""
    db = SessionLocal()
    try:
        row = db.query(Setting).filter(
            Setting.key == "oidc_require_verified_email"
        ).first()
        # Default: require verification. Explicit "false" opts out.
        return (row.value if row else "true") != "false"
    finally:
        db.close()


def button_label() -> str:
    db = SessionLocal()
    try:
        row = db.query(Setting).filter(Setting.key == "oidc_button_label").first()
        return (row.value if row and row.value else "Se connecter via SSO")
    finally:
        db.close()


def get_oauth() -> Optional[OAuth]:
    """Build a fresh OAuth() instance per call. Authlib caches per-name
    registrations on the OAuth object; by creating a new one here we avoid
    stale state after admin changes the config."""
    db = SessionLocal()
    try:
        cfg = _get_all(db)
    finally:
        db.close()

    if cfg.get("oidc_enabled") != "true":
        return None
    if not (cfg.get("oidc_discovery_url") and cfg.get("oidc_client_id")
            and cfg.get("oidc_client_secret")):
        return None

    secret = _crypto.decrypt(cfg["oidc_client_secret"])
    if not secret:
        return None
    oauth = OAuth()
    oauth.register(
        name=OIDC_CLIENT_NAME,
        client_id=cfg["oidc_client_id"],
        client_secret=secret,
        server_metadata_url=cfg["oidc_discovery_url"],
        client_kwargs={"scope": "openid email profile"},
    )
    return oauth


def email_allowed(email: str) -> bool:
    """Allowlist match. Supports exact emails and `*@domain` glob patterns."""
    if not email:
        return False
    db = SessionLocal()
    try:
        row = db.query(Setting).filter(Setting.key == "oidc_allowlist").first()
        raw = (row.value if row else "") or ""
    finally:
        db.close()

    patterns = [p.strip().lower() for p in raw.split(",") if p.strip()]
    if not patterns:
        return False  # fail-closed: if allowlist is empty, deny everyone

    e = email.strip().lower()
    for pat in patterns:
        if pat == e:
            return True
        if pat.startswith("*@") and fnmatch.fnmatchcase(e, pat):
            return True
    return False

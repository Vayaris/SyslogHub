import logging
import uuid
from datetime import datetime, timezone, timedelta

import bcrypt
from itsdangerous import TimestampSigner, BadSignature, SignatureExpired
from fastapi import Request, HTTPException
from sqlalchemy.orm import Session
from .database import SessionLocal
from .models import ActiveSession, Setting
from . import config

log = logging.getLogger("syslog-server")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_secret() -> str:
    db = SessionLocal()
    try:
        row = db.query(Setting).filter(Setting.key == "session_secret").first()
        return row.value if row else config.SECRET_KEY
    finally:
        db.close()


def totp_enabled() -> bool:
    """True if the admin has TOTP 2FA activated."""
    db = SessionLocal()
    try:
        row = db.query(Setting).filter(Setting.key == "admin_totp_enabled").first()
        return bool(row and row.value == "true")
    finally:
        db.close()


def get_admin_totp_secret() -> str | None:
    db = SessionLocal()
    try:
        row = db.query(Setting).filter(Setting.key == "admin_totp_secret").first()
        return row.value if row else None
    finally:
        db.close()


def get_admin_totp_last_counter() -> int:
    """Return the last TOTP counter value the admin successfully consumed,
    or 0 if unset. Used by verify_and_advance to block replay."""
    db = SessionLocal()
    try:
        row = db.query(Setting).filter(
            Setting.key == "admin_totp_last_counter"
        ).first()
        try:
            return int(row.value) if row else 0
        except (TypeError, ValueError):
            return 0
    finally:
        db.close()


def set_admin_totp_last_counter(counter: int) -> None:
    db = SessionLocal()
    try:
        row = db.query(Setting).filter(
            Setting.key == "admin_totp_last_counter"
        ).first()
        if row:
            row.value = str(counter)
        else:
            db.add(Setting(key="admin_totp_last_counter", value=str(counter)))
        db.commit()
    finally:
        db.close()


# ── Two-step login: tx_id signed tokens (2-min TTL) ───────────────────────────

TOTP_TX_MAX_AGE = 120  # seconds — window to enter the 6-digit code


def make_totp_tx(username: str) -> str:
    """Opaque signed token used between the password step and the TOTP step.

    No DB row: stateless, so it expires by itself after TOTP_TX_MAX_AGE."""
    signer = TimestampSigner(_get_secret() + "|totp")
    return signer.sign(f"totp|{username}").decode()


def verify_totp_tx(token: str) -> str | None:
    signer = TimestampSigner(_get_secret() + "|totp")
    try:
        raw = signer.unsign(token, max_age=TOTP_TX_MAX_AGE).decode()
    except (BadSignature, SignatureExpired):
        return None
    if not raw.startswith("totp|"):
        return None
    return raw.split("|", 1)[1]


def _client_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    xri = request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for")
    if xri:
        return xri.split(",")[0].strip()
    return request.client.host if request.client else None


def _user_agent(request: Request | None) -> str | None:
    if request is None:
        return None
    ua = request.headers.get("user-agent") or ""
    return ua[:255] if ua else None


def create_session(username: str, request: Request | None = None) -> tuple[str, str]:
    """Create a signed token carrying username + session_id, and persist the
    session row in active_sessions. Returns (token, session_id)."""
    session_id = uuid.uuid4().hex
    now = _now_iso()
    db: Session = SessionLocal()
    try:
        row = ActiveSession(
            id=session_id,
            username=username,
            created_at=now,
            last_seen_at=now,
            ip=_client_ip(request),
            user_agent=_user_agent(request),
            revoked=False,
        )
        db.add(row)
        db.commit()
    finally:
        db.close()
    signer = TimestampSigner(_get_secret())
    token = signer.sign(f"{username}|{session_id}").decode()
    return token, session_id


def validate_session(token: str) -> str | None:
    """Return the username if the token is valid, the session exists in DB
    and is not revoked. Also bumps last_seen_at."""
    signer = TimestampSigner(_get_secret())
    try:
        raw = signer.unsign(token, max_age=config.SESSION_MAX_AGE).decode()
    except (BadSignature, SignatureExpired):
        return None

    if "|" not in raw:
        return None
    username, sid = raw.split("|", 1)

    db: Session = SessionLocal()
    try:
        row = db.query(ActiveSession).filter(ActiveSession.id == sid).first()
        if not row or row.revoked or row.username != username:
            return None
        row.last_seen_at = _now_iso()
        db.commit()
        return username
    finally:
        db.close()


def refresh_session_token(token: str) -> str | None:
    """Re-sign a valid token with a fresh timestamp, keeping the same
    session_id. Used by the rolling-session middleware so a single session
    row is not duplicated per request."""
    signer = TimestampSigner(_get_secret())
    try:
        raw = signer.unsign(token, max_age=config.SESSION_MAX_AGE).decode()
    except (BadSignature, SignatureExpired):
        return None
    if "|" not in raw:
        return None
    return signer.sign(raw).decode()


def extract_session_id(token: str) -> str | None:
    """Decode a token and return just the session_id (for UI to mark current)."""
    signer = TimestampSigner(_get_secret())
    try:
        raw = signer.unsign(token, max_age=config.SESSION_MAX_AGE).decode()
    except (BadSignature, SignatureExpired):
        return None
    if "|" not in raw:
        return None
    return raw.split("|", 1)[1]


def revoke_session(session_id: str) -> bool:
    db: Session = SessionLocal()
    try:
        row = db.query(ActiveSession).filter(ActiveSession.id == session_id).first()
        if not row:
            return False
        row.revoked = True
        db.commit()
        return True
    finally:
        db.close()


def purge_stale_sessions(db: Session) -> int:
    """Delete revoked sessions and sessions whose last_seen is older than
    SESSION_MAX_AGE. Called at startup."""
    cutoff = (datetime.now(timezone.utc)
              - timedelta(seconds=config.SESSION_MAX_AGE)).isoformat()
    try:
        n = (db.query(ActiveSession)
             .filter((ActiveSession.revoked.is_(True))
                     | (ActiveSession.last_seen_at < cutoff))
             .delete(synchronize_session=False))
        db.commit()
        return n
    except Exception as e:
        db.rollback()
        log.warning(f"purge_stale_sessions failed: {e}")
        return 0


def get_current_user(request: Request) -> str:
    token = request.cookies.get("session")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    username = validate_session(token)
    if not username:
        raise HTTPException(status_code=401, detail="Session expired")
    return username


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


def authenticate_user(username: str, password: str) -> bool:
    db = SessionLocal()
    try:
        u_row = db.query(Setting).filter(Setting.key == "admin_username").first()
        p_row = db.query(Setting).filter(Setting.key == "admin_password_hash").first()
        if not u_row or not p_row:
            return False
        return u_row.value == username and verify_password(password, p_row.value)
    finally:
        db.close()

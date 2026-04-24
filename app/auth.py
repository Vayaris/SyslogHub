import logging
import uuid
from datetime import datetime, timezone, timedelta

import bcrypt
from itsdangerous import TimestampSigner, BadSignature, SignatureExpired
from fastapi import Request, HTTPException
from sqlalchemy.orm import Session
from .database import SessionLocal
from .models import ActiveSession, Setting, User
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


def totp_enabled_for(username: str) -> bool:
    """True if this user has TOTP 2FA activated (v2 user row or legacy admin)."""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if user and user.totp_enabled and user.totp_secret:
            return True
        # Legacy fallback : the global admin TOTP setting, only if the username
        # matches the legacy admin_username (so an OIDC user doesn't accidentally
        # inherit the admin's 2FA challenge).
        admin_name = db.query(Setting).filter(Setting.key == "admin_username").first()
        if admin_name and admin_name.value == username:
            row = db.query(Setting).filter(Setting.key == "admin_totp_enabled").first()
            return bool(row and row.value == "true")
        return False
    finally:
        db.close()


def totp_enabled() -> bool:
    """Legacy wrapper : True if the *legacy admin* has TOTP. Kept for
    code paths that still reference the global admin."""
    db = SessionLocal()
    try:
        row = db.query(Setting).filter(Setting.key == "admin_totp_enabled").first()
        return bool(row and row.value == "true")
    finally:
        db.close()


def get_totp_secret_for(username: str) -> str | None:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if user and user.totp_enabled and user.totp_secret:
            return user.totp_secret
        # Legacy admin fallback
        admin_name = db.query(Setting).filter(Setting.key == "admin_username").first()
        if admin_name and admin_name.value == username:
            row = db.query(Setting).filter(Setting.key == "admin_totp_secret").first()
            return row.value if row else None
        return None
    finally:
        db.close()


def get_admin_totp_secret() -> str | None:
    """Legacy wrapper. Prefer `get_totp_secret_for(username)` in new code."""
    db = SessionLocal()
    try:
        row = db.query(Setting).filter(Setting.key == "admin_totp_secret").first()
        return row.value if row else None
    finally:
        db.close()


def get_totp_last_counter_for(username: str) -> int:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if user and user.totp_enabled:
            return int(user.totp_last_counter or 0)
        admin_name = db.query(Setting).filter(Setting.key == "admin_username").first()
        if admin_name and admin_name.value == username:
            row = db.query(Setting).filter(Setting.key == "admin_totp_last_counter").first()
            try:
                return int(row.value) if row else 0
            except (TypeError, ValueError):
                return 0
        return 0
    finally:
        db.close()


def get_admin_totp_last_counter() -> int:
    """Legacy wrapper."""
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


def set_totp_last_counter_for(username: str, counter: int) -> None:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if user and user.totp_enabled:
            user.totp_last_counter = counter
            db.commit()
            return
        # Legacy admin
        admin_name = db.query(Setting).filter(Setting.key == "admin_username").first()
        if admin_name and admin_name.value == username:
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


def set_admin_totp_last_counter(counter: int) -> None:
    """Legacy wrapper."""
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
    """Legacy dependency: returns the username string. Kept for routes
    that only need to audit the actor. Prefer `get_current_user_obj` for
    RBAC-aware code (Phase A v2.0.0)."""
    token = request.cookies.get("session")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    username = validate_session(token)
    if not username:
        raise HTTPException(status_code=401, detail="Session expired")
    return username


def get_user_by_username(db: Session, username: str) -> User | None:
    return db.query(User).filter(User.username == username).first()


def get_user_by_id(db: Session, user_id: int) -> User | None:
    return db.query(User).filter(User.id == user_id).first()


def get_current_user_obj(request: Request) -> User:
    """v2.0.0 — dependency that resolves the session cookie to a User object.

    Falls back to the legacy admin settings if the User row hasn't been
    created yet (fresh install, first boot before migration ran — should
    be impossible, but we fail-open to the admin in that case so the user
    doesn't get locked out of their own instance)."""
    token = request.cookies.get("session")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    username = validate_session(token)
    if not username:
        raise HTTPException(status_code=401, detail="Session expired")
    db = SessionLocal()
    try:
        user = get_user_by_username(db, username)
        if user is None:
            # Migration may not have run yet OR the legacy admin renamed but
            # didn't propagate. Last-ditch : if this username matches the
            # legacy admin_username setting, treat as admin.
            admin_row = db.query(Setting).filter(Setting.key == "admin_username").first()
            if admin_row and admin_row.value == username:
                # Synthesize an in-memory User (not persisted) to unblock the
                # admin UI. Startup migration will create the row on next boot.
                stub = User(
                    id=0, username=username, role_global="admin",
                    disabled=False, created_at=_now_iso(),
                )
                return stub
            raise HTTPException(status_code=401, detail="Utilisateur introuvable")
        if user.disabled:
            raise HTTPException(status_code=403, detail="Compte désactivé")
        # Expunge so the caller can access attributes after the session closes
        db.expunge(user)
        return user
    finally:
        db.close()


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


def authenticate_user(username: str, password: str) -> bool:
    """Check credentials. v2.0.0 : tries the `users` table first (post-migration),
    then falls back to the legacy `admin_*` settings (in case migration didn't
    run yet or the only admin is still the legacy one)."""
    db = SessionLocal()
    try:
        # Users table (v2+)
        user = db.query(User).filter(User.username == username).first()
        if user and not user.disabled and user.password_hash:
            if verify_password(password, user.password_hash):
                # Touch last_login_at (best-effort)
                try:
                    user.last_login_at = _now_iso()
                    db.commit()
                except Exception:
                    db.rollback()
                return True

        # Legacy admin fallback
        u_row = db.query(Setting).filter(Setting.key == "admin_username").first()
        p_row = db.query(Setting).filter(Setting.key == "admin_password_hash").first()
        if not u_row or not p_row:
            return False
        return u_row.value == username and verify_password(password, p_row.value)
    finally:
        db.close()

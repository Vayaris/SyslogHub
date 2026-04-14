import bcrypt
from itsdangerous import TimestampSigner, BadSignature, SignatureExpired
from fastapi import Request, HTTPException
from .database import SessionLocal
from .models import Setting
from . import config


def _get_secret() -> str:
    db = SessionLocal()
    try:
        row = db.query(Setting).filter(Setting.key == "session_secret").first()
        return row.value if row else config.SECRET_KEY
    finally:
        db.close()


def create_session(username: str) -> str:
    signer = TimestampSigner(_get_secret())
    return signer.sign(username).decode()


def validate_session(token: str) -> str | None:
    signer = TimestampSigner(_get_secret())
    try:
        username = signer.unsign(token, max_age=config.SESSION_MAX_AGE).decode()
        return username
    except (BadSignature, SignatureExpired):
        return None


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

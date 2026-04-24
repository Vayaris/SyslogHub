from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from ..auth import (
    authenticate_user, create_session, extract_session_id,
    get_totp_secret_for, get_totp_last_counter_for,
    get_current_user, make_totp_tx,
    revoke_session, set_totp_last_counter_for,
    totp_enabled_for, verify_totp_tx,
)
from ..database import get_db
from ..models import User
from ..schemas import LoginRequest, TOTPLoginRequest
from ..services import audit as audit_svc
from ..services import oidc as oidc_svc
from ..services import ratelimit as ratelimit_svc
from ..services import totp as totp_svc


def _client_ip(request: Request) -> str | None:
    xri = request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for")
    if xri:
        return xri.split(",")[0].strip()
    return request.client.host if request.client else None


def _ensure_not_locked(db: Session, request: Request, username: str) -> None:
    """Raise 429 if the account is currently locked. Logs the block in the
    audit trail so admins can see lockouts in /settings → Audit."""
    locked, retry_after = ratelimit_svc.is_locked(db, username)
    if not locked:
        return
    audit_svc.log_event(db, request, "login_locked",
                        username=username,
                        details={"retry_after_seconds": retry_after})
    raise HTTPException(
        status_code=429,
        detail=f"Trop de tentatives échouées. Réessayez dans {retry_after} s.",
        headers={"Retry-After": str(retry_after)},
    )

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _set_session_cookie(response: Response, request: Request, token: str):
    is_https = request.url.scheme == "https"
    response.set_cookie(
        key="session",
        value=token,
        httponly=True,
        secure=is_https,
        samesite="strict",
        path="/",
        max_age=86400,
    )


@router.post("/login")
def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    _ensure_not_locked(db, request, body.username)
    ip = _client_ip(request)

    if not authenticate_user(body.username, body.password):
        ratelimit_svc.record_attempt(db, body.username, ip, success=False)
        audit_svc.log_event(db, request, "login_failed",
                            username=body.username,
                            details={"reason": "bad_credentials"})
        raise HTTPException(status_code=401, detail="Identifiants invalides")

    # If 2FA is active for this user, issue a short-lived tx_id instead of a
    # session cookie; the client must POST /login/totp with a valid code.
    # Note: we do NOT reset the lockout counter yet — the password step alone
    # is not a full success until the TOTP step also passes.
    if totp_enabled_for(body.username):
        audit_svc.log_event(db, request, "login_totp_challenge",
                            username=body.username)
        return {
            "ok": True,
            "totp_required": True,
            "tx_id": make_totp_tx(body.username),
        }

    ratelimit_svc.record_attempt(db, body.username, ip, success=True)
    token, session_id = create_session(body.username, request)
    _set_session_cookie(response, request, token)
    audit_svc.log_event(db, request, "login",
                        username=body.username,
                        details={"via": "local", "session_id": session_id})
    return {"ok": True}


@router.post("/login/totp")
def login_totp(
    body: TOTPLoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    username = verify_totp_tx(body.tx_id)
    if not username:
        audit_svc.log_event(db, request, "login_totp_failed",
                            details={"reason": "bad_tx"})
        raise HTTPException(status_code=401,
                            detail="Session d'authentification expirée, veuillez recommencer")

    _ensure_not_locked(db, request, username)
    ip = _client_ip(request)

    secret = get_totp_secret_for(username)
    matched_counter = totp_svc.verify_and_advance(
        secret or "", body.code, get_totp_last_counter_for(username)
    )
    if matched_counter is None:
        ratelimit_svc.record_attempt(db, username, ip, success=False)
        # Distinguish "bad code" from "replay" for the audit log — but still
        # return the same 401 to the client so an attacker can't probe the
        # counter state.
        replay = bool(secret and totp_svc.verify(secret, body.code))
        audit_svc.log_event(db, request, "login_totp_failed",
                            username=username,
                            details={"reason": "replay" if replay else "bad_code"})
        raise HTTPException(status_code=401, detail="Code 2FA invalide")

    # Burn the counter so the same code can't be reused within its window.
    set_totp_last_counter_for(username, matched_counter)
    ratelimit_svc.record_attempt(db, username, ip, success=True)
    token, session_id = create_session(username, request)
    _set_session_cookie(response, request, token)
    audit_svc.log_event(db, request, "login",
                        username=username,
                        details={"via": "local+totp", "session_id": session_id})
    return {"ok": True}


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    token = request.cookies.get("session")
    username = None
    if token:
        from ..auth import validate_session
        username = validate_session(token)  # resolve BEFORE revoking
        sid = extract_session_id(token)
        if sid:
            revoke_session(sid)
    response.delete_cookie("session", path="/")
    audit_svc.log_event(db, request, "logout", username=username)
    return {"ok": True}


@router.get("/me")
def me(
    request: Request,
    db: Session = Depends(get_db),
    username: str = Depends(get_current_user),
):
    """Enriched user info for the frontend (v2.0.0).

    Backward-compatible : the `username` field is preserved; new fields are
    additive so legacy JS keeps working."""
    u = db.query(User).filter(User.username == username).first()
    # Legacy admin fallback (if migration hasn't created the row yet)
    from ..models import Setting
    password_must_change = False
    flag = db.query(Setting).filter(Setting.key == "admin_password_must_change").first()
    admin_row = db.query(Setting).filter(Setting.key == "admin_username").first()
    legacy_admin = admin_row.value if admin_row else "admin"
    if flag and flag.value == "true" and username == legacy_admin:
        password_must_change = True

    if u is None:
        # Synthesize for the legacy admin (shouldn't normally happen)
        return {
            "username": username,
            "email": None,
            "role_global": "admin" if username == legacy_admin else "operator",
            "is_admin": (username == legacy_admin),
            "totp_enabled": False,
            "password_must_change": password_must_change,
        }
    return {
        "username": u.username,
        "email": u.email,
        "role_global": u.role_global,
        "is_admin": (u.role_global == "admin" and not u.disabled),
        "totp_enabled": bool(u.totp_enabled),
        "password_must_change": password_must_change,
    }


# ── OIDC / SSO ────────────────────────────────────────────────────────────────

@router.get("/oidc/status")
def oidc_status():
    """Public probe used by /login to decide whether to show the SSO button."""
    return {
        "enabled": oidc_svc.is_enabled(),
        "label": oidc_svc.button_label(),
    }


@router.get("/oidc/login")
async def oidc_login(request: Request):
    oauth = oidc_svc.get_oauth()
    if not oauth:
        raise HTTPException(status_code=400, detail="OIDC non configuré")
    redirect_uri = str(request.url_for("oidc_callback"))
    # Trust X-Forwarded-Proto from the nginx proxy.
    if request.headers.get("x-forwarded-proto") == "https":
        redirect_uri = redirect_uri.replace("http://", "https://", 1)
    client = oauth.create_client(oidc_svc.OIDC_CLIENT_NAME)
    return await client.authorize_redirect(request, redirect_uri)


@router.get("/oidc/callback", name="oidc_callback")
async def oidc_callback(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    oauth = oidc_svc.get_oauth()
    if not oauth:
        raise HTTPException(status_code=400, detail="OIDC non configuré")
    client = oauth.create_client(oidc_svc.OIDC_CLIENT_NAME)
    try:
        token = await client.authorize_access_token(request)
    except Exception as e:
        audit_svc.log_event(db, request, "login_failed",
                            details={"via": "oidc", "error": str(e)[:200]})
        return RedirectResponse(url="/login?error=oidc_denied", status_code=302)

    userinfo = token.get("userinfo") or {}
    if not userinfo:
        try:
            userinfo = await client.userinfo(token=token)
        except Exception:
            userinfo = {}

    email = (userinfo.get("email") or "").strip().lower()
    if not email or not oidc_svc.email_allowed(email):
        audit_svc.log_event(db, request, "login_failed",
                            details={"via": "oidc", "reason": "not_allowlisted",
                                     "email": email or None})
        return RedirectResponse(url="/login?error=oidc_denied", status_code=302)

    # v1.10.0 — refuse unverified emails by default. A laxist IdP that lets
    # users register with any address they don't control would otherwise
    # bypass the allowlist. The admin can relax this via a setting if their
    # IdP simply doesn't emit the claim.
    require_verified = oidc_svc.require_verified_email()
    if require_verified and not userinfo.get("email_verified", False):
        audit_svc.log_event(db, request, "login_failed",
                            details={"via": "oidc", "reason": "email_unverified",
                                     "email": email})
        return RedirectResponse(url="/login?error=oidc_denied", status_code=302)

    # v2.0.0 — provision the user in the `users` table on first login.
    # Subsequent logins just bump last_login_at.
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    sub = (userinfo.get("sub") or "").strip() or None
    user = (
        db.query(User).filter(User.oidc_subject == sub).first() if sub else None
    ) or db.query(User).filter(User.username == email).first()

    if user is None:
        user = User(
            username     = email,
            email        = email,
            password_hash= None,
            role_global  = "operator",     # OIDC users get operator by default; admin can promote
            oidc_subject = sub,
            created_at   = now,
            last_login_at= now,
        )
        db.add(user)
        db.commit()
    else:
        user.last_login_at = now
        if sub and not user.oidc_subject:
            user.oidc_subject = sub
        db.commit()

    redirect = RedirectResponse(url="/dashboard", status_code=302)
    session_token, session_id = create_session(user.username, request)
    _set_session_cookie(redirect, request, session_token)
    audit_svc.log_event(db, request, "login",
                        username=user.username,
                        details={"via": "oidc", "session_id": session_id,
                                 "new_user": bool(user.last_login_at == now and (user.created_at or "") == now)})
    return redirect

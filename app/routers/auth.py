from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from ..auth import (
    authenticate_user, create_session, extract_session_id,
    get_admin_totp_secret, get_current_user, make_totp_tx,
    revoke_session, totp_enabled, verify_totp_tx,
)
from ..database import get_db
from ..schemas import LoginRequest, TOTPLoginRequest
from ..services import audit as audit_svc
from ..services import oidc as oidc_svc
from ..services import totp as totp_svc

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
    if not authenticate_user(body.username, body.password):
        audit_svc.log_event(db, request, "login_failed",
                            username=body.username,
                            details={"reason": "bad_credentials"})
        raise HTTPException(status_code=401, detail="Identifiants invalides")

    # If 2FA is active, issue a short-lived tx_id instead of a session cookie;
    # the client must POST /login/totp with a valid code to finish login.
    if totp_enabled():
        audit_svc.log_event(db, request, "login_totp_challenge",
                            username=body.username)
        return {
            "ok": True,
            "totp_required": True,
            "tx_id": make_totp_tx(body.username),
        }

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

    secret = get_admin_totp_secret()
    if not secret or not totp_svc.verify(secret, body.code):
        audit_svc.log_event(db, request, "login_totp_failed",
                            username=username,
                            details={"reason": "bad_code"})
        raise HTTPException(status_code=401, detail="Code 2FA invalide")

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
def me(username: str = Depends(get_current_user)):
    return {"username": username}


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

    # Use the email as the app username (we're a single-admin app, but the
    # audit log will show the real person behind the SSO).
    redirect = RedirectResponse(url="/dashboard", status_code=302)
    session_token, session_id = create_session(email, request)
    _set_session_cookie(redirect, request, session_token)
    audit_svc.log_event(db, request, "login",
                        username=email,
                        details={"via": "oidc", "session_id": session_id})
    return redirect

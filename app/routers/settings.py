import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy.orm import Session

from ..auth import (
    extract_session_id, get_current_user, hash_password, verify_password,
)
from ..database import get_db
from ..models import ActiveSession, AuditLog, Setting, Space
from ..schemas import (
    AlertsConfigOut, AlertsConfigUpdate, AlertTestRequest,
    AuditEntry, AuditListResponse,
    OIDCConfigOut, OIDCConfigUpdate,
    SessionInfo,
    SettingsOut, SettingsUpdate, SystemStatus,
    TOTPActivateRequest, TOTPDisableRequest, TOTPSetupResponse, TOTPStatus,
)
from ..services import alerts as alerts_svc
from ..services import audit as audit_svc
from ..services import totp as totp_svc
from ..services.log_scanner import total_log_size, volume_by_day
from ..utils import service_active
from .. import config

router = APIRouter(prefix="/api/settings", tags=["settings"])


def _get_setting(db: Session, key: str) -> str | None:
    row = db.query(Setting).filter(Setting.key == key).first()
    return row.value if row else None


def _set_setting(db: Session, key: str, value: str):
    row = db.query(Setting).filter(Setting.key == key).first()
    if row:
        row.value = value
    else:
        db.add(Setting(key=key, value=value))
    db.commit()


@router.get("", response_model=SettingsOut)
def get_settings(
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    return SettingsOut(
        retention_days=int(_get_setting(db, "retention_days") or "90"),
        admin_username=_get_setting(db, "admin_username") or "admin",
    )


@router.put("")
def update_settings(
    body: SettingsUpdate,
    request: Request,
    db: Session = Depends(get_db),
    username: str = Depends(get_current_user),
):
    changed: list[str] = []

    if body.retention_days is not None:
        _set_setting(db, "retention_days", str(body.retention_days))
        changed.append("retention_days")

    if body.admin_username is not None:
        _set_setting(db, "admin_username", body.admin_username)
        changed.append("admin_username")

    if body.new_password is not None:
        if not body.current_password:
            raise HTTPException(
                status_code=400, detail="Mot de passe actuel requis"
            )
        current_hash = _get_setting(db, "admin_password_hash") or ""
        if not verify_password(body.current_password, current_hash):
            audit_svc.log_event(db, request, "password_change_failed",
                                username=username,
                                details={"reason": "bad_current"})
            raise HTTPException(
                status_code=400, detail="Mot de passe actuel incorrect"
            )
        _set_setting(db, "admin_password_hash", hash_password(body.new_password))
        # Rotate session secret so all existing sessions (this browser + others) are invalidated
        _set_setting(db, "session_secret", secrets.token_hex(32))
        audit_svc.log_event(db, request, "password_change", username=username)

    if changed:
        audit_svc.log_event(db, request, "settings_update",
                            username=username, details={"fields": changed})

    return {"ok": True}


@router.get("/status", response_model=SystemStatus)
def system_status(
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    total = db.query(Space).count()
    enabled = db.query(Space).filter(Space.enabled == True).count()

    db_size = 0
    try:
        db_size = Path(config.DB_PATH).stat().st_size
    except OSError:
        pass

    return SystemStatus(
        rsyslog_active=service_active("rsyslog"),
        nginx_active=service_active("nginx"),
        total_log_size_bytes=total_log_size(),
        total_spaces=total,
        enabled_spaces=enabled,
        db_size_bytes=db_size,
    )


@router.get("/volume")
def log_volume(
    days: int = Query(default=7, ge=1, le=90),
    _: str = Depends(get_current_user),
):
    return volume_by_day(days)


# ── Alerts (no-log) ───────────────────────────────────────────────────────────

@router.get("/alerts", response_model=AlertsConfigOut)
def get_alerts_config(
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    port = _get_setting(db, "smtp_port")
    return AlertsConfigOut(
        enabled=(_get_setting(db, "alerts_global_enabled") or "false") == "true",
        smtp_host=_get_setting(db, "smtp_host") or None,
        smtp_port=int(port) if port else None,
        smtp_username=_get_setting(db, "smtp_username") or None,
        smtp_from_email=_get_setting(db, "smtp_from_email") or None,
        smtp_default_to=_get_setting(db, "smtp_default_to") or None,
        smtp_password_set=bool(_get_setting(db, "smtp_password")),
    )


@router.put("/alerts")
def update_alerts_config(
    body: AlertsConfigUpdate,
    request: Request,
    db: Session = Depends(get_db),
    username: str = Depends(get_current_user),
):
    fields = body.model_fields_set
    if "enabled" in fields:
        _set_setting(db, "alerts_global_enabled", "true" if body.enabled else "false")
    text_map = {
        "smtp_host": "smtp_host",
        "smtp_username": "smtp_username",
        "smtp_from_email": "smtp_from_email",
        "smtp_default_to": "smtp_default_to",
    }
    for bf, key in text_map.items():
        if bf in fields:
            _set_setting(db, key, (getattr(body, bf) or "").strip())
    if "smtp_port" in fields and body.smtp_port is not None:
        _set_setting(db, "smtp_port", str(body.smtp_port))
    # Password: empty/None = keep; value = overwrite
    if "smtp_password" in fields and body.smtp_password:
        _set_setting(db, "smtp_password", body.smtp_password)
    audit_svc.log_event(db, request, "alerts_update",
                        username=username, details={"fields": sorted(fields)})
    return {"ok": True}


@router.post("/alerts/test")
def test_alerts_config(
    body: AlertTestRequest,
    request: Request,
    db: Session = Depends(get_db),
    username: str = Depends(get_current_user),
):
    smtp = alerts_svc.get_settings(db)
    try:
        alerts_svc.send_test_email(smtp, body.to_email)
    except Exception as e:
        audit_svc.log_event(db, request, "alerts_test_failed",
                            username=username,
                            details={"to": body.to_email, "error": str(e)[:200]})
        raise HTTPException(status_code=502, detail=f"Échec de l'envoi : {e}")
    audit_svc.log_event(db, request, "alerts_test",
                        username=username, details={"to": body.to_email})
    return {"ok": True}


# ── Audit log ─────────────────────────────────────────────────────────────────

@router.get("/audit", response_model=AuditListResponse)
def list_audit(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=500),
    action: str = Query(default=""),
    username: str = Query(default=""),
    since: str = Query(default=""),
    until: str = Query(default=""),
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    q = db.query(AuditLog)
    if action:
        q = q.filter(AuditLog.action == action)
    if username:
        q = q.filter(AuditLog.username == username)
    if since:
        q = q.filter(AuditLog.ts >= since)
    if until:
        q = q.filter(AuditLog.ts <= until)

    total = q.count()
    pages = max(1, (total + per_page - 1) // per_page)
    rows = (q.order_by(AuditLog.ts.desc())
             .offset((page - 1) * per_page)
             .limit(per_page)
             .all())
    items = [
        AuditEntry(
            id=r.id, ts=r.ts, username=r.username, action=r.action,
            ip=r.ip, user_agent=r.user_agent, details=r.details,
        ) for r in rows
    ]
    return AuditListResponse(
        items=items, total=total, page=page, per_page=per_page, pages=pages,
    )


@router.delete("/audit")
def purge_audit(
    request: Request,
    before: str = Query(default=""),
    db: Session = Depends(get_db),
    username: str = Depends(get_current_user),
):
    cutoff = before or datetime.now(timezone.utc).isoformat()
    n = (db.query(AuditLog)
           .filter(AuditLog.ts < cutoff)
           .delete(synchronize_session=False))
    db.commit()
    audit_svc.log_event(db, request, "audit_purge",
                        username=username,
                        details={"before": cutoff, "deleted": int(n)})
    return {"ok": True, "deleted": int(n)}


# ── Active sessions ───────────────────────────────────────────────────────────

def _current_session_id(request: Request) -> str | None:
    token = request.cookies.get("session")
    return extract_session_id(token) if token else None


@router.get("/sessions", response_model=list[SessionInfo])
def list_sessions(
    request: Request,
    db: Session = Depends(get_db),
    username: str = Depends(get_current_user),
):
    current_sid = _current_session_id(request)
    rows = (db.query(ActiveSession)
              .filter(ActiveSession.username == username,
                      ActiveSession.revoked == False)  # noqa: E712
              .order_by(ActiveSession.last_seen_at.desc())
              .all())
    return [
        SessionInfo(
            id=r.id, username=r.username,
            created_at=r.created_at, last_seen_at=r.last_seen_at,
            ip=r.ip, user_agent=r.user_agent,
            is_current=(r.id == current_sid),
        ) for r in rows
    ]


@router.delete("/sessions/{session_id}")
def revoke_one_session(
    session_id: str,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    username: str = Depends(get_current_user),
):
    row = (db.query(ActiveSession)
             .filter(ActiveSession.id == session_id,
                     ActiveSession.username == username)
             .first())
    if not row:
        raise HTTPException(status_code=404, detail="Session introuvable")
    row.revoked = True
    db.commit()

    is_current = (session_id == _current_session_id(request))
    if is_current:
        response.delete_cookie("session", path="/")

    audit_svc.log_event(db, request, "session_revoke",
                        username=username,
                        details={"session_id": session_id,
                                 "self": is_current})
    return {"ok": True, "was_current": is_current}


# ── OIDC / SSO configuration ──────────────────────────────────────────────────

_OIDC_KEYS = [
    "oidc_enabled", "oidc_discovery_url", "oidc_client_id",
    "oidc_client_secret", "oidc_allowlist", "oidc_button_label",
]


@router.get("/oidc", response_model=OIDCConfigOut)
def get_oidc_config(
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    return OIDCConfigOut(
        enabled=(_get_setting(db, "oidc_enabled") or "false") == "true",
        discovery_url=_get_setting(db, "oidc_discovery_url") or None,
        client_id=_get_setting(db, "oidc_client_id") or None,
        allowlist=_get_setting(db, "oidc_allowlist") or None,
        button_label=_get_setting(db, "oidc_button_label") or None,
        client_secret_set=bool(_get_setting(db, "oidc_client_secret")),
    )


@router.put("/oidc")
def update_oidc_config(
    body: OIDCConfigUpdate,
    request: Request,
    db: Session = Depends(get_db),
    username: str = Depends(get_current_user),
):
    fields = body.model_fields_set
    if "enabled" in fields:
        _set_setting(db, "oidc_enabled", "true" if body.enabled else "false")
    text_map = {
        "discovery_url": "oidc_discovery_url",
        "client_id":     "oidc_client_id",
        "allowlist":     "oidc_allowlist",
        "button_label":  "oidc_button_label",
    }
    for bf, key in text_map.items():
        if bf in fields:
            _set_setting(db, key, (getattr(body, bf) or "").strip())
    # Secret: empty/None = keep; non-empty = overwrite
    if "client_secret" in fields and body.client_secret:
        _set_setting(db, "oidc_client_secret", body.client_secret)
    audit_svc.log_event(db, request, "oidc_config_update",
                        username=username,
                        details={"fields": sorted(fields)})
    return {"ok": True}


# ── TOTP 2FA ──────────────────────────────────────────────────────────────────

@router.get("/totp", response_model=TOTPStatus)
def totp_status(
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    return TOTPStatus(
        enabled=(_get_setting(db, "admin_totp_enabled") or "false") == "true",
        pending=bool(_get_setting(db, "admin_totp_secret_pending")),
    )


@router.post("/totp/setup", response_model=TOTPSetupResponse)
def totp_setup(
    db: Session = Depends(get_db),
    username: str = Depends(get_current_user),
):
    if (_get_setting(db, "admin_totp_enabled") or "false") == "true":
        raise HTTPException(status_code=400, detail="2FA déjà activé")
    secret = totp_svc.generate_secret()
    _set_setting(db, "admin_totp_secret_pending", secret)
    uri = totp_svc.build_uri(username, secret)
    return TOTPSetupResponse(uri=uri, svg=totp_svc.qr_svg(uri))


@router.post("/totp/activate")
def totp_activate(
    body: TOTPActivateRequest,
    request: Request,
    db: Session = Depends(get_db),
    username: str = Depends(get_current_user),
):
    pending = _get_setting(db, "admin_totp_secret_pending")
    if not pending:
        raise HTTPException(status_code=400, detail="Aucune inscription 2FA en cours")
    if not totp_svc.verify(pending, body.code):
        raise HTTPException(status_code=400, detail="Code invalide")
    _set_setting(db, "admin_totp_secret", pending)
    _set_setting(db, "admin_totp_enabled", "true")
    # Clear pending
    row = db.query(Setting).filter(Setting.key == "admin_totp_secret_pending").first()
    if row:
        db.delete(row)
        db.commit()
    audit_svc.log_event(db, request, "totp_enable", username=username)
    return {"ok": True}


@router.delete("/totp")
def totp_disable(
    body: TOTPDisableRequest,
    request: Request,
    db: Session = Depends(get_db),
    username: str = Depends(get_current_user),
):
    current_hash = _get_setting(db, "admin_password_hash") or ""
    if not verify_password(body.password, current_hash):
        audit_svc.log_event(db, request, "totp_disable_failed",
                            username=username,
                            details={"reason": "bad_password"})
        raise HTTPException(status_code=400, detail="Mot de passe incorrect")
    for key in ("admin_totp_enabled", "admin_totp_secret", "admin_totp_secret_pending"):
        row = db.query(Setting).filter(Setting.key == key).first()
        if row:
            db.delete(row)
    db.commit()
    audit_svc.log_event(db, request, "totp_disable", username=username)
    return {"ok": True}


@router.delete("/sessions")
def revoke_other_sessions(
    request: Request,
    db: Session = Depends(get_db),
    username: str = Depends(get_current_user),
):
    current_sid = _current_session_id(request)
    q = (db.query(ActiveSession)
           .filter(ActiveSession.username == username,
                   ActiveSession.revoked == False))  # noqa: E712
    if current_sid:
        q = q.filter(ActiveSession.id != current_sid)
    affected = q.all()
    ids = [r.id for r in affected]
    for r in affected:
        r.revoked = True
    db.commit()
    audit_svc.log_event(db, request, "sessions_revoke_others",
                        username=username,
                        details={"count": len(ids)})
    return {"ok": True, "revoked": len(ids)}

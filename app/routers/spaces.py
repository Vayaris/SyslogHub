from datetime import datetime, timezone
from pathlib import Path
from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from sqlalchemy.orm import Session

from ..auth import get_current_user_obj
from ..database import get_db
from ..models import Space, User
from ..schemas import SpaceCreate, SpaceOut, SpaceStats, SpaceUpdate
from ..services import rsyslog as rsyslog_svc
from ..services import log_scanner
from ..services import omada as omada_svc
from ..services import audit as audit_svc
from ..services import crypto as crypto_svc
from ..services import rbac
from ..services import url_guard


def _check_omada_url(body) -> None:
    """Reject Omada URLs pointing at cloud metadata, loopback, or link-local
    ranges. LAN-private IPs are allowed (a typical Omada controller lives on
    10.x or 172.16.x) but never cloud-metadata or localhost."""
    if "omada_base_url" not in body.model_fields_set:
        return
    val = (body.omada_base_url or "").strip()
    if not val:
        return
    ok, reason = url_guard.validate_url(val, allow_private=True)
    if not ok:
        raise HTTPException(
            status_code=400,
            detail=f"URL du contrôleur Omada refusée : {reason}",
        )

router = APIRouter(prefix="/api/spaces", tags=["spaces"])


def _space_out(space: Space, with_stats: bool = True) -> SpaceOut:
    stats = None
    if with_stats:
        try:
            raw = log_scanner.get_space_stats(space.port)
            stats = SpaceStats(**raw)
        except Exception:
            stats = SpaceStats(source_count=0, total_size_bytes=0, last_seen=None)
    return SpaceOut(
        id=space.id,
        name=space.name,
        port=space.port,
        enabled=space.enabled,
        description=space.description,
        allowed_ip=getattr(space, "allowed_ip", None),
        tcp_enabled=bool(getattr(space, "tcp_enabled", False)),
        lan_mode=bool(getattr(space, "lan_mode", False)),
        omada_base_url=space.omada_base_url or None,
        omada_id=space.omada_id or None,
        omada_client_id=space.omada_client_id or None,
        omada_verify_ssl=bool(space.omada_verify_ssl),
        omada_configured=omada_svc.is_configured(space),
        omada_controller_ip=getattr(space, "omada_controller_ip", None) or None,
        alerts_enabled=bool(getattr(space, "alerts_enabled", False)),
        alert_threshold_hours=int(getattr(space, "alert_threshold_hours", 24) or 24),
        alert_email_to=getattr(space, "alert_email_to", None) or None,
        alert_webhook_url=getattr(space, "alert_webhook_url", None) or None,
        alert_state=getattr(space, "alert_state", "ok") or "ok",
        alert_last_transition_at=getattr(space, "alert_last_transition_at", None),
        retention_days=int(getattr(space, "retention_days", 365) or 365),
        branding_logo_path=getattr(space, "branding_logo_path", None) or None,
        branding_color=getattr(space, "branding_color", None) or None,
        dhcp_parse_enabled=bool(getattr(space, "dhcp_parse_enabled", False)),
        omada_sync_enabled=bool(getattr(space, "omada_sync_enabled", False)),
        chain_enabled=bool(getattr(space, "chain_enabled", True)),
        created_at=space.created_at,
        updated_at=space.updated_at,
        stats=stats,
    )


def _apply_alert_fields(space: Space, body, is_create: bool):
    """Copy alert fields from SpaceCreate/SpaceUpdate onto the Space row."""
    fields = body.model_fields_set
    if is_create or "alerts_enabled" in fields:
        if body.alerts_enabled is not None:
            space.alerts_enabled = bool(body.alerts_enabled)
    if is_create or "alert_threshold_hours" in fields:
        if body.alert_threshold_hours is not None:
            space.alert_threshold_hours = int(body.alert_threshold_hours)
    if is_create or "alert_email_to" in fields:
        val = (body.alert_email_to or "").strip() or None
        space.alert_email_to = val
    if is_create or "alert_webhook_url" in fields:
        val = (body.alert_webhook_url or "").strip() or None
        space.alert_webhook_url = val


def _apply_omada_fields(space: Space, body, is_create: bool):
    """Copy Omada fields from a SpaceCreate/SpaceUpdate body onto a Space row.

    Create: all provided fields are written verbatim (client_secret required for config to be effective).
    Update: fields explicitly set in the payload are written; an empty client_secret means 'keep current'.
    Returns True if any Omada-related field changed (so the cached client can be dropped)."""
    changed = False
    fields_set = body.model_fields_set

    # Text fields — treat empty string as "clear"
    text_map = {
        "omada_base_url":      "omada_base_url",
        "omada_id":            "omada_id",
        "omada_client_id":     "omada_client_id",
        "omada_controller_ip": "omada_controller_ip",
    }
    for body_field, col in text_map.items():
        if is_create or body_field in fields_set:
            new_val = getattr(body, body_field)
            new_val = (new_val or "").strip() or None
            if getattr(space, col) != new_val:
                setattr(space, col, new_val)
                changed = True

    # Secret — only overwrite when a non-empty value is provided.
    # v1.10.0: stored encrypted at rest (Fernet).
    if is_create or "omada_client_secret" in fields_set:
        sec = body.omada_client_secret
        if sec:  # non-empty → overwrite
            wrapped = crypto_svc.encrypt(sec)
            if space.omada_client_secret != wrapped:
                space.omada_client_secret = wrapped
                changed = True
        elif is_create:
            space.omada_client_secret = None

    # Boolean verify_ssl
    if is_create or "omada_verify_ssl" in fields_set:
        new_bool = bool(body.omada_verify_ssl) if body.omada_verify_ssl is not None else False
        if bool(space.omada_verify_ssl) != new_bool:
            space.omada_verify_ssl = new_bool
            changed = True

    return changed


@router.get("", response_model=list[SpaceOut])
def list_spaces(
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    spaces = rbac.accessible_spaces(db, me)
    return [_space_out(s) for s in spaces]


@router.post("", response_model=SpaceOut, status_code=201)
def create_space(
    body: SpaceCreate,
    request: Request,
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    rbac.require_admin(me)
    username = me.username
    existing = db.query(Space).filter(Space.port == body.port).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Port {body.port} déjà utilisé")

    _check_omada_url(body)

    now = datetime.now(timezone.utc).isoformat()
    space = Space(
        name=body.name,
        port=body.port,
        enabled=True,
        description=body.description,
        allowed_ip=body.allowed_ip,
        tcp_enabled=body.tcp_enabled,
        lan_mode=body.lan_mode,
        retention_days     = int(body.retention_days) if body.retention_days is not None else 365,
        branding_color     = (body.branding_color or "").strip() or None,
        dhcp_parse_enabled = bool(body.dhcp_parse_enabled) if body.dhcp_parse_enabled is not None else False,
        omada_sync_enabled = bool(body.omada_sync_enabled) if body.omada_sync_enabled is not None else False,
        chain_enabled      = bool(body.chain_enabled) if body.chain_enabled is not None else True,
        created_at=now,
        updated_at=now,
    )
    _apply_omada_fields(space, body, is_create=True)
    _apply_alert_fields(space, body, is_create=True)
    db.add(space)
    db.commit()
    db.refresh(space)

    all_spaces = db.query(Space).all()
    ok, msg = rsyslog_svc.apply_rsyslog_config(all_spaces)
    if not ok:
        db.delete(space)
        db.commit()
        raise HTTPException(
            status_code=400,
            detail=f"Impossible d'ouvrir le port {body.port} : {msg}",
        )

    audit_svc.log_event(db, request, "space_create",
                        username=username,
                        details={"space_id": space.id, "name": space.name,
                                 "port": space.port})
    return _space_out(space)


@router.get("/{space_id}", response_model=SpaceOut)
def get_space(
    space_id: int,
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    space = db.query(Space).filter(Space.id == space_id).first()
    if not space:
        raise HTTPException(status_code=404, detail="Espace introuvable")
    rbac.require_read(db, me, space)
    return _space_out(space)


@router.put("/{space_id}", response_model=SpaceOut)
def update_space(
    space_id: int,
    body: SpaceUpdate,
    request: Request,
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    space = db.query(Space).filter(Space.id == space_id).first()
    if not space:
        raise HTTPException(status_code=404, detail="Espace introuvable")
    rbac.require_admin_space(db, me, space)
    username = me.username

    _check_omada_url(body)

    reload_needed = False

    if body.name is not None:
        space.name = body.name
    if body.description is not None:
        space.description = body.description
    if body.enabled is not None and body.enabled != space.enabled:
        space.enabled = body.enabled
        reload_needed = True
    if "allowed_ip" in body.model_fields_set:
        space.allowed_ip = body.allowed_ip
        reload_needed = True
    if body.tcp_enabled is not None and body.tcp_enabled != getattr(space, "tcp_enabled", False):
        space.tcp_enabled = body.tcp_enabled
        reload_needed = True
    if body.lan_mode is not None and body.lan_mode != getattr(space, "lan_mode", False):
        space.lan_mode = body.lan_mode
        reload_needed = True

    # v2.0.0 — champs conformité (pas de reload rsyslog nécessaire)
    fields_set = body.model_fields_set
    if "retention_days" in fields_set and body.retention_days is not None:
        space.retention_days = int(body.retention_days)
    if "branding_color" in fields_set:
        space.branding_color = (body.branding_color or "").strip() or None
    if "dhcp_parse_enabled" in fields_set and body.dhcp_parse_enabled is not None:
        space.dhcp_parse_enabled = bool(body.dhcp_parse_enabled)
    if "omada_sync_enabled" in fields_set and body.omada_sync_enabled is not None:
        space.omada_sync_enabled = bool(body.omada_sync_enabled)
    if "chain_enabled" in fields_set and body.chain_enabled is not None:
        space.chain_enabled = bool(body.chain_enabled)

    omada_changed = _apply_omada_fields(space, body, is_create=False)
    _apply_alert_fields(space, body, is_create=False)

    space.updated_at = datetime.now(timezone.utc).isoformat()
    db.commit()
    db.refresh(space)

    if omada_changed:
        omada_svc.clear_client_for_space(space.id)

    if reload_needed:
        all_spaces = db.query(Space).all()
        rsyslog_svc.apply_rsyslog_config(all_spaces)

    audit_svc.log_event(db, request, "space_update",
                        username=username,
                        details={"space_id": space.id,
                                 "fields": sorted(body.model_fields_set)})
    return _space_out(space)


@router.delete("/{space_id}")
def delete_space(
    space_id: int,
    request: Request,
    delete_logs: bool = Query(default=False),
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    rbac.require_admin(me)
    username = me.username
    space = db.query(Space).filter(Space.id == space_id).first()
    if not space:
        raise HTTPException(status_code=404, detail="Espace introuvable")

    port = space.port
    name = space.name
    db.delete(space)
    db.commit()
    omada_svc.clear_client_for_space(space_id)

    logs_deleted = False
    if delete_logs:
        import shutil
        from pathlib import Path
        from .. import config
        log_dir = Path(config.LOG_ROOT) / str(port)
        if log_dir.exists():
            shutil.rmtree(str(log_dir))
            logs_deleted = True

    all_spaces = db.query(Space).all()
    rsyslog_svc.apply_rsyslog_config(all_spaces)

    audit_svc.log_event(db, request, "space_delete",
                        username=username,
                        details={"space_id": space_id, "name": name,
                                 "port": port, "logs_deleted": logs_deleted})
    return {"ok": True, "logs_deleted": logs_deleted}


# ── v2.0.0 — branding per space ──────────────────────────────────────────────

_BRANDING_DIR = Path("/opt/syslog-server/data/branding")
_BRANDING_DIR.mkdir(parents=True, exist_ok=True)

_ALLOWED_MIME = {"image/png": "png", "image/jpeg": "jpg", "image/gif": "gif"}
_MAGIC_BYTES = {
    b"\x89PNG\r\n\x1a\n":  "png",
    b"\xff\xd8\xff":        "jpg",
    b"GIF87a":              "gif",
    b"GIF89a":              "gif",
}
_MAX_LOGO_BYTES = 256 * 1024


@router.post("/{space_id}/branding/logo")
async def upload_branding_logo(
    space_id: int,
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    space = db.query(Space).filter(Space.id == space_id).first()
    if not space:
        raise HTTPException(status_code=404, detail="Espace introuvable")
    rbac.require_admin_space(db, me, space)

    content = await file.read(_MAX_LOGO_BYTES + 1)
    if len(content) > _MAX_LOGO_BYTES:
        raise HTTPException(status_code=413, detail=f"Fichier trop volumineux (max {_MAX_LOGO_BYTES//1024} KB)")

    # Vérification par magic bytes (pas seulement l'extension — anti-XSS SVG, etc.)
    ext = None
    for magic, e in _MAGIC_BYTES.items():
        if content.startswith(magic):
            ext = e
            break
    if not ext:
        raise HTTPException(status_code=400, detail="Format non supporté (PNG, JPEG ou GIF uniquement)")

    out_path = _BRANDING_DIR / f"{space_id}.{ext}"
    # Supprimer toute ancienne version avec une autre extension
    for old_ext in ("png", "jpg", "gif"):
        if old_ext != ext:
            (_BRANDING_DIR / f"{space_id}.{old_ext}").unlink(missing_ok=True)
    with open(out_path, "wb") as f:
        f.write(content)
    import os
    try:
        os.chmod(str(out_path), 0o640)
    except OSError:
        pass

    space.branding_logo_path = f"/branding/{space_id}.{ext}"
    space.updated_at = datetime.now(timezone.utc).isoformat()
    db.commit()

    audit_svc.log_event(db, request, "space_branding_logo_upload",
                        username=me.username,
                        details={"space_id": space_id, "size": len(content), "ext": ext})
    return {"ok": True, "path": space.branding_logo_path}


@router.delete("/{space_id}/branding/logo")
def delete_branding_logo(
    space_id: int,
    request: Request,
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    space = db.query(Space).filter(Space.id == space_id).first()
    if not space:
        raise HTTPException(status_code=404, detail="Espace introuvable")
    rbac.require_admin_space(db, me, space)

    for ext in ("png", "jpg", "gif"):
        (_BRANDING_DIR / f"{space_id}.{ext}").unlink(missing_ok=True)
    space.branding_logo_path = None
    space.updated_at = datetime.now(timezone.utc).isoformat()
    db.commit()
    audit_svc.log_event(db, request, "space_branding_logo_delete",
                        username=me.username, details={"space_id": space_id})
    return {"ok": True}


@router.get("/{space_id}/omada/test")
def test_space_omada(
    space_id: int,
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    space = db.query(Space).filter(Space.id == space_id).first()
    if not space:
        raise HTTPException(status_code=404, detail="Espace introuvable")
    rbac.require_admin_space(db, me, space)
    client = omada_svc.get_client_for_space(space)
    if not client:
        raise HTTPException(status_code=400, detail="Intégration Omada non configurée pour cet espace")
    try:
        return client.test_connection()
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Connexion Omada échouée : {e}")

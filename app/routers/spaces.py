from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..models import Space
from ..schemas import SpaceCreate, SpaceOut, SpaceStats, SpaceUpdate
from ..services import rsyslog as rsyslog_svc
from ..services import log_scanner
from ..services import omada as omada_svc

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
        alerts_enabled=bool(getattr(space, "alerts_enabled", False)),
        alert_threshold_hours=int(getattr(space, "alert_threshold_hours", 24) or 24),
        alert_email_to=getattr(space, "alert_email_to", None) or None,
        alert_webhook_url=getattr(space, "alert_webhook_url", None) or None,
        alert_state=getattr(space, "alert_state", "ok") or "ok",
        alert_last_transition_at=getattr(space, "alert_last_transition_at", None),
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
        "omada_base_url":   "omada_base_url",
        "omada_id":         "omada_id",
        "omada_client_id":  "omada_client_id",
    }
    for body_field, col in text_map.items():
        if is_create or body_field in fields_set:
            new_val = getattr(body, body_field)
            new_val = (new_val or "").strip() or None
            if getattr(space, col) != new_val:
                setattr(space, col, new_val)
                changed = True

    # Secret — only overwrite when a non-empty value is provided
    if is_create or "omada_client_secret" in fields_set:
        sec = body.omada_client_secret
        if sec:  # non-empty → overwrite
            if space.omada_client_secret != sec:
                space.omada_client_secret = sec
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
    _: str = Depends(get_current_user),
):
    spaces = db.query(Space).order_by(Space.port).all()
    return [_space_out(s) for s in spaces]


@router.post("", response_model=SpaceOut, status_code=201)
def create_space(
    body: SpaceCreate,
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    existing = db.query(Space).filter(Space.port == body.port).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Port {body.port} déjà utilisé")

    now = datetime.now(timezone.utc).isoformat()
    space = Space(
        name=body.name,
        port=body.port,
        enabled=True,
        description=body.description,
        allowed_ip=body.allowed_ip,
        tcp_enabled=body.tcp_enabled,
        lan_mode=body.lan_mode,
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

    return _space_out(space)


@router.get("/{space_id}", response_model=SpaceOut)
def get_space(
    space_id: int,
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    space = db.query(Space).filter(Space.id == space_id).first()
    if not space:
        raise HTTPException(status_code=404, detail="Espace introuvable")
    return _space_out(space)


@router.put("/{space_id}", response_model=SpaceOut)
def update_space(
    space_id: int,
    body: SpaceUpdate,
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    space = db.query(Space).filter(Space.id == space_id).first()
    if not space:
        raise HTTPException(status_code=404, detail="Espace introuvable")

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

    return _space_out(space)


@router.delete("/{space_id}")
def delete_space(
    space_id: int,
    delete_logs: bool = Query(default=False),
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    space = db.query(Space).filter(Space.id == space_id).first()
    if not space:
        raise HTTPException(status_code=404, detail="Espace introuvable")

    port = space.port
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

    return {"ok": True, "logs_deleted": logs_deleted}


@router.get("/{space_id}/omada/test")
def test_space_omada(
    space_id: int,
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    space = db.query(Space).filter(Space.id == space_id).first()
    if not space:
        raise HTTPException(status_code=404, detail="Espace introuvable")
    client = omada_svc.get_client_for_space(space)
    if not client:
        raise HTTPException(status_code=400, detail="Intégration Omada non configurée pour cet espace")
    try:
        return client.test_connection()
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Connexion Omada échouée : {e}")

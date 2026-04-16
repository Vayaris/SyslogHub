import os
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..auth import get_current_user, hash_password, verify_password
from ..database import get_db
from ..models import Setting, Space
from ..schemas import SettingsOut, SettingsUpdate, SystemStatus, OmadaSettings
from ..services.log_scanner import total_log_size, volume_by_day
from ..services import omada as omada_svc
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
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    if body.retention_days is not None:
        _set_setting(db, "retention_days", str(body.retention_days))

    if body.admin_username is not None:
        _set_setting(db, "admin_username", body.admin_username)

    if body.new_password is not None:
        if not body.current_password:
            raise HTTPException(
                status_code=400, detail="Mot de passe actuel requis"
            )
        current_hash = _get_setting(db, "admin_password_hash") or ""
        if not verify_password(body.current_password, current_hash):
            raise HTTPException(
                status_code=400, detail="Mot de passe actuel incorrect"
            )
        _set_setting(db, "admin_password_hash", hash_password(body.new_password))

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


# ── Omada integration ──────────────────────────────────────────────────────────

@router.get("/omada", response_model=OmadaSettings)
def get_omada_settings(
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    base_url = _get_setting(db, "omada_base_url") or ""
    return OmadaSettings(
        base_url=base_url,
        omada_id=_get_setting(db, "omada_id") or "",
        client_id=_get_setting(db, "omada_client_id") or "",
        site_name=_get_setting(db, "omada_site") or "Default",
        verify_ssl=(_get_setting(db, "omada_verify_ssl") or "false") == "true",
        configured=bool(base_url),
    )


@router.put("/omada")
def update_omada_settings(
    body: OmadaSettings,
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user),
):
    _set_setting(db, "omada_base_url", body.base_url or "")
    _set_setting(db, "omada_id", body.omada_id or "")
    _set_setting(db, "omada_client_id", body.client_id or "")
    if body.client_secret:
        _set_setting(db, "omada_client_secret", body.client_secret)
    _set_setting(db, "omada_site", body.site_name or "Default")
    _set_setting(db, "omada_verify_ssl", "true" if body.verify_ssl else "false")

    # Rebuild the singleton
    secret = body.client_secret or _get_setting(db, "omada_client_secret") or ""
    if body.base_url and body.omada_id and body.client_id and secret:
        omada_svc.build_client(
            base_url=body.base_url,
            omada_id=body.omada_id,
            client_id=body.client_id,
            client_secret=secret,
            site_name=body.site_name or "Default",
            verify_ssl=body.verify_ssl,
        )
    else:
        omada_svc.clear_client()

    return {"ok": True}


@router.get("/omada/test")
def test_omada_connection(
    _: str = Depends(get_current_user),
):
    client = omada_svc.get_client()
    if not client:
        raise HTTPException(status_code=400, detail="Intégration Omada non configurée")
    try:
        return client.test_connection()
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Connexion Omada échouée : {e}")

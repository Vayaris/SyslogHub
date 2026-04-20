import os
import secrets
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..auth import get_current_user, hash_password, verify_password
from ..database import get_db
from ..models import Setting, Space
from ..schemas import SettingsOut, SettingsUpdate, SystemStatus
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
        # Rotate session secret so all existing sessions (this browser + others) are invalidated
        _set_setting(db, "session_secret", secrets.token_hex(32))

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

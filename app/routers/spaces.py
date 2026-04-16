from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..models import Space
from ..schemas import SpaceCreate, SpaceOut, SpaceStats, SpaceUpdate
from ..services import rsyslog as rsyslog_svc
from ..services import log_scanner

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
        created_at=space.created_at,
        updated_at=space.updated_at,
        stats=stats,
    )


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
        created_at=now,
        updated_at=now,
    )
    db.add(space)
    db.commit()
    db.refresh(space)

    all_spaces = db.query(Space).all()
    ok, msg = rsyslog_svc.apply_rsyslog_config(all_spaces)
    if not ok:
        # Rollback: rsyslog couldn't open the port
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

    space.updated_at = datetime.now(timezone.utc).isoformat()
    db.commit()
    db.refresh(space)

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

"""v2.0.0 — API pour le tableau de bord "Chaîne d'intégrité"."""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..auth import get_current_user_obj
from ..database import get_db
from ..models import LogChain, Space, User
from ..services import audit as audit_svc
from ..services import chain as chain_svc
from ..services import rbac
from ..services import tsa as tsa_svc

router = APIRouter(prefix="/api/compliance/chain", tags=["compliance"])


@router.get("")
def list_chain(
    space_id: int | None = None,
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    """Retourne toutes les entrées log_chain visibles par l'utilisateur.
    Un admin voit tout ; un operator voit uniquement les chains des spaces
    auxquels il a accès."""
    if space_id is not None:
        space = db.query(Space).filter(Space.id == space_id).first()
        if not space:
            raise HTTPException(status_code=404, detail="Espace introuvable")
        rbac.require_read(db, me, space)
        spaces = [space]
    else:
        spaces = rbac.accessible_spaces(db, me)

    out = []
    for sp in spaces:
        rows = (
            db.query(LogChain)
              .filter(LogChain.space_id == sp.id)
              .order_by(LogChain.day.desc())
              .limit(400)
              .all()
        )
        gaps = chain_svc.detect_gaps(db, sp, days_back=30)
        out.append({
            "space_id":   sp.id,
            "space_name": sp.name,
            "port":       sp.port,
            "chain_enabled": bool(sp.chain_enabled),
            "gaps":       gaps,
            "entries": [
                {
                    "day":             r.day,
                    "manifest_sha256": r.manifest_sha256,
                    "prev_sha256":     r.prev_sha256,
                    "files_count":     r.files_count,
                    "total_bytes":     r.total_bytes,
                    "tsa_status":      r.tsa_status,
                    "tsa_url":         r.tsa_url,
                    "tsa_gen_time":    r.tsa_gen_time,
                    "tsa_serial":      r.tsa_serial,
                    "tsa_attempts":    r.tsa_attempts,
                    "tsa_last_error":  r.tsa_last_error,
                    "created_at":      r.created_at,
                } for r in rows
            ],
        })
    return {"spaces": out}


@router.post("/{space_id}/{day}/retimestamp")
def retimestamp(
    space_id: int,
    day: str,
    request: Request,
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    """Rejoue l'horodatage TSA pour une entrée en échec."""
    space = db.query(Space).filter(Space.id == space_id).first()
    if not space:
        raise HTTPException(status_code=404, detail="Espace introuvable")
    rbac.require_admin_space(db, me, space)

    row = (
        db.query(LogChain)
          .filter(LogChain.space_id == space_id, LogChain.day == day)
          .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Entrée de chaîne introuvable")
    if row.tsa_status == "ok":
        return {"ok": True, "already": True}

    # Reset the attempt counter so the retry isn't blocked by retry_max
    row.tsa_attempts = 0
    row.tsa_status = "pending"
    db.commit()
    ok = tsa_svc.timestamp_manifest(db, row)
    audit_svc.log_event(db, request, "tsa_retimestamp",
                        username=me.username,
                        details={"space_id": space_id, "day": day, "ok": ok})
    return {"ok": ok, "status": row.tsa_status, "error": row.tsa_last_error}


@router.get("/tsa-config")
def get_tsa_config(
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    rbac.require_admin(me)
    return tsa_svc.get_config()


@router.put("/tsa-config")
def update_tsa_config(
    body: dict,
    request: Request,
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    rbac.require_admin(me)
    from ..models import Setting

    def _set(key: str, value: str):
        row = db.query(Setting).filter(Setting.key == key).first()
        if row:
            row.value = value
        else:
            db.add(Setting(key=key, value=value))

    changed = []
    if "enabled" in body:
        _set("tsa_enabled", "true" if body["enabled"] else "false")
        changed.append("enabled")
    if "url" in body and body["url"]:
        _set("tsa_url", str(body["url"]).strip())
        changed.append("url")
    if "retry_max" in body and body["retry_max"] is not None:
        _set("tsa_retry_max", str(int(body["retry_max"])))
        changed.append("retry_max")
    db.commit()
    audit_svc.log_event(db, request, "tsa_config_update",
                        username=me.username, details={"fields": changed})
    return {"ok": True, "config": tsa_svc.get_config()}


@router.post("/tsa-config/test")
def test_tsa(
    request: Request,
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    """Bouton "preuve de vie" : horodate un hash factice pour valider que la
    TSA répond. Ne modifie pas la chaîne."""
    rbac.require_admin(me)
    test_data = f"sysloghub-tsa-test-{datetime_iso()}".encode()
    tsr, err, info = tsa_svc.timestamp_data(test_data)
    audit_svc.log_event(db, request, "tsa_test",
                        username=me.username,
                        details={"ok": bool(tsr), "error": err})
    if tsr:
        return {"ok": True, "info": info, "tsr_size": len(tsr)}
    return {"ok": False, "error": err}


def datetime_iso():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()

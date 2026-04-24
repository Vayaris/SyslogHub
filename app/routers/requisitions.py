"""v2.0.0 — workflow réquisition judiciaire."""
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from typing import Optional

from ..auth import get_current_user_obj
from ..database import get_db
from ..models import LegalHold, Requisition, Space, User
from ..services import audit as audit_svc
from ..services import rbac
from ..services import requisition_bundle as bundle_svc

router = APIRouter(prefix="/api/compliance/requisitions", tags=["compliance"])


# ── schemas ──────────────────────────────────────────────────────────────────

class RequisitionCreate(BaseModel):
    number: str = Field(..., min_length=1, max_length=200)
    opj_name: str = Field(..., min_length=1, max_length=200)
    opj_service: Optional[str] = Field(None, max_length=200)
    opj_email: Optional[str] = Field(None, max_length=254)
    justification: str = Field(..., min_length=3)
    space_id: Optional[int] = None       # None = tous les spaces
    time_from: str          # ISO 8601 UTC
    time_to: str
    notes: Optional[str] = None


class RequisitionPreviewRequest(BaseModel):
    space_id: Optional[int] = None
    time_from: str
    time_to: str


class RequisitionUpdate(BaseModel):
    notes: Optional[str] = None


# ── helpers ──────────────────────────────────────────────────────────────────

def _req_out(r: Requisition, db: Session) -> dict:
    sp = None
    if r.space_id:
        sp = db.query(Space).filter(Space.id == r.space_id).first()
    creator = db.query(User).filter(User.id == r.created_by).first()
    return {
        "id":             r.id,
        "number":         r.number,
        "opj_name":       r.opj_name,
        "opj_service":    r.opj_service,
        "opj_email":      r.opj_email,
        "justification":  r.justification,
        "space_id":       r.space_id,
        "space_name":     sp.name if sp else None,
        "time_from":      r.time_from,
        "time_to":        r.time_to,
        "status":         r.status,
        "created_at":     r.created_at,
        "created_by_id":  r.created_by,
        "created_by":     creator.username if creator else None,
        "exported_at":    r.exported_at,
        "bundle_path":    r.bundle_path,
        "bundle_sha256":  r.bundle_sha256,
        "bundle_size_bytes": r.bundle_size_bytes,
        "closed_at":      r.closed_at,
        "notes":          r.notes,
    }


def _parse_time(s: str) -> str:
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Format datetime invalide : {s}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _require_access(db, me: User, space_id: int | None):
    """Admin ou owner/operator sur le space concerné."""
    if rbac.is_admin(me):
        return
    if space_id is None:
        # Réquisition "tous spaces" = admin only
        raise HTTPException(status_code=403, detail="Réquisition globale réservée aux administrateurs")
    sp = db.query(Space).filter(Space.id == space_id).first()
    if not sp:
        raise HTTPException(status_code=404, detail="Espace introuvable")
    if not rbac.can_write_space(db, me, sp):
        raise HTTPException(status_code=403, detail="Accès refusé à cet espace")


# ── endpoints ────────────────────────────────────────────────────────────────

@router.get("")
def list_requisitions(
    status: str = Query(default=""),
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    q = db.query(Requisition)
    if status:
        q = q.filter(Requisition.status == status)
    if not rbac.is_admin(me):
        # Restreindre aux spaces accessibles
        accessible_ids = {s.id for s in rbac.accessible_spaces(db, me)}
        q = q.filter(Requisition.space_id.in_(accessible_ids))
    rows = q.order_by(Requisition.created_at.desc()).all()
    return {"items": [_req_out(r, db) for r in rows]}


@router.post("/preview")
def preview(
    body: RequisitionPreviewRequest,
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    _require_access(db, me, body.space_id)
    t_from = datetime.fromisoformat(body.time_from.replace("Z", "+00:00"))
    t_to   = datetime.fromisoformat(body.time_to.replace("Z", "+00:00"))
    return bundle_svc.preview(db, body.space_id, t_from, t_to)


@router.post("", status_code=201)
def create_requisition(
    body: RequisitionCreate,
    request: Request,
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    _require_access(db, me, body.space_id)
    time_from = _parse_time(body.time_from)
    time_to   = _parse_time(body.time_to)
    if time_from >= time_to:
        raise HTTPException(status_code=400, detail="time_from doit précéder time_to")

    now = datetime.now(timezone.utc).isoformat()
    req = Requisition(
        number=body.number.strip(),
        opj_name=body.opj_name.strip(),
        opj_service=(body.opj_service or "").strip() or None,
        opj_email=(body.opj_email or "").strip() or None,
        justification=body.justification.strip(),
        space_id=body.space_id,
        time_from=time_from, time_to=time_to,
        status="draft",
        created_at=now, created_by=me.id,
        notes=(body.notes or "").strip() or None,
    )
    db.add(req)
    db.commit()
    db.refresh(req)

    audit_svc.log_event(db, request, "requisition_create",
                        username=me.username,
                        details={"id": req.id, "number": req.number,
                                 "opj": req.opj_name, "space_id": req.space_id,
                                 "time_from": req.time_from, "time_to": req.time_to})
    return _req_out(req, db)


@router.get("/{req_id}")
def get_requisition(
    req_id: int,
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    r = db.query(Requisition).filter(Requisition.id == req_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Réquisition introuvable")
    _require_access(db, me, r.space_id)
    return _req_out(r, db)


@router.post("/{req_id}/export")
def export_requisition(
    req_id: int,
    request: Request,
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    r = db.query(Requisition).filter(Requisition.id == req_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Réquisition introuvable")
    _require_access(db, me, r.space_id)
    if r.status == "exported":
        raise HTTPException(status_code=400, detail="Déjà exportée — utiliser /download")

    # IMPORTANT : activer le legal hold AVANT la génération, pour éviter une
    # purge concurrente sur les fichiers en cours de zipping.
    hold = LegalHold(
        requisition_id=r.id,
        space_id=r.space_id,          # None = tous spaces
        time_from=r.time_from,
        time_to=r.time_to,
        active=True,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    db.add(hold)
    db.commit()

    info = bundle_svc.build_bundle(db, r, me)

    audit_svc.log_event(db, request, "requisition_export",
                        username=me.username,
                        details={"id": r.id, "number": r.number,
                                 "bundle_sha256": info["bundle_sha256"],
                                 "bundle_size_bytes": info["bundle_size_bytes"],
                                 "files_count": info["files_count"]})
    return {"ok": True, **info}


@router.get("/{req_id}/download")
def download_bundle(
    req_id: int,
    request: Request,
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    r = db.query(Requisition).filter(Requisition.id == req_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Réquisition introuvable")
    _require_access(db, me, r.space_id)
    if not r.bundle_path or not Path(r.bundle_path).exists():
        raise HTTPException(status_code=404, detail="Bundle non généré — utiliser POST /export d'abord")

    audit_svc.log_event(db, request, "requisition_download",
                        username=me.username,
                        details={"id": r.id, "number": r.number,
                                 "bundle_sha256": r.bundle_sha256})
    fname = Path(r.bundle_path).name
    return FileResponse(
        r.bundle_path, media_type="application/zip", filename=fname,
        headers={"X-Bundle-SHA256": r.bundle_sha256 or ""},
    )


@router.post("/{req_id}/close")
def close_requisition(
    req_id: int,
    request: Request,
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    r = db.query(Requisition).filter(Requisition.id == req_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Réquisition introuvable")
    _require_access(db, me, r.space_id)
    if r.status == "closed":
        return {"ok": True, "already": True}
    now = datetime.now(timezone.utc).isoformat()
    r.status = "closed"
    r.closed_at = now
    r.closed_by = me.id

    # Désactiver les legal_holds associés
    n = (db.query(LegalHold)
           .filter(LegalHold.requisition_id == r.id,
                   LegalHold.active == True)       # noqa: E712
           .update({"active": False}, synchronize_session=False))
    db.commit()
    audit_svc.log_event(db, request, "requisition_close",
                        username=me.username,
                        details={"id": r.id, "number": r.number,
                                 "holds_deactivated": int(n)})
    return {"ok": True, "holds_deactivated": int(n)}


@router.delete("/{req_id}")
def delete_requisition(
    req_id: int,
    request: Request,
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    r = db.query(Requisition).filter(Requisition.id == req_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Réquisition introuvable")
    _require_access(db, me, r.space_id)
    if r.status != "closed":
        raise HTTPException(status_code=400, detail="Seule une réquisition clôturée peut être supprimée")
    # Remove bundle file (on disk)
    if r.bundle_path and Path(r.bundle_path).exists():
        try:
            Path(r.bundle_path).unlink()
        except OSError:
            pass
    num = r.number
    db.delete(r)
    db.commit()
    audit_svc.log_event(db, request, "requisition_delete",
                        username=me.username,
                        details={"id": req_id, "number": num})
    return {"ok": True}

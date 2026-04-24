"""v2.0.0 — endpoints de génération des documents RGPD."""
import io
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response, PlainTextResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional

from ..auth import get_current_user_obj
from ..database import get_db
from ..models import LogChain, Requisition, Setting, Space, User
from ..services import audit as audit_svc
from ..services import pdf_templates
from ..services import rbac

router = APIRouter(prefix="/api/compliance/docs", tags=["compliance"])


# ── Organization settings ────────────────────────────────────────────────────

_ORG_KEYS = [
    "organization_name", "organization_address", "organization_siren",
    "dpo_name", "dpo_email", "privacy_contact_email",
]


class OrgConfig(BaseModel):
    organization_name: Optional[str] = None
    organization_address: Optional[str] = None
    organization_siren: Optional[str] = None
    dpo_name: Optional[str] = None
    dpo_email: Optional[str] = None
    privacy_contact_email: Optional[str] = None


def _get_org(db: Session) -> dict:
    rows = {r.key: r.value for r in db.query(Setting).filter(Setting.key.in_(_ORG_KEYS)).all()}
    return {
        "name":    rows.get("organization_name"),
        "address": rows.get("organization_address"),
        "siren":   rows.get("organization_siren"),
        "dpo_name":   rows.get("dpo_name"),
        "dpo_email":  rows.get("dpo_email"),
        "privacy_contact_email": rows.get("privacy_contact_email"),
    }


def _set_setting(db: Session, key: str, value: str | None):
    row = db.query(Setting).filter(Setting.key == key).first()
    val = (value or "").strip()
    if row:
        if val:
            row.value = val
        else:
            db.delete(row)
    elif val:
        db.add(Setting(key=key, value=val))


@router.get("/organization")
def get_organization(
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    rbac.require_admin(me)
    return _get_org(db)


@router.put("/organization")
def update_organization(
    body: OrgConfig,
    request: Request,
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    rbac.require_admin(me)
    fields = body.model_fields_set
    for key_json, key_setting in [
        ("organization_name", "organization_name"),
        ("organization_address", "organization_address"),
        ("organization_siren", "organization_siren"),
        ("dpo_name", "dpo_name"),
        ("dpo_email", "dpo_email"),
        ("privacy_contact_email", "privacy_contact_email"),
    ]:
        if key_json in fields:
            _set_setting(db, key_setting, getattr(body, key_json))
    db.commit()
    audit_svc.log_event(db, request, "org_settings_update",
                        username=me.username, details={"fields": sorted(fields)})
    return _get_org(db)


# ── PDF endpoints ────────────────────────────────────────────────────────────

@router.get("/register.pdf")
def register_pdf(
    request: Request,
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    rbac.require_admin(me)
    spaces = db.query(Space).order_by(Space.port).all()
    sp_out = [
        {"name": sp.name, "port": sp.port, "retention_days": int(sp.retention_days or 365)}
        for sp in spaces
    ]
    buf = io.BytesIO()
    pdf_templates.render_gdpr_register(buf, organization=_get_org(db), spaces=sp_out)
    audit_svc.log_event(db, request, "compliance_register_generated", username=me.username)
    return Response(
        content=buf.getvalue(),
        media_type="application/pdf",
        headers={"Content-Disposition": 'inline; filename="registre-rgpd.pdf"'},
    )


@router.get("/notice/{space_id}.pdf")
def notice_pdf(
    space_id: int,
    request: Request,
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    sp = db.query(Space).filter(Space.id == space_id).first()
    if not sp:
        raise HTTPException(status_code=404, detail="Espace introuvable")
    rbac.require_read(db, me, sp)
    buf = io.BytesIO()
    pdf_templates.render_portal_notice(
        buf,
        organization=_get_org(db),
        space={"name": sp.name, "retention_days": int(sp.retention_days or 365)},
    )
    audit_svc.log_event(db, request, "compliance_notice_generated",
                        username=me.username, details={"space_id": space_id})
    return Response(
        content=buf.getvalue(),
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="notice-{sp.port}.pdf"'},
    )


@router.get("/notice/{space_id}.md")
def notice_md(
    space_id: int,
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    sp = db.query(Space).filter(Space.id == space_id).first()
    if not sp:
        raise HTTPException(status_code=404, detail="Espace introuvable")
    rbac.require_read(db, me, sp)
    md = pdf_templates.render_portal_notice_markdown(
        _get_org(db),
        {"name": sp.name, "retention_days": int(sp.retention_days or 365)},
    )
    return PlainTextResponse(md, media_type="text/markdown; charset=utf-8")


@router.get("/annual-report.pdf")
def annual_report_pdf(
    request: Request,
    year: int = None,
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    rbac.require_admin(me)
    y = int(year or datetime.now(timezone.utc).year)

    spaces = db.query(Space).all()
    per_space = []
    totals = {"requisitions_total": 0, "tsa_success_rate_pct": 0.0}
    tsa_ok_global = 0
    tsa_fail_global = 0

    day_lo = f"{y}-01-01"
    day_hi = f"{y}-12-31"
    ts_lo  = f"{y}-01-01T00:00:00+00:00"
    ts_hi  = f"{y}-12-31T23:59:59+00:00"

    for sp in spaces:
        entries = (db.query(LogChain)
                     .filter(LogChain.space_id == sp.id,
                             LogChain.day >= day_lo, LogChain.day <= day_hi)
                     .all())
        ok    = sum(1 for e in entries if e.tsa_status == "ok")
        bf    = sum(1 for e in entries if e.tsa_status == "skipped_backfill")
        fail  = sum(1 for e in entries if e.tsa_status == "failed")
        total_vol = sum(e.total_bytes or 0 for e in entries)
        # Gaps : jours sans manifest mais avec logs — on se fie au nombre
        # d'entrées vs les 365 jours de l'année.
        active_days = len(entries)
        # Uptime approx : ratio jours-avec-manifest sur 365 (ou jours écoulés cette année si année courante)
        from datetime import date
        ref_day = date(y, 12, 31)
        today = datetime.now(timezone.utc).date()
        if ref_day > today:
            ref_day = today
        elapsed_days = max(1, (ref_day - date(y, 1, 1)).days + 1)
        uptime = min(100.0, active_days * 100.0 / elapsed_days)

        req_count = (db.query(Requisition)
                       .filter(Requisition.space_id == sp.id,
                               Requisition.created_at >= ts_lo,
                               Requisition.created_at <= ts_hi)
                       .count())
        totals["requisitions_total"] += req_count
        tsa_ok_global += ok
        tsa_fail_global += fail

        per_space.append({
            "name": sp.name,
            "uptime_pct": uptime,
            "gaps": max(0, elapsed_days - active_days),
            "requisitions_count": req_count,
            "tsa_ok": ok + bf,       # backfill = retroactif, on le compte comme "ok" pour la stat
            "tsa_failed": fail,
            "volume_bytes": total_vol,
        })

    # Also count "tous spaces" requisitions
    totals["requisitions_total"] += (
        db.query(Requisition)
          .filter(Requisition.space_id.is_(None),
                  Requisition.created_at >= ts_lo,
                  Requisition.created_at <= ts_hi)
          .count()
    )
    total_tsa = tsa_ok_global + tsa_fail_global
    totals["tsa_success_rate_pct"] = (tsa_ok_global / total_tsa * 100.0) if total_tsa else 100.0

    buf = io.BytesIO()
    pdf_templates.render_annual_report(
        buf,
        organization=_get_org(db),
        year=y,
        per_space=per_space,
        totals=totals,
    )
    audit_svc.log_event(db, request, "compliance_annual_generated",
                        username=me.username, details={"year": y})
    return Response(
        content=buf.getvalue(),
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="rapport-conformite-{y}.pdf"'},
    )

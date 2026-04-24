"""v2.0.0 — gestion multi-utilisateurs + attribution rôles par space.

Toutes les routes sont réservées aux admins globaux (`role_global='admin'`).
"""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..auth import get_current_user_obj, hash_password
from ..database import get_db
from ..models import Space, SpaceRole, User
from ..schemas import (
    SpaceRoleOut, SpaceRoleUpdate,
    UserCreate, UserOut, UserUpdate,
)
from ..services import audit as audit_svc
from ..services import rbac

router = APIRouter(prefix="/api/users", tags=["users"])


def _now():
    return datetime.now(timezone.utc).isoformat()


def _user_out(u: User) -> UserOut:
    return UserOut(
        id=u.id,
        username=u.username,
        email=u.email,
        role_global=u.role_global,
        disabled=bool(u.disabled),
        has_password=bool(u.password_hash),
        totp_enabled=bool(u.totp_enabled),
        oidc_subject=u.oidc_subject,
        created_at=u.created_at,
        last_login_at=u.last_login_at,
    )


def _require_admin(me: User):
    rbac.require_admin(me)


@router.get("", response_model=list[UserOut])
def list_users(
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    _require_admin(me)
    rows = db.query(User).order_by(User.username).all()
    return [_user_out(u) for u in rows]


@router.post("", response_model=UserOut, status_code=201)
def create_user(
    body: UserCreate,
    request: Request,
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    _require_admin(me)
    existing = db.query(User).filter(User.username == body.username).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"L'utilisateur '{body.username}' existe déjà")
    if body.email:
        if db.query(User).filter(User.email == body.email).first():
            raise HTTPException(status_code=409, detail="Cet email est déjà attribué")

    u = User(
        username      = body.username.strip(),
        email         = (body.email or "").strip() or None,
        password_hash = hash_password(body.password) if body.password else None,
        role_global   = body.role_global,
        created_at    = _now(),
    )
    db.add(u)
    db.commit()
    db.refresh(u)

    audit_svc.log_event(db, request, "user_create",
                        username=me.username,
                        details={"user_id": u.id, "username": u.username,
                                 "role_global": u.role_global})
    return _user_out(u)


@router.put("/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    body: UserUpdate,
    request: Request,
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    _require_admin(me)
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")

    changed: list[str] = []
    fields = body.model_fields_set

    if "username" in fields and body.username and body.username.strip() != u.username:
        clash = db.query(User).filter(User.username == body.username.strip()).first()
        if clash and clash.id != u.id:
            raise HTTPException(status_code=409, detail="Nom d'utilisateur déjà pris")
        u.username = body.username.strip()
        changed.append("username")

    if "email" in fields:
        new_email = (body.email or "").strip() or None
        if new_email and new_email != u.email:
            clash = db.query(User).filter(User.email == new_email).first()
            if clash and clash.id != u.id:
                raise HTTPException(status_code=409, detail="Email déjà attribué")
        u.email = new_email
        changed.append("email")

    if "role_global" in fields and body.role_global:
        # Ne pas laisser un admin se rétrograder s'il est le dernier admin actif.
        if u.id == me.id and body.role_global != "admin":
            admins_active = (
                db.query(User)
                  .filter(User.role_global == "admin", User.disabled == False,  # noqa: E712
                          User.id != u.id)
                  .count()
            )
            if admins_active == 0:
                raise HTTPException(
                    status_code=400,
                    detail="Impossible de rétrograder le dernier administrateur",
                )
        u.role_global = body.role_global
        changed.append("role_global")

    if "disabled" in fields and body.disabled is not None:
        if body.disabled and u.id == me.id:
            raise HTTPException(status_code=400, detail="Impossible de désactiver votre propre compte")
        if body.disabled and u.role_global == "admin":
            admins_active = (
                db.query(User)
                  .filter(User.role_global == "admin", User.disabled == False,  # noqa: E712
                          User.id != u.id)
                  .count()
            )
            if admins_active == 0:
                raise HTTPException(
                    status_code=400,
                    detail="Impossible de désactiver le dernier administrateur",
                )
        u.disabled = bool(body.disabled)
        changed.append("disabled")

    if "new_password" in fields and body.new_password:
        u.password_hash = hash_password(body.new_password)
        changed.append("new_password")

    db.commit()
    db.refresh(u)

    audit_svc.log_event(db, request, "user_update",
                        username=me.username,
                        details={"user_id": u.id, "fields": changed})
    return _user_out(u)


@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    _require_admin(me)
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    if u.id == me.id:
        raise HTTPException(status_code=400, detail="Impossible de supprimer votre propre compte")
    if u.role_global == "admin":
        admins_active = (
            db.query(User)
              .filter(User.role_global == "admin", User.disabled == False,  # noqa: E712
                      User.id != u.id)
              .count()
        )
        if admins_active == 0:
            raise HTTPException(
                status_code=400,
                detail="Impossible de supprimer le dernier administrateur",
            )
    username = u.username
    db.delete(u)
    db.commit()
    audit_svc.log_event(db, request, "user_delete",
                        username=me.username,
                        details={"user_id": user_id, "username": username})
    return {"ok": True}


# ── Attribution de rôles par space ──────────────────────────────────────────

@router.get("/{user_id}/spaces", response_model=list[SpaceRoleOut])
def list_user_space_roles(
    user_id: int,
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    _require_admin(me)
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    rows = (
        db.query(SpaceRole, Space)
          .join(Space, SpaceRole.space_id == Space.id)
          .filter(SpaceRole.user_id == user_id)
          .order_by(Space.port)
          .all()
    )
    return [
        SpaceRoleOut(
            id=sr.id, user_id=sr.user_id, space_id=sr.space_id,
            space_name=sp.name, role=sr.role, granted_at=sr.granted_at,
        )
        for (sr, sp) in rows
    ]


@router.put("/{user_id}/spaces/{space_id}", response_model=SpaceRoleOut)
def upsert_user_space_role(
    user_id: int,
    space_id: int,
    body: SpaceRoleUpdate,
    request: Request,
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    _require_admin(me)
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    sp = db.query(Space).filter(Space.id == space_id).first()
    if not sp:
        raise HTTPException(status_code=404, detail="Espace introuvable")

    existing = (
        db.query(SpaceRole)
          .filter(SpaceRole.user_id == user_id, SpaceRole.space_id == space_id)
          .first()
    )
    if existing:
        existing.role = body.role
        db.commit()
        sr = existing
    else:
        sr = SpaceRole(
            user_id=user_id, space_id=space_id, role=body.role,
            granted_at=_now(), granted_by=me.id if me.id else None,
        )
        db.add(sr)
        db.commit()
        db.refresh(sr)

    audit_svc.log_event(db, request, "user_space_role_set",
                        username=me.username,
                        details={"user_id": user_id, "space_id": space_id, "role": body.role})
    return SpaceRoleOut(
        id=sr.id, user_id=sr.user_id, space_id=sr.space_id,
        space_name=sp.name, role=sr.role, granted_at=sr.granted_at,
    )


@router.delete("/{user_id}/spaces/{space_id}")
def remove_user_space_role(
    user_id: int,
    space_id: int,
    request: Request,
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    _require_admin(me)
    sr = (
        db.query(SpaceRole)
          .filter(SpaceRole.user_id == user_id, SpaceRole.space_id == space_id)
          .first()
    )
    if not sr:
        raise HTTPException(status_code=404, detail="Rôle introuvable")
    db.delete(sr)
    db.commit()
    audit_svc.log_event(db, request, "user_space_role_remove",
                        username=me.username,
                        details={"user_id": user_id, "space_id": space_id})
    return {"ok": True}

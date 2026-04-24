"""v2.0.0 — RBAC helpers.

Un `User.role_global` in {admin, operator} :
  - `admin` : tout accès (gestion users, settings globaux, tous les spaces).
  - `operator` : doit avoir un `SpaceRole` explicite pour chaque space auquel
    il accède. Sans rôle, aucun accès.

Les rôles par space (`SpaceRole.role`) :
  - `owner` : configure le space (Omada, alerts, retention, branding, delete).
  - `operator` : peut créer des réquisitions, exporter, voir les logs, mais
    pas toucher la config du space.
  - `readonly` : consultation logs uniquement.

Toutes les routes qui manipulent un space DOIVENT passer par ces helpers.
"""
from __future__ import annotations

from typing import Optional
from sqlalchemy.orm import Session

from ..models import Space, SpaceRole, User


def is_admin(user: Optional[User]) -> bool:
    return bool(user and user.role_global == "admin" and not user.disabled)


def _role_for(db: Session, user: User, space: Space) -> Optional[str]:
    row = (
        db.query(SpaceRole)
          .filter(SpaceRole.user_id == user.id, SpaceRole.space_id == space.id)
          .first()
    )
    return row.role if row else None


def can_read_space(db: Session, user: Optional[User], space: Space) -> bool:
    if not user or user.disabled:
        return False
    if user.role_global == "admin":
        return True
    return _role_for(db, user, space) in ("owner", "operator", "readonly")


def can_write_space(db: Session, user: Optional[User], space: Space) -> bool:
    """Créer/éditer réquisition, upload branding, trigger live tail, etc."""
    if not user or user.disabled:
        return False
    if user.role_global == "admin":
        return True
    return _role_for(db, user, space) in ("owner", "operator")


def can_admin_space(db: Session, user: Optional[User], space: Space) -> bool:
    """Config space (Omada, alerts, retention, delete)."""
    if not user or user.disabled:
        return False
    if user.role_global == "admin":
        return True
    return _role_for(db, user, space) == "owner"


def can_manage_users(user: Optional[User]) -> bool:
    return is_admin(user)


def can_manage_settings(user: Optional[User]) -> bool:
    """TSA config, organization info, OIDC, alerts globaux → admin only."""
    return is_admin(user)


def accessible_spaces(db: Session, user: User) -> list[Space]:
    """Liste des spaces visibles par l'utilisateur."""
    if not user or user.disabled:
        return []
    q = db.query(Space)
    if user.role_global == "admin":
        return q.order_by(Space.port).all()
    # operator : join via space_roles
    space_ids = [
        row.space_id for row in
        db.query(SpaceRole).filter(SpaceRole.user_id == user.id).all()
    ]
    if not space_ids:
        return []
    return q.filter(Space.id.in_(space_ids)).order_by(Space.port).all()


def require_read(db: Session, user: Optional[User], space: Space):
    from fastapi import HTTPException
    if not can_read_space(db, user, space):
        raise HTTPException(status_code=403, detail="Accès refusé à cet espace")


def require_write(db: Session, user: Optional[User], space: Space):
    from fastapi import HTTPException
    if not can_write_space(db, user, space):
        raise HTTPException(status_code=403, detail="Accès refusé à cet espace")


def require_admin_space(db: Session, user: Optional[User], space: Space):
    from fastapi import HTTPException
    if not can_admin_space(db, user, space):
        raise HTTPException(status_code=403, detail="Réservé au propriétaire du space")


def require_admin(user: Optional[User]):
    from fastapi import HTTPException
    if not is_admin(user):
        raise HTTPException(status_code=403, detail="Action réservée aux administrateurs")

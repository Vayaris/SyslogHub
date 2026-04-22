"""Internal audit log helper.

Usage: call `log_event(db, request, action, username=..., details=...)` at the
end of any write/sensitive endpoint. The helper never raises — if persistence
fails, a warning is logged and the caller continues.
"""
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import Request
from sqlalchemy.orm import Session

from ..models import AuditLog

log = logging.getLogger("syslog-server")


def _client_ip(request: Optional[Request]) -> Optional[str]:
    if request is None:
        return None
    xri = request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for")
    if xri:
        return xri.split(",")[0].strip()
    return request.client.host if request.client else None


def _user_agent(request: Optional[Request]) -> Optional[str]:
    if request is None:
        return None
    ua = request.headers.get("user-agent") or ""
    return ua[:255] if ua else None


def log_event(
    db: Session,
    request: Optional[Request],
    action: str,
    username: Optional[str] = None,
    details: Optional[dict[str, Any]] = None,
) -> None:
    try:
        entry = AuditLog(
            ts=datetime.now(timezone.utc).isoformat(),
            username=username,
            action=action,
            ip=_client_ip(request),
            user_agent=_user_agent(request),
            details=json.dumps(details, default=str) if details else None,
        )
        db.add(entry)
        db.commit()
    except Exception as e:
        db.rollback()
        log.warning(f"audit.log_event({action}) failed: {e}")


def purge_old(db: Session, keep_days: int = 180) -> int:
    from sqlalchemy import text
    from datetime import timedelta

    cutoff = (datetime.now(timezone.utc) - timedelta(days=keep_days)).isoformat()
    try:
        res = db.execute(
            text("DELETE FROM audit_logs WHERE ts < :cutoff"),
            {"cutoff": cutoff},
        )
        db.commit()
        return res.rowcount or 0
    except Exception as e:
        db.rollback()
        log.warning(f"audit.purge_old failed: {e}")
        return 0

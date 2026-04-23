"""Per-username brute-force lockout.

Nginx limits login attempts per IP — a botnet defeats that. This module
layers an application-level lockout *per username* on top: after a threshold
of recent failures, the account is locked for a growing duration. A single
successful login wipes the slate clean for that username.

Design:
- Events are stored in `login_attempts(username, ip, ts, success)`, both
  successes and failures. Successes are used to reset the counter.
- `is_locked(db, username)` returns `(locked: bool, retry_after: int)`.
- Thresholds (fail-in-window → lock-duration):
    5 fails / 15 min  →  1  min
    10 fails / 1 h    →  15 min
    20 fails / 24 h   →  60 min
  The longest applicable lock wins.
- `record_attempt(db, username, ip, success)` writes the row. On success it
  also purges the username's prior failure rows so the counter resets.
- `purge_old(db)` retains only the last 7 days — called once at startup.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from sqlalchemy.orm import Session

from ..models import LoginAttempt

log = logging.getLogger("syslog-server")


# (window_seconds, fail_threshold, lockout_seconds)
_TIERS = (
    (15 * 60,      5,   60),
    (60 * 60,     10,  15 * 60),
    (24 * 60 * 60, 20, 60 * 60),
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def record_attempt(db: Session, username: str, ip: str | None, success: bool) -> None:
    """Persist a login attempt. On success, clears the failure history for
    this username so the lockout counter resets."""
    if not username:
        return
    try:
        db.add(LoginAttempt(
            username=username, ip=ip or None,
            ts=_iso(_now()), success=bool(success),
        ))
        if success:
            # Reset on success — a legitimate login shouldn't be penalised by
            # past bot noise.
            (db.query(LoginAttempt)
               .filter(LoginAttempt.username == username,
                       LoginAttempt.success == False)  # noqa: E712
               .delete(synchronize_session=False))
        db.commit()
    except Exception as e:
        db.rollback()
        log.warning(f"ratelimit.record_attempt failed: {e}")


def is_locked(db: Session, username: str) -> tuple[bool, int]:
    """Return `(locked, retry_after_seconds)` for this username."""
    if not username:
        return False, 0
    try:
        now = _now()
        locked_until = now
        for window_s, threshold, lockout_s in _TIERS:
            window_start = now - timedelta(seconds=window_s)
            # Only failures within the window count.
            fails = (db.query(LoginAttempt)
                       .filter(LoginAttempt.username == username,
                               LoginAttempt.success == False,  # noqa: E712
                               LoginAttempt.ts >= _iso(window_start))
                       .order_by(LoginAttempt.ts.desc())
                       .limit(threshold)
                       .all())
            if len(fails) >= threshold:
                # Lock starts from the most recent failure.
                last = datetime.fromisoformat(fails[0].ts)
                candidate = last + timedelta(seconds=lockout_s)
                if candidate > locked_until:
                    locked_until = candidate
        if locked_until > now:
            return True, int((locked_until - now).total_seconds())
        return False, 0
    except Exception as e:
        log.warning(f"ratelimit.is_locked failed: {e}")
        return False, 0


def purge_old(db: Session, keep_days: int = 7) -> int:
    cutoff = _iso(_now() - timedelta(days=keep_days))
    try:
        n = (db.query(LoginAttempt)
               .filter(LoginAttempt.ts < cutoff)
               .delete(synchronize_session=False))
        db.commit()
        return int(n or 0)
    except Exception as e:
        db.rollback()
        log.warning(f"ratelimit.purge_old failed: {e}")
        return 0

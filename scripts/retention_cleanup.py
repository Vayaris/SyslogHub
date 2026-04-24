#!/usr/bin/env python3
"""v2.0.0 — purge des logs selon la rétention par space + respect des legal holds.

Changements vs v1.x :
  - Rétention `per space` (colonne `spaces.retention_days`), default 365j (LCEN).
  - Tout fichier couvert par un `legal_hold` actif est PRÉSERVÉ, même expiré.
  - Chaque suppression / préservation est tracée dans `audit_logs`.

Lancé par le timer systemd `syslog-retention.timer` (quotidien).
"""
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "/opt/syslog-server")

from app import config
from app.database import SessionLocal
from app.models import AuditLog, LegalHold, Space
from sqlalchemy import or_


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _log_event(db, action: str, space_id: int | None, details: dict):
    try:
        db.add(AuditLog(
            ts=_now_iso(),
            username="system",
            action=action,
            ip=None,
            user_agent="retention_cleanup.py",
            details=json.dumps(details, default=str),
        ))
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"  ! audit_log failed : {e}", file=sys.stderr)


def _active_holds(db, space_id: int) -> list[LegalHold]:
    return (
        db.query(LegalHold)
          .filter(LegalHold.active == True,                                  # noqa: E712
                  or_(LegalHold.space_id == None, LegalHold.space_id == space_id))  # noqa: E711
          .all()
    )


def _held_by(holds: list[LegalHold], file_mtime_ts: float) -> LegalHold | None:
    """Retourne le premier hold dont la plage couvre le fichier, ou None."""
    ft = datetime.fromtimestamp(file_mtime_ts, tz=timezone.utc)
    for h in holds:
        try:
            h_from = datetime.fromisoformat(h.time_from)
            h_to   = datetime.fromisoformat(h.time_to)
        except ValueError:
            continue
        if h_from <= ft <= h_to:
            return h
    return None


def _bytes_fmt(n: int) -> str:
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024: return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB"


def main():
    db = SessionLocal()
    try:
        spaces = db.query(Space).all()
        if not spaces:
            print("Aucun space configuré.")
            return

        now_ts = time.time()
        grand_deleted = 0
        grand_bytes = 0
        grand_held = 0

        for space in spaces:
            retention_days = int(space.retention_days or 365)
            cutoff = now_ts - retention_days * 86400
            log_dir = Path(config.LOG_ROOT) / str(space.port)
            if not log_dir.exists():
                continue

            holds = _active_holds(db, space.id)
            deleted = 0
            bytes_freed = 0
            held_count = 0

            for f in log_dir.rglob("*"):
                if not f.is_file():
                    continue
                # Ne pas toucher les artefacts de chaîne
                if f.parent.name == "chain":
                    continue
                try:
                    stat = f.stat()
                except OSError:
                    continue
                if stat.st_mtime >= cutoff:
                    continue    # dans la période de rétention

                hold = _held_by(holds, stat.st_mtime)
                if hold is not None:
                    held_count += 1
                    _log_event(db, "retention_skip_hold", space.id, {
                        "file": str(f.relative_to(log_dir)),
                        "mtime": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                        "hold_id": hold.id,
                        "requisition_id": hold.requisition_id,
                    })
                    continue

                try:
                    f.unlink()
                    deleted += 1
                    bytes_freed += stat.st_size
                    _log_event(db, "retention_delete", space.id, {
                        "file": str(f.relative_to(log_dir)),
                        "size_bytes": stat.st_size,
                        "age_days": int((now_ts - stat.st_mtime) / 86400),
                    })
                except OSError as e:
                    print(f"  ! Erreur suppression {f}: {e}", file=sys.stderr)

            if deleted or held_count:
                print(f"[space {space.id} {space.name} — rétention {retention_days}j] "
                      f"supprimés: {deleted} ({_bytes_fmt(bytes_freed)}) · "
                      f"préservés (hold): {held_count}")
            grand_deleted += deleted
            grand_bytes += bytes_freed
            grand_held += held_count

        print(f"\nTotal : {grand_deleted} fichiers supprimés ({_bytes_fmt(grand_bytes)}), "
              f"{grand_held} préservés sous legal hold")
    finally:
        db.close()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Retention cleanup — removes log files older than retention_days setting.
Run via systemd timer (syslog-retention.timer) or cron.
"""

import sys
import os
import time
from pathlib import Path

sys.path.insert(0, "/opt/syslog-server")

from app.database import SessionLocal
from app.models import Setting
from app import config


def main():
    db = SessionLocal()
    try:
        row = db.query(Setting).filter(Setting.key == "retention_days").first()
        retention_days = int(row.value) if row else 90
    finally:
        db.close()

    cutoff = time.time() - (retention_days * 86400)
    log_root = Path(config.LOG_ROOT)

    if not log_root.exists():
        print(f"Log root {log_root} not found, nothing to do.")
        return

    deleted = 0
    total_bytes = 0

    for f in log_root.rglob("*"):
        if not f.is_file():
            continue
        try:
            mtime = f.stat().st_mtime
            if mtime < cutoff:
                size = f.stat().st_size
                f.unlink()
                deleted += 1
                total_bytes += size
                print(f"Deleted: {f} ({size} bytes)")
        except OSError as e:
            print(f"Error deleting {f}: {e}", file=sys.stderr)

    mb = total_bytes / (1024 * 1024)
    print(f"Done: deleted {deleted} files, freed {mb:.1f} MB (retention={retention_days} days)")


if __name__ == "__main__":
    main()

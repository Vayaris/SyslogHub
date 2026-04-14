#!/usr/bin/env python3
"""Daily SQLite backup with 7-day rotation."""
import shutil
import sys
from datetime import datetime
from pathlib import Path

DB = Path("/opt/syslog-server/data/syslog-server.db")
BACKUP_DIR = Path("/opt/syslog-server/data/backups")
KEEP = 7

if not DB.exists():
    print(f"ERROR: database not found at {DB}", file=sys.stderr)
    sys.exit(1)

BACKUP_DIR.mkdir(parents=True, exist_ok=True)

dst = BACKUP_DIR / f"syslog-server_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
shutil.copy2(DB, dst)
print(f"Backup created: {dst.name}")

# Rotation: keep only the KEEP most recent backups
backups = sorted(BACKUP_DIR.glob("syslog-server_*.db"))
for old in backups[:-KEEP]:
    old.unlink()
    print(f"Removed old backup: {old.name}")

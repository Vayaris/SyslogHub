#!/usr/bin/env python3
"""Daily SQLite backup with 7-day rotation. Backups are encrypted at rest
with the Fernet master key from config/secrets.key (v1.10.0). Decrypt via
scripts/restore_backup.py."""
import os
import sys
from datetime import datetime
from pathlib import Path

# Secrets in the DB (admin hash, SMTP/OIDC/Omada creds) — the backup must
# never inherit a world-readable umask from cron/systemd.
os.umask(0o077)

sys.path.insert(0, "/opt/syslog-server")
from app.services import crypto as crypto_svc

DB = Path("/opt/syslog-server/data/syslog-server.db")
BACKUP_DIR = Path("/opt/syslog-server/data/backups")
KEEP = 7

if not DB.exists():
    print(f"ERROR: database not found at {DB}", file=sys.stderr)
    sys.exit(1)

BACKUP_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
os.chmod(BACKUP_DIR, 0o700)

ts = datetime.now().strftime("%Y%m%d_%H%M%S")
dst = BACKUP_DIR / f"syslog-server_{ts}.db.enc"

# Read the full DB and write the encrypted copy atomically.
db_bytes = DB.read_bytes()
ciphertext = crypto_svc.encrypt_bytes(db_bytes)

tmp = dst.with_suffix(dst.suffix + ".tmp")
fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
try:
    os.write(fd, ciphertext)
finally:
    os.close(fd)
os.rename(tmp, dst)
os.chmod(dst, 0o600)
print(f"Backup created: {dst.name}")

# Rotation: keep only the KEEP most recent backups. Match both legacy .db
# and new .db.enc so upgrades don't orphan old clear-text copies.
backups = sorted(BACKUP_DIR.glob("syslog-server_*.db*"))
# Remove old legacy cleartext copies outright — they defeat the purpose.
legacy_cleartext = [b for b in backups if b.name.endswith(".db") and not b.name.endswith(".db.enc")]
for old in legacy_cleartext:
    old.unlink()
    print(f"Removed legacy plaintext backup: {old.name}")

backups = sorted(BACKUP_DIR.glob("syslog-server_*.db.enc"))
for old in backups[:-KEEP]:
    old.unlink()
    print(f"Removed old backup: {old.name}")

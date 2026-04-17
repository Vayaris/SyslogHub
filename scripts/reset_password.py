#!/usr/bin/env python3
"""Reset admin credentials to admin / changeme and rotate session secret.

Usage: sudo /opt/syslog-server/venv/bin/python /opt/syslog-server/scripts/reset_password.py
"""
import sys
import secrets
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import bcrypt
from app.database import SessionLocal, init_db
from app.models import Setting


def _set(db, key: str, value: str):
    row = db.query(Setting).filter(Setting.key == key).first()
    if row:
        row.value = value
    else:
        db.add(Setting(key=key, value=value))


def main():
    init_db()
    db = SessionLocal()
    try:
        _set(db, "admin_username", "admin")
        _set(db, "admin_password_hash", bcrypt.hashpw(b"changeme", bcrypt.gensalt()).decode())
        _set(db, "session_secret", secrets.token_hex(32))
        db.commit()
        print("OK — identifiants réinitialisés : admin / changeme (toutes sessions invalidées)")
    finally:
        db.close()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Alert check — run every 10 min via systemd timer."""
import sys

sys.path.insert(0, "/opt/syslog-server")

from app.database import SessionLocal
from app.services import alerts


def main():
    db = SessionLocal()
    try:
        res = alerts.run_all_checks(db)
        print(f"alerts: {res}")
    finally:
        db.close()


if __name__ == "__main__":
    main()

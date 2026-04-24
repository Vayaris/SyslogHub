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
        print(f"alerts no-log: {res}")
        # v2.0.0 — conformité checks toutes les X minutes, mais les alertes
        # sont idempotentes au niveau message (email seulement si anomalie).
        # Pas de spam tant qu'aucune nouvelle anomalie n'apparaît ? En l'état
        # on renvoie à chaque run — si c'est gênant, déduper via un flag DB.
        comp = alerts.check_compliance(db)
        print(f"alerts compliance: {comp}")
    finally:
        db.close()


if __name__ == "__main__":
    main()

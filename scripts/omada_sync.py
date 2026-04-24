#!/usr/bin/env python3
"""v2.0.0 — sync périodique des sessions hotspot Omada.

Exécuté toutes les 5 minutes via timer systemd. Pour chaque space avec
`omada_sync_enabled=1`, pull les clients actifs et upsert dans
`omada_sessions`.
"""
import sys

sys.path.insert(0, "/opt/syslog-server")

from app.database import SessionLocal
from app.models import Space
from app.services import omada_sync


def main():
    db = SessionLocal()
    try:
        spaces = db.query(Space).filter(
            Space.enabled == True,                # noqa: E712
            Space.omada_sync_enabled == True,     # noqa: E712
        ).all()
        if not spaces:
            return
        for sp in spaces:
            try:
                pulled, upserted = omada_sync.sync_space(db, sp)
                if pulled or upserted:
                    print(f"[omada_sync] space={sp.id} {sp.name}: "
                          f"{pulled} actifs, {upserted} nouveau(x)")
            except Exception as e:
                print(f"[omada_sync] space={sp.id} {sp.name}: ERROR {e}")
    finally:
        db.close()


if __name__ == "__main__":
    main()

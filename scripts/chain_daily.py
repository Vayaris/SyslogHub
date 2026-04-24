#!/usr/bin/env python3
"""v2.0.0 — construction quotidienne de la chaîne d'intégrité + horodatage TSA.

Lancé par le timer systemd `syslog-chain.timer` à 00:05 UTC. Pour chaque
space avec `chain_enabled=1`, construit le manifest du jour J-1 s'il n'existe
pas déjà, puis soumet son hash à la TSA configurée.

Safe à rejouer : idempotent via le `UNIQUE(space_id, day)`.
"""
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, "/opt/syslog-server")

from app.database import SessionLocal
from app.models import Space
from app.services import chain as chain_svc
from app.services import tsa as tsa_svc


def main():
    db = SessionLocal()
    try:
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).date()
        spaces = db.query(Space).filter(Space.enabled == True, Space.chain_enabled == True).all()  # noqa: E712
        print(f"[chain_daily] {len(spaces)} spaces à traiter pour le jour {yesterday}")

        for space in spaces:
            try:
                row = chain_svc.build_daily_manifest(db, space, yesterday)
            except Exception as e:
                print(f"  [✗] space={space.id} {space.name}: build_manifest échoué : {e}")
                continue
            if row is None:
                print(f"  [·] space={space.id} {space.name}: aucun log sur {yesterday}")
                continue
            print(f"  [✓] space={space.id} {space.name}: {row.files_count} fichiers, "
                  f"{row.total_bytes} octets, sha256={row.manifest_sha256[:12]}…")

            if tsa_svc.is_enabled():
                ok = tsa_svc.timestamp_manifest(db, row)
                status = "TSA OK" if ok else f"TSA {row.tsa_status} ({row.tsa_last_error or '?'})"
                print(f"       {status}")

        # Rejouer les échecs antérieurs qui ont encore du budget retry
        if tsa_svc.is_enabled():
            retried, ok = tsa_svc.retry_failed(db)
            if retried:
                print(f"[chain_daily] Retry TSA : {ok}/{retried} réussis")
    finally:
        db.close()


if __name__ == "__main__":
    main()

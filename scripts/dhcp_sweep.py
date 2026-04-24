#!/usr/bin/env python3
"""v2.0.0 — sweep nightly des logs DHCP.

Pour chaque space avec `dhcp_parse_enabled=1`, parcourt les fichiers de logs
de J-1 et upsert les leases détectés dans `dhcp_leases`.

Idempotent via `UNIQUE(space_id, mac, ip, seen_at)`.
"""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, "/opt/syslog-server")

from app import config
from app.database import SessionLocal
from app.models import Space
from app.services import dhcp_parser


def main():
    db = SessionLocal()
    try:
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).date()
        day_start = datetime(yesterday.year, yesterday.month, yesterday.day, tzinfo=timezone.utc).timestamp()
        day_end   = day_start + 86400

        spaces = db.query(Space).filter(
            Space.enabled == True,                # noqa: E712
            Space.dhcp_parse_enabled == True,     # noqa: E712
        ).all()

        print(f"[dhcp_sweep] {len(spaces)} spaces avec parsing DHCP, jour {yesterday}")
        for sp in spaces:
            log_dir = Path(config.LOG_ROOT) / str(sp.port)
            if not log_dir.exists():
                continue
            files = []
            for f in log_dir.iterdir():
                if not f.is_file() or f.parent.name == "chain":
                    continue
                try:
                    mtime = f.stat().st_mtime
                except OSError:
                    continue
                if day_start <= mtime < day_end:
                    files.append(f)
            if not files:
                print(f"  [·] space={sp.id} {sp.name}: aucun fichier pour {yesterday}")
                continue
            total = 0
            for f in sorted(files, key=lambda p: p.name):
                n = dhcp_parser.sweep_file(db, sp, f)
                total += n
                if n:
                    print(f"    · {f.name}: +{n} leases")
            print(f"  [✓] space={sp.id} {sp.name}: {total} nouveaux leases")
    finally:
        db.close()


if __name__ == "__main__":
    main()

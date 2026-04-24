#!/usr/bin/env python3
"""v2.0.0 — vérifie la chaîne d'intégrité d'un ou de tous les spaces.

Usage :
    verify_chain.py                 # tous les spaces
    verify_chain.py --space 3       # un space précis

Code retour 0 si tout est OK, 1 sinon (pratique pour un monitoring cron).
"""
import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, "/opt/syslog-server")

from app.database import SessionLocal
from app.models import LogChain, Space
from app.services import chain as chain_svc


def check_space(db, space: Space) -> int:
    """Retourne le nombre d'anomalies détectées pour ce space."""
    rows = (
        db.query(LogChain)
          .filter(LogChain.space_id == space.id)
          .order_by(LogChain.day)
          .all()
    )
    print(f"\n== Space {space.id} — {space.name} (port {space.port}) ==")
    if not rows:
        print("  [·] Aucune chaîne en DB (service récent ou chain_enabled=0 ?)")
        # Mais : s'il y a des logs, c'est un vrai gap
        gaps = chain_svc.detect_gaps(db, space, days_back=30)
        if gaps:
            print(f"  [!] {len(gaps)} jours avec logs mais sans manifest : {gaps[:5]}{'…' if len(gaps)>5 else ''}")
            return len(gaps)
        return 0

    issues = 0
    prev_sha = None
    for r in rows:
        tag = ""
        if r.tsa_status == "ok":
            tag = f" — TSA OK ({(r.tsa_url or '?').split('//')[-1].split('/')[0]}, {r.tsa_gen_time})"
        elif r.tsa_status == "skipped_backfill":
            tag = " — TSA N/A (backfill rétroactif)"
        elif r.tsa_status == "failed":
            tag = f" — TSA FAILED ({r.tsa_attempts} tentatives) : {r.tsa_last_error or 'inconnu'}"
            issues += 1
        elif r.tsa_status == "pending":
            tag = " — TSA pending"

        manifest = chain_svc.load_manifest(space.port, _parse_day(r.day))
        if manifest is None:
            print(f"  [✗] {r.day} : manifest introuvable sur disque ({r.manifest_path})")
            issues += 1
            continue

        # Re-hash le manifest : doit correspondre au champ stocké en DB
        if not chain_svc.verify_manifest_hash(manifest):
            print(f"  [✗] {r.day} : hash du manifest ne correspond pas — ALTÉRATION")
            issues += 1
            continue

        # Chaîne : prev_sha256 du manifest doit matcher le sha256 du manifest précédent
        if prev_sha is not None and manifest.get("prev_sha256") != prev_sha:
            print(f"  [✗] {r.day} : prev_sha256 ne correspond pas au manifest précédent — CHAÎNE CASSÉE")
            issues += 1

        # Re-hash des fichiers listés
        bad = chain_svc.verify_file_hashes(manifest, space.port)
        if bad:
            for b in bad:
                if b["status"] == "missing":
                    print(f"  [!] {r.day} : fichier {b['name']} absent (purgé par rétention ?)")
                else:
                    print(f"  [✗] {r.day} : fichier {b['name']} ALTÉRÉ")
                    issues += 1
        else:
            print(f"  [✓] {r.day} ({r.files_count} fichiers, {_fmt_bytes(r.total_bytes)}){tag}")

        prev_sha = r.manifest_sha256

    return issues


def _parse_day(s: str):
    y, m, d = [int(x) for x in s.split("-")]
    from datetime import date
    return date(y, m, d)


def _fmt_bytes(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--space", type=int, help="Vérifie un seul space (par id)")
    args = p.parse_args()

    db = SessionLocal()
    try:
        q = db.query(Space)
        if args.space:
            q = q.filter(Space.id == args.space)
        spaces = q.order_by(Space.port).all()
        if not spaces:
            print("Aucun space trouvé.")
            return 0
        total_issues = 0
        for sp in spaces:
            total_issues += check_space(db, sp)
        print()
        if total_issues == 0:
            print("✅ Chaîne d'intégrité : OK sur tous les spaces vérifiés.")
            return 0
        print(f"❌ {total_issues} anomalie(s) détectée(s).")
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())

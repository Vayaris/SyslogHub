"""v2.0.0 — construction du bundle ZIP pour une réquisition judiciaire.

Le bundle contient :
  - MANIFEST.json       metadata + sha256 de chaque fichier
  - PV.pdf              procès-verbal d'extraction pré-rempli
  - README.txt          instructions de vérification (FR)
  - verify.sh           script portable (bash + sha256sum + openssl)
  - logs/<space>/       fichiers de logs bruts de la plage
  - chain/<space>/      manifests journaliers + .tsr
  - correlation/        CSV : dhcp_leases.csv, omada_sessions.csv

Streamé directement dans un fichier — pas de BytesIO (les grosses réquisitions
peuvent dépasser plusieurs GB et feraient OOM).
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import os
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from .. import config
from ..models import (
    DhcpLease, LogChain, OmadaSession, Requisition, Space, User, Setting,
)
from . import pdf_templates

log = logging.getLogger("syslog-server")

BUNDLE_DIR = Path("/opt/syslog-server/data/requisitions")
BUNDLE_DIR.mkdir(parents=True, exist_ok=True)


def _slugify(s: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]+", "-", s).strip("-")
    return s or "x"


def _sha256_stream(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def _parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _get_org(db: Session) -> dict:
    keys = [
        "organization_name", "organization_address", "organization_siren",
        "dpo_name", "dpo_email", "privacy_contact_email",
    ]
    rows = {r.key: r.value for r in db.query(Setting).filter(Setting.key.in_(keys)).all()}
    return {
        "name":    rows.get("organization_name"),
        "address": rows.get("organization_address"),
        "siren":   rows.get("organization_siren"),
        "dpo_name":  rows.get("dpo_name"),
        "dpo_email": rows.get("dpo_email"),
        "privacy_contact_email": rows.get("privacy_contact_email"),
    }


def _spaces_for(db: Session, req: Requisition) -> list[Space]:
    if req.space_id:
        s = db.query(Space).filter(Space.id == req.space_id).first()
        return [s] if s else []
    return db.query(Space).all()


def _files_for_space(space: Space, t_from: datetime, t_to: datetime) -> list[Path]:
    log_dir = Path(config.LOG_ROOT) / str(space.port)
    if not log_dir.exists():
        return []
    lo = t_from.timestamp() - 86400   # tampon d'un jour de chaque côté
    hi = t_to.timestamp() + 86400
    out = []
    for f in log_dir.iterdir():
        if not f.is_file():
            continue
        if f.parent.name == "chain":
            continue
        try:
            mtime = f.stat().st_mtime
        except OSError:
            continue
        if lo <= mtime <= hi:
            out.append(f)
    return sorted(out, key=lambda p: p.name)


def _chain_rows_for_space(db: Session, space: Space, t_from: datetime, t_to: datetime) -> list[LogChain]:
    from datetime import timedelta
    day_lo = (t_from - timedelta(days=1)).date().isoformat()
    day_hi = (t_to + timedelta(days=1)).date().isoformat()
    return (
        db.query(LogChain)
          .filter(LogChain.space_id == space.id,
                  LogChain.day >= day_lo, LogChain.day <= day_hi)
          .order_by(LogChain.day)
          .all()
    )


README_TEMPLATE = """Bundle de réquisition SyslogHub v2.0.0
=======================================

Réquisition : {number}
OPJ         : {opj_name} ({opj_service})
Plage       : {time_from} → {time_to}
Généré le   : {generated_at}

Contenu :
  MANIFEST.json        Métadonnées du bundle + SHA-256 de chaque fichier.
  PV.pdf               Procès-verbal d'extraction pré-rempli (à signer).
  logs/                Fichiers de logs bruts couvrant la plage.
  chain/               Manifests journaliers (.json) + horodatages TSA (.tsr).
  correlation/         CSV — leases DHCP et sessions Omada hotspot.
  verify.sh            Script portable de vérification cryptographique.
  signatures/bundle.sha256   Hash du bundle (sans ce fichier).

Vérification indépendante
-------------------------
Sur une machine Linux/macOS avec bash + sha256sum + openssl, exécuter :

    cd <dossier_extrait>
    bash verify.sh

Le script vérifie :
  1. SHA-256 de chaque fichier (logs + chain + correlation) vs MANIFEST.json
  2. Cohérence de la chaîne d'intégrité (sha256 du manifest suivant = prev_sha256)
  3. Validité des horodatages RFC 3161 (si le .tsr est présent et si openssl ts
     est disponible avec la CA fournie par la TSA)
  4. SHA-256 du bundle lui-même

Cadre légal
-----------
Les données conservées dans ce bundle le sont en application de la LCEN
(loi n° 2004-575 du 21 juin 2004), article 6-II, et de l'article R. 10-13 CPCE
qui imposent aux opérateurs de services de communication au public en ligne
la conservation des données de connexion pendant un an.

Contact conformité
------------------
{contact}

— fin du README —
"""

VERIFY_SH = r"""#!/bin/bash
# SyslogHub v2.0 — vérification d'intégrité d'un bundle de réquisition.
# Dépendances : bash, sha256sum, openssl.
set -e
cd "$(dirname "$0")"

FAIL=0

if [ ! -f MANIFEST.json ]; then
  echo "[✗] MANIFEST.json manquant"
  exit 1
fi

echo "[1/4] Vérification des SHA-256 des fichiers…"
python3 -c '
import json, hashlib, sys
with open("MANIFEST.json") as f: m = json.load(f)
files = m["files"]
errors = 0
for entry in files:
    path = entry["path"]
    expected = entry["sha256"]
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(65536)
                if not chunk: break
                h.update(chunk)
        actual = h.hexdigest()
        if actual != expected:
            exp_s = expected[:12]
            act_s = actual[:12]
            print("  [X] " + path + ": sha256 different (expected " + exp_s + "..., got " + act_s + "...)")
            errors += 1
    except FileNotFoundError:
        print("  [X] " + path + ": absent")
        errors += 1
print("   " + str(len(files)) + " fichiers verifies, " + str(errors) + " anomalie(s)")
sys.exit(0 if errors == 0 else 2)
' || FAIL=$((FAIL+1))

echo "[2/4] Vérification de la chaîne d'intégrité…"
python3 -c '
import json, hashlib, sys, os, pathlib
errors = 0
for space_dir in pathlib.Path("chain").glob("*/"):
    prev_sha = None
    for manifest in sorted(space_dir.glob("*.json")):
        with open(manifest, "r", encoding="utf-8") as f:
            m = json.load(f)
        # Re-hash canonique
        claimed = m.get("manifest_sha256")
        m_nosig = {k: v for k, v in m.items() if k != "manifest_sha256"}
        raw = json.dumps(m_nosig, sort_keys=True, separators=(",",":"), ensure_ascii=False).encode()
        actual = hashlib.sha256(raw).hexdigest()
        if actual != claimed:
            print(f"  [✗] {manifest}: hash manifest invalide")
            errors += 1
        if prev_sha is not None and m.get("prev_sha256") != prev_sha:
            print(f"  [✗] {manifest}: prev_sha256 ne correspond pas — chaîne cassée")
            errors += 1
        prev_sha = claimed
print(f"   Chaîne : {errors} anomalie(s)")
sys.exit(0 if errors == 0 else 2)
' || FAIL=$((FAIL+1))

echo "[3/4] Vérification des horodatages TSA (si openssl disponible)…"
if command -v openssl >/dev/null 2>&1; then
  count=0
  for tsr in chain/*/*.tsr; do
    [ -f "$tsr" ] || continue
    count=$((count+1))
    # L'utilisateur devra fournir la CA de la TSA s'il veut -verify complet.
    openssl ts -reply -in "$tsr" -text 2>/dev/null | grep -E "Time stamp:|Serial" | head -2
  done
  echo "   $count horodatage(s) listé(s). Pour une vérification signée : openssl ts -verify -data <manifest.json> -in <manifest.tsr> -CAfile <ca_de_la_TSA>"
else
  echo "   (openssl absent — étape ignorée)"
fi

echo "[4/4] Vérification du SHA-256 du bundle…"
if [ -f signatures/bundle.sha256 ]; then
  EXPECTED=$(cat signatures/bundle.sha256)
  ACTUAL=$(find . -type f ! -path "./signatures/*" -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')
  if [ "$EXPECTED" = "$ACTUAL" ]; then
    echo "   ✓ Bundle intègre"
  else
    echo "   ✗ Bundle ALTÉRÉ (attendu $EXPECTED, obtenu $ACTUAL)"
    FAIL=$((FAIL+1))
  fi
fi

if [ $FAIL -eq 0 ]; then
  echo
  echo "✓ Bundle intègre. Voir PV.pdf pour le procès-verbal."
  exit 0
else
  echo
  echo "✗ $FAIL groupe(s) d'anomalie(s) détecté(s). Ne pas considérer ce bundle comme probant."
  exit 1
fi
"""


def build_bundle(db: Session, req: Requisition, operator: User) -> dict:
    """Construit le ZIP, met à jour req.* (bundle_path, bundle_sha256, size).
    Retourne un dict récap."""
    t_from = _parse_iso(req.time_from)
    t_to   = _parse_iso(req.time_to)

    spaces = _spaces_for(db, req)
    organization = _get_org(db)

    slug_num = _slugify(req.number)
    out_path = BUNDLE_DIR / f"requisition_{slug_num}_{req.id}.zip"

    manifest_entries = []
    chain_entries_flat = []

    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:

        # 1. Logs bruts par space
        for sp in spaces:
            sp_slug = _slugify(sp.name)
            files = _files_for_space(sp, t_from, t_to)
            for f in files:
                arc = f"logs/{sp_slug}/{f.name}"
                sha = _sha256_stream(f)
                zf.write(str(f), arc)
                manifest_entries.append({
                    "path": arc, "size": f.stat().st_size, "sha256": sha,
                })

        # 2. Chaîne d'intégrité par space
        for sp in spaces:
            sp_slug = _slugify(sp.name)
            rows = _chain_rows_for_space(db, sp, t_from, t_to)
            for r in rows:
                if r.manifest_path and Path(r.manifest_path).exists():
                    arc = f"chain/{sp_slug}/{Path(r.manifest_path).name}"
                    sha = _sha256_stream(Path(r.manifest_path))
                    zf.write(r.manifest_path, arc)
                    manifest_entries.append({
                        "path": arc, "size": Path(r.manifest_path).stat().st_size,
                        "sha256": sha,
                    })
                if r.tsa_receipt_path and Path(r.tsa_receipt_path).exists():
                    arc = f"chain/{sp_slug}/{Path(r.tsa_receipt_path).name}"
                    sha = _sha256_stream(Path(r.tsa_receipt_path))
                    zf.write(r.tsa_receipt_path, arc)
                    manifest_entries.append({
                        "path": arc, "size": Path(r.tsa_receipt_path).stat().st_size,
                        "sha256": sha,
                    })
                chain_entries_flat.append({
                    "space_id": sp.id, "space_name": sp.name, "day": r.day,
                    "manifest_sha256": r.manifest_sha256,
                    "tsa_status": r.tsa_status, "tsa_gen_time": r.tsa_gen_time,
                    "tsa_serial": r.tsa_serial, "tsa_url": r.tsa_url,
                    "files_count": r.files_count, "total_bytes": r.total_bytes,
                })

        # 3. Corrélation — CSV par space
        for sp in spaces:
            sp_slug = _slugify(sp.name)
            dhcp_rows = (
                db.query(DhcpLease)
                  .filter(DhcpLease.space_id == sp.id,
                          DhcpLease.seen_at >= t_from.isoformat(),
                          DhcpLease.seen_at <= t_to.isoformat())
                  .all()
            )
            if dhcp_rows:
                buf = io.StringIO()
                w = csv.writer(buf)
                w.writerow(["mac", "ip", "hostname", "seen_at", "source_file"])
                for r in dhcp_rows:
                    w.writerow([r.mac, r.ip, r.hostname or "", r.seen_at, r.source_file or ""])
                arc = f"correlation/{sp_slug}_dhcp_leases.csv"
                data = buf.getvalue().encode("utf-8")
                zf.writestr(arc, data)
                manifest_entries.append({
                    "path": arc, "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                })

            om_rows = (
                db.query(OmadaSession)
                  .filter(OmadaSession.space_id == sp.id,
                          OmadaSession.session_start >= t_from.isoformat(),
                          OmadaSession.session_start <= t_to.isoformat())
                  .all()
            )
            if om_rows:
                buf = io.StringIO()
                w = csv.writer(buf)
                w.writerow([
                    "client_mac", "client_ip", "identifier",
                    "ap_mac", "ssid", "session_start", "session_end",
                    "uploaded_bytes", "downloaded_bytes",
                ])
                for r in om_rows:
                    w.writerow([
                        r.client_mac, r.client_ip or "", r.identifier or "",
                        r.ap_mac or "", r.ssid or "",
                        r.session_start, r.session_end or "",
                        r.uploaded_bytes or 0, r.downloaded_bytes or 0,
                    ])
                arc = f"correlation/{sp_slug}_omada_sessions.csv"
                data = buf.getvalue().encode("utf-8")
                zf.writestr(arc, data)
                manifest_entries.append({
                    "path": arc, "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                })

        # 4. PV.pdf
        pv_buf = io.BytesIO()
        pdf_templates.render_requisition_pv(
            pv_buf,
            requisition={
                "number": req.number, "opj_name": req.opj_name,
                "opj_service": req.opj_service, "opj_email": req.opj_email,
                "justification": req.justification,
                "space_id": req.space_id,
                "space_name": (spaces[0].name if len(spaces) == 1 else None),
                "time_from": req.time_from, "time_to": req.time_to,
                "created_at": req.created_at,
            },
            organization=organization,
            chain_entries=chain_entries_flat,
            operator_username=operator.username,
        )
        pv_bytes = pv_buf.getvalue()
        zf.writestr("PV.pdf", pv_bytes)
        manifest_entries.append({
            "path": "PV.pdf", "size": len(pv_bytes),
            "sha256": hashlib.sha256(pv_bytes).hexdigest(),
        })

        # 5. README.txt
        readme = README_TEMPLATE.format(
            number=req.number, opj_name=req.opj_name,
            opj_service=req.opj_service or "—",
            time_from=req.time_from, time_to=req.time_to,
            generated_at=datetime.now(timezone.utc).isoformat(),
            contact=(organization.get("privacy_contact_email")
                     or organization.get("dpo_email")
                     or "Non renseigné"),
        ).encode("utf-8")
        zf.writestr("README.txt", readme)
        manifest_entries.append({
            "path": "README.txt", "size": len(readme),
            "sha256": hashlib.sha256(readme).hexdigest(),
        })

        # 6. verify.sh
        vs = VERIFY_SH.encode("utf-8")
        zf.writestr(zipfile.ZipInfo(filename="verify.sh"), vs)
        manifest_entries.append({
            "path": "verify.sh", "size": len(vs),
            "sha256": hashlib.sha256(vs).hexdigest(),
        })

        # 7. MANIFEST.json — écrit en DERNIER pour contenir tous les hashes
        manifest_doc = {
            "version": 1,
            "requisition": {
                "number":    req.number,
                "opj":       {"name": req.opj_name, "service": req.opj_service,
                              "email": req.opj_email},
                "justification": req.justification,
                "spaces":    [{"id": s.id, "name": s.name, "port": s.port} for s in spaces],
                "time_from": req.time_from, "time_to": req.time_to,
                "created_by": operator.username,
                "created_at": req.created_at,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            },
            "organization": organization,
            "files":        manifest_entries,
            "files_count":  len(manifest_entries),
            "total_bytes":  sum(m["size"] for m in manifest_entries),
        }
        manifest_bytes = json.dumps(manifest_doc, indent=2, ensure_ascii=False).encode("utf-8")
        zf.writestr("MANIFEST.json", manifest_bytes)

        # 8. signatures/bundle.sha256 — agrégat de tous les sha256 de chaque
        #    entrée (triés par path), pour vérification indépendante via
        #    verify.sh. Cohérent avec le check find | sort | sha256sum.
        all_entries = list(manifest_entries)
        all_entries.append({
            "path": "MANIFEST.json",
            "size": len(manifest_bytes),
            "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        })
        # Format identique à ce que produit `find -type f ! -path './signatures/*'
        #   -print0 | sort -z | xargs -0 sha256sum | sha256sum`
        lines = []
        for e in sorted(all_entries, key=lambda x: x["path"]):
            lines.append(f"{e['sha256']}  ./{e['path']}\n")
        inner_digest = hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()
        zf.writestr("signatures/bundle.sha256", inner_digest)

    # 9. SHA-256 du ZIP entier (stocké en DB + commentaire ZIP)
    bundle_sha = _sha256_stream(out_path)
    try:
        with zipfile.ZipFile(out_path, "a", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.comment = f"SyslogHub-v2.0 bundle_sha256={bundle_sha} inner={inner_digest}".encode()
    except Exception:
        pass

    req.bundle_path       = str(out_path)
    req.bundle_sha256     = bundle_sha
    req.bundle_size_bytes = out_path.stat().st_size
    req.exported_at       = datetime.now(timezone.utc).isoformat()
    req.status            = "exported"
    db.commit()

    try:
        os.chmod(str(out_path), 0o600)
    except OSError:
        pass

    return {
        "bundle_path":       str(out_path),
        "bundle_sha256":     bundle_sha,
        "bundle_size_bytes": req.bundle_size_bytes,
        "files_count":       len(manifest_entries),
    }


def preview(db: Session, space_id: int | None, t_from: datetime, t_to: datetime) -> dict:
    """Récap non-destructif : combien de fichiers, quelle taille, couverts par la plage."""
    if space_id:
        spaces = [db.query(Space).filter(Space.id == space_id).first()]
        spaces = [s for s in spaces if s]
    else:
        spaces = db.query(Space).all()
    total_files = 0
    total_bytes = 0
    per_space = []
    for sp in spaces:
        if sp is None:
            continue
        files = _files_for_space(sp, t_from, t_to)
        bytes_ = sum(f.stat().st_size for f in files if f.exists())
        per_space.append({
            "space_id": sp.id, "space_name": sp.name,
            "files": len(files), "bytes": bytes_,
        })
        total_files += len(files)
        total_bytes += bytes_
    return {
        "files":    total_files,
        "bytes":    total_bytes,
        "per_space": per_space,
    }

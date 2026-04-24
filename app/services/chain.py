"""v2.0.0 — chaîne d'intégrité journalière (par space).

Chaque jour, pour chaque space avec `chain_enabled=1`, on construit un
manifest JSON qui liste tous les fichiers de logs rotated + actifs dont le
mtime est dans le jour UTC concerné, avec leur SHA-256. Le manifest contient
aussi le sha256 du manifest du jour précédent — une modification a posteriori
de n'importe quel log ou manifest casse la chaîne et est détectable par
`scripts/verify_chain.py`.

Après construction, le hash du manifest est soumis à une TSA RFC3161 pour
l'horodatage qualifié (cf. `tsa.py`).

Structure sur disque :
    /var/log/syslog-server/<port>/chain/
        2026-04-23.json         # manifest
        2026-04-23.tsr          # TSA response (si horodatage réussi)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

from sqlalchemy.orm import Session

from .. import config
from ..models import LogChain, Space

log = logging.getLogger("syslog-server")

_RESERVED_PREFIX = "_"     # fichiers _all.log etc. — inclus dans le manifest
_MANIFEST_VERSION = 1


def _chain_dir(port: int) -> Path:
    return Path(config.LOG_ROOT) / str(port) / "chain"


def manifest_path(port: int, day: date) -> Path:
    return _chain_dir(port) / f"{day.isoformat()}.json"


def tsr_path(port: int, day: date) -> Path:
    return _chain_dir(port) / f"{day.isoformat()}.tsr"


def _sha256_stream(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def _canonical_sha256(manifest: dict) -> str:
    """Hash déterministe du manifest JSON (sort_keys, séparateurs compacts).

    Le champ `manifest_sha256` s'il est présent est retiré avant hash — on
    hashe l'objet "sans sa propre signature"."""
    m = dict(manifest)
    m.pop("manifest_sha256", None)
    raw = json.dumps(m, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _iter_log_files(port: int, day: date) -> Iterable[Path]:
    log_dir = Path(config.LOG_ROOT) / str(port)
    if not log_dir.exists():
        return []
    day_start = datetime(day.year, day.month, day.day, tzinfo=timezone.utc).timestamp()
    day_end   = day_start + 86400
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
        if day_start <= mtime < day_end:
            out.append(f)
    return sorted(out, key=lambda p: p.name)


def build_daily_manifest(db: Session, space: Space, day: date) -> LogChain | None:
    """Construit le manifest du jour pour ce space, écrit le JSON, crée la
    ligne `log_chain` (ou la met à jour si elle existe déjà). Retourne la
    ligne ou None si aucun fichier n'a été trouvé (pas de manifest créé).

    Idempotent : relancer sur un jour déjà manifesté écrase le JSON avec le
    nouveau scan (les hashes seront identiques si rien n'a bougé)."""
    chain_dir = _chain_dir(space.port)
    chain_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(chain_dir), 0o750)
    except OSError:
        pass

    files = list(_iter_log_files(space.port, day))
    if not files:
        return None

    # prev_sha256 : chercher le manifest le plus récent antérieur à `day` pour
    # ce space. On n'exige pas J-1 exactement : un space peut ne pas avoir de
    # logs un jour donné, ça ne doit pas casser la chaîne.
    prev_row = (
        db.query(LogChain)
          .filter(LogChain.space_id == space.id, LogChain.day < day.isoformat())
          .order_by(LogChain.day.desc())
          .first()
    )
    prev_sha = prev_row.manifest_sha256 if prev_row else None

    files_meta = []
    total_bytes = 0
    for f in files:
        size = f.stat().st_size
        total_bytes += size
        files_meta.append({
            "name":   f.name,
            "size":   size,
            "sha256": _sha256_stream(f),
            "mtime":  datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc).isoformat(),
        })

    manifest = {
        "version":        _MANIFEST_VERSION,
        "space":          {"id": space.id, "name": space.name, "port": space.port},
        "day":            day.isoformat(),
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "prev_sha256":    prev_sha,
        "files":          files_meta,
        "files_count":    len(files_meta),
        "total_bytes":    total_bytes,
    }
    sha = _canonical_sha256(manifest)
    manifest["manifest_sha256"] = sha

    mpath = manifest_path(space.port, day)
    with open(mpath, "w", encoding="utf-8") as f:
        json.dump(manifest, f, sort_keys=True, ensure_ascii=False, indent=2)
    try:
        os.chmod(str(mpath), 0o640)
    except OSError:
        pass

    row = (
        db.query(LogChain)
          .filter(LogChain.space_id == space.id, LogChain.day == day.isoformat())
          .first()
    )
    if row:
        row.manifest_path   = str(mpath)
        row.manifest_sha256 = sha
        row.prev_sha256     = prev_sha
        row.files_count     = len(files_meta)
        row.total_bytes     = total_bytes
        # tsa_* non touchés — permet de retry l'horodatage séparément
    else:
        row = LogChain(
            space_id        = space.id,
            day             = day.isoformat(),
            manifest_path   = str(mpath),
            manifest_sha256 = sha,
            prev_sha256     = prev_sha,
            files_count     = len(files_meta),
            total_bytes     = total_bytes,
            tsa_status      = "pending",
            created_at      = datetime.now(timezone.utc).isoformat(),
        )
        db.add(row)
    db.commit()
    db.refresh(row)
    return row


def verify_file_hashes(manifest_dict: dict, port: int) -> list[dict]:
    """Re-hash les fichiers listés dans le manifest et compare. Retourne la
    liste des divergences : [{name, expected, actual, status}]."""
    log_dir = Path(config.LOG_ROOT) / str(port)
    issues = []
    for entry in manifest_dict.get("files", []):
        path = log_dir / entry["name"]
        if not path.exists():
            issues.append({
                "name": entry["name"], "status": "missing",
                "expected": entry["sha256"], "actual": None,
            })
            continue
        actual = _sha256_stream(path)
        if actual != entry["sha256"]:
            issues.append({
                "name": entry["name"], "status": "mismatch",
                "expected": entry["sha256"], "actual": actual,
            })
    return issues


def load_manifest(port: int, day: date) -> dict | None:
    p = manifest_path(port, day)
    if not p.exists():
        return None
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def verify_manifest_hash(manifest: dict) -> bool:
    """True si le champ manifest_sha256 correspond au hash canonique du JSON."""
    claimed = manifest.get("manifest_sha256")
    if not claimed:
        return False
    return _canonical_sha256(manifest) == claimed


def detect_gaps(db: Session, space: Space, days_back: int = 30) -> list[str]:
    """Liste des jours J-N..J-1 (UTC) pour lesquels des logs existent mais
    aucun manifest n'a été produit — utilisé par l'alerte chain_gap."""
    today = datetime.now(timezone.utc).date()
    gaps = []
    for i in range(1, days_back + 1):
        d = today - timedelta(days=i)
        files = list(_iter_log_files(space.port, d))
        if not files:
            continue
        row = (
            db.query(LogChain)
              .filter(LogChain.space_id == space.id, LogChain.day == d.isoformat())
              .first()
        )
        if not row:
            gaps.append(d.isoformat())
    return gaps


def backfill_retroactive(db: Session, space: Space, max_days: int = 365) -> int:
    """Construit rétroactivement les manifests pour les jours couverts par
    les logs actuels (jusqu'à `max_days`). Appelé une fois à l'installation
    de v2.0.0. Les manifests rétroactifs n'ont PAS d'horodatage TSA
    (`tsa_status='skipped_backfill'`) — horodater a posteriori n'aurait pas
    de valeur légale.

    Itère du plus ancien au plus récent pour que chaque manifest puisse
    pointer correctement vers son prédécesseur.

    Retourne le nombre de manifests créés."""
    today = datetime.now(timezone.utc).date()
    created = 0
    # Itération chronologique : J-max_days → J-1 (plus ancien d'abord)
    for i in range(max_days, 0, -1):
        d = today - timedelta(days=i)
        existing = (
            db.query(LogChain)
              .filter(LogChain.space_id == space.id, LogChain.day == d.isoformat())
              .first()
        )
        if existing:
            continue
        files = list(_iter_log_files(space.port, d))
        if not files:
            continue
        row = build_daily_manifest(db, space, d)
        if row:
            row.tsa_status = "skipped_backfill"
            db.commit()
            created += 1
    return created

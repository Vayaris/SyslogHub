"""v2.0.0 — horodatage qualifié RFC3161 (Time-Stamp Protocol).

Soumet le hash SHA-256 du manifest à une TSA publique (défaut : FreeTSA.org,
libre, reconnue) et récupère un token `.tsr` signé qui prouve que le hash
existait à une date donnée. La valeur probante est reconnue par les
tribunaux dès lors que la TSA est fiable.

Défauts :
  - `tsa_enabled` : installation neuve → activé ; upgrade → désactivé
    (l'admin active explicitement après avoir lu les implications).
  - `tsa_url`     : https://freetsa.org/tsr
  - `tsa_ca_path` : /opt/syslog-server/config/tsa/freetsa-ca.pem
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from ..database import SessionLocal
from ..models import LogChain, Setting

log = logging.getLogger("syslog-server")

DEFAULT_TSA_URL = "https://freetsa.org/tsr"
DEFAULT_TSA_CA  = "/opt/syslog-server/config/tsa/freetsa-ca.pem"


def _get_setting(db: Session, key: str, default: str | None = None) -> str | None:
    row = db.query(Setting).filter(Setting.key == key).first()
    return row.value if row else default


def is_enabled() -> bool:
    db = SessionLocal()
    try:
        return (_get_setting(db, "tsa_enabled", "false") or "false") == "true"
    finally:
        db.close()


def set_enabled(enabled: bool) -> None:
    db = SessionLocal()
    try:
        row = db.query(Setting).filter(Setting.key == "tsa_enabled").first()
        val = "true" if enabled else "false"
        if row:
            row.value = val
        else:
            db.add(Setting(key="tsa_enabled", value=val))
        db.commit()
    finally:
        db.close()


def get_config() -> dict:
    """Retourne la config TSA courante (safe pour l'UI)."""
    db = SessionLocal()
    try:
        return {
            "enabled":          (_get_setting(db, "tsa_enabled", "false") or "false") == "true",
            "url":              _get_setting(db, "tsa_url", DEFAULT_TSA_URL),
            "ca_path":          _get_setting(db, "tsa_ca_path", DEFAULT_TSA_CA),
            "retry_max":        int(_get_setting(db, "tsa_retry_max", "3") or "3"),
            "retry_interval_h": int(_get_setting(db, "tsa_retry_interval_hours", "6") or "6"),
        }
    finally:
        db.close()


def timestamp_data(data: bytes, cfg: dict | None = None) -> tuple[bytes | None, str | None, dict | None]:
    """Soumet `data` (typiquement le .json du manifest) à la TSA.

    Approche : construit la TSA-query binaire via `openssl ts -query`, POST
    le binaire (Content-Type: application/timestamp-query), stocke la réponse
    brute. La vérification cryptographique (signature TSR contre la CA) est
    faite séparément via `openssl ts -verify`, soit par le cron de retry,
    soit par `verify.sh` dans le bundle de réquisition — donc on n'essaie pas
    de la faire ici (rfc3161ng 2.1.3 a un bug connu avec les clés ECDSA
    modernes — cf. cryptography ≥ 41).

    Retourne (tsr_bytes, error, info)."""
    import subprocess
    import tempfile

    cfg = cfg or get_config()
    url = cfg.get("url") or DEFAULT_TSA_URL

    try:
        # 1. Construire la requête TSA (TSQ) via openssl
        with tempfile.NamedTemporaryFile(suffix=".data", delete=False) as tf_data, \
             tempfile.NamedTemporaryFile(suffix=".tsq", delete=False) as tf_tsq:
            data_path = tf_data.name
            tsq_path  = tf_tsq.name
            tf_data.write(data)
            tf_data.flush()
        proc = subprocess.run(
            ["openssl", "ts", "-query",
             "-data", data_path,
             "-sha256",
             "-cert",       # demande à la TSA d'inclure son cert
             "-no_nonce",
             "-out", tsq_path],
            capture_output=True, text=True, timeout=15,
        )
        if proc.returncode != 0:
            return None, f"openssl ts -query: {proc.stderr.strip()[:300]}", None

        with open(tsq_path, "rb") as f:
            tsq_bytes = f.read()

        # 2. POST à la TSA
        import requests as _req
        r = _req.post(
            url,
            data=tsq_bytes,
            headers={"Content-Type": "application/timestamp-query"},
            timeout=20,
        )
        if r.status_code != 200:
            return None, f"TSA HTTP {r.status_code}", None

        tsr_bytes = r.content
        if not tsr_bytes or len(tsr_bytes) < 64:
            return None, "TSR vide ou trop court", None

        # 3. Extraire metadata via openssl ts -reply -in <tsr> -text
        info = {"url": url, "gen_time": None, "serial": None}
        with tempfile.NamedTemporaryFile(suffix=".tsr", delete=False) as tf_tsr:
            tsr_path = tf_tsr.name
            tf_tsr.write(tsr_bytes)
            tf_tsr.flush()
        try:
            rep = subprocess.run(
                ["openssl", "ts", "-reply", "-in", tsr_path, "-text"],
                capture_output=True, text=True, timeout=10,
            )
            if rep.returncode == 0:
                for line in rep.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("Time stamp:"):
                        # "Time stamp: Apr 24 15:55:01 2026 GMT"
                        info["gen_time"] = line.split(":", 1)[1].strip()
                    elif line.startswith("Serial number:"):
                        info["serial"] = line.split(":", 1)[1].strip()
        finally:
            Path(tsr_path).unlink(missing_ok=True)

        Path(data_path).unlink(missing_ok=True)
        Path(tsq_path).unlink(missing_ok=True)
        return tsr_bytes, None, info

    except subprocess.TimeoutExpired:
        return None, "openssl ts timeout", None
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"[:500], None


def timestamp_manifest(db: Session, row: LogChain) -> bool:
    """Soumet le manifest_sha256 à la TSA et met à jour la ligne log_chain.

    Retourne True en cas de succès, False sinon. Safe à rejouer :
    incrémente tsa_attempts à chaque essai, ne touche pas à l'état si déjà
    'ok', et tolère les disparitions de fichier."""
    if row.tsa_status == "ok":
        return True
    if row.tsa_status == "skipped_backfill":
        return True   # pas d'horodatage rétroactif — on considère comme "done"

    cfg = get_config()
    if not cfg["enabled"]:
        row.tsa_last_error = "tsa_disabled"
        db.commit()
        return False

    manifest_path = Path(row.manifest_path)
    if not manifest_path.exists():
        row.tsa_status = "failed"
        row.tsa_last_error = f"manifest manquant : {manifest_path}"
        row.tsa_attempts += 1
        db.commit()
        return False

    with open(manifest_path, "rb") as f:
        data = f.read()

    tsr, err, info = timestamp_data(data, cfg)
    row.tsa_attempts += 1

    if err or not tsr:
        row.tsa_status = "failed"
        row.tsa_last_error = err or "tsr vide"
        db.commit()
        log.warning(f"TSA échec space={row.space_id} day={row.day} : {row.tsa_last_error}")
        return False

    tsr_out = manifest_path.with_suffix(".tsr")
    with open(tsr_out, "wb") as f:
        f.write(tsr)
    try:
        os.chmod(str(tsr_out), 0o640)
    except OSError:
        pass

    row.tsa_status       = "ok"
    row.tsa_receipt_path = str(tsr_out)
    row.tsa_serial       = (info or {}).get("serial")
    row.tsa_url          = (info or {}).get("url")
    row.tsa_gen_time     = (info or {}).get("gen_time") or datetime.now(timezone.utc).isoformat()
    row.tsa_last_error   = None
    db.commit()
    log.info(f"TSA OK space={row.space_id} day={row.day} serial={row.tsa_serial}")
    return True


def retry_failed(db: Session) -> tuple[int, int]:
    """Rejoue l'horodatage pour toutes les lignes `failed` dont le compteur
    d'essais est < retry_max. Retourne (rejouées, réussies)."""
    cfg = get_config()
    max_attempts = cfg["retry_max"]
    rows = (
        db.query(LogChain)
          .filter(LogChain.tsa_status == "failed",
                  LogChain.tsa_attempts < max_attempts)
          .all()
    )
    retried = 0
    ok = 0
    for r in rows:
        retried += 1
        if timestamp_manifest(db, r):
            ok += 1
    return retried, ok

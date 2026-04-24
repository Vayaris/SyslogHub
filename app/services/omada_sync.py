"""v2.0.0 — sync des sessions clients Omada pour la corrélation identité.

Pull depuis l'API Omada OpenAPI toutes les ~5 min : pour chaque space avec
`omada_sync_enabled=1`, récupère la liste des clients actifs + (si
disponible) l'historique. Upsert dans `omada_sessions`.

Stratégie fallback : l'endpoint "insight" n'est pas garanti sur toutes les
versions. Si absent, on reconstruit le journal à partir du snapshot :
  - Snapshot 1 : client X connecté depuis t0 → insert nouveau si absent
  - Snapshot 2 : X toujours là → update le session_end (= now)
  - Snapshot 3 : X parti → session fermée (session_end = last_seen)
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from ..models import OmadaSession, Space
from . import omada as omada_svc

log = logging.getLogger("syslog-server")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sync_space(db: Session, space: Space) -> tuple[int, int]:
    """Pull les clients actifs et upsert les sessions. Retourne (pulled, upserted)."""
    client = omada_svc.get_client_for_space(space)
    if client is None:
        return 0, 0

    clients = _fetch_active_clients(client)
    if not clients:
        # Si aucune réponse, on ne "ferme" pas les sessions existantes — il se
        # peut que le controller soit momentanément injoignable. Fermeture
        # seulement si la réponse est explicitement vide ET qu'on a eu une
        # vraie connexion (HTTP 200). Le client lib lève sur les erreurs, donc
        # arriver ici avec [] = vraiment personne.
        pass

    upserted = 0
    seen_macs = set()
    now = _now()

    for c in clients:
        mac = (c.get("mac") or "").replace("-", ":").lower()
        if not mac or len(mac) < 12:
            continue
        ip = c.get("ip") or None
        identifier = _extract_identifier(c)
        ap_mac = (c.get("apMac") or c.get("ap") or "").replace("-", ":").lower() or None
        ssid = c.get("ssid") or None
        uploaded = c.get("trafficUp") or c.get("uploadBytes") or 0
        downloaded = c.get("trafficDown") or c.get("downloadBytes") or 0

        # connectTimestamp / lastSeen en ms
        connect_ts = c.get("connectTime") or c.get("lastSeen") or c.get("connectTimestamp")
        if connect_ts and connect_ts > 10**12:
            session_start = datetime.fromtimestamp(connect_ts / 1000, tz=timezone.utc).isoformat()
        elif connect_ts:
            session_start = datetime.fromtimestamp(connect_ts, tz=timezone.utc).isoformat()
        else:
            session_start = now

        existing = (
            db.query(OmadaSession)
              .filter(OmadaSession.space_id == space.id,
                      OmadaSession.client_mac == mac,
                      OmadaSession.session_start == session_start)
              .first()
        )
        if existing:
            existing.session_end = now     # toujours actif = bump le last_seen
            existing.client_ip = ip or existing.client_ip
            existing.ssid = ssid or existing.ssid
            existing.identifier = identifier or existing.identifier
            existing.ap_mac = ap_mac or existing.ap_mac
            existing.uploaded_bytes = uploaded
            existing.downloaded_bytes = downloaded
            existing.pulled_at = now
        else:
            row = OmadaSession(
                space_id     = space.id,
                client_mac   = mac,
                client_ip    = ip,
                identifier   = identifier,
                ap_mac       = ap_mac,
                ssid         = ssid,
                session_start= session_start,
                session_end  = now,     # provisoire — bumped au prochain pull
                uploaded_bytes   = uploaded,
                downloaded_bytes = downloaded,
                pulled_at    = now,
            )
            db.add(row)
            upserted += 1
        seen_macs.add(mac)

    # Commit : on ferme pas les sessions absentes ici — c'est le rôle du
    # pull suivant qui verra le client disparaître et saura le figer.
    db.commit()
    return len(clients), upserted


def _fetch_active_clients(client) -> list[dict]:
    """Try different Omada endpoints for the active client list. The precise
    path varies slightly by controller version ; we try known variants."""
    candidates = ["/clients", "/insight/clients", "/client/active"]
    for path in candidates:
        try:
            result = client._get(path, params={"page": 1, "pageSize": 500})
            if isinstance(result, dict):
                data = result.get("data") or result.get("clients") or []
                if data:
                    return data
            elif isinstance(result, list) and result:
                return result
        except Exception as e:
            log.debug(f"Omada {path} failed: {e}")
            continue
    return []


def _extract_identifier(c: dict) -> Optional[str]:
    """L'identifiant d'un client hotspot varie selon le mode d'auth :
    email pour portail captif email, numéro pour SMS, code voucher, etc.
    On essaie les champs les plus courants."""
    for key in ("hotspotUser", "portalUser", "email", "user", "userName", "phone"):
        v = c.get(key)
        if v:
            return str(v)
    return None


def lookup(
    db: Session,
    space_id: int | None,
    ip: str | None,
    at_ts: datetime,
    window_minutes: int = 30,
) -> list[OmadaSession]:
    """Cherche les sessions Omada qui CHEVAUCHENT la fenêtre [at - w, at + w]."""
    from datetime import timedelta
    lo = (at_ts - timedelta(minutes=window_minutes)).isoformat()
    hi = (at_ts + timedelta(minutes=window_minutes)).isoformat()
    q = db.query(OmadaSession).filter(
        OmadaSession.session_start <= hi,
        # session_end >= lo OR session_end is NULL
        (OmadaSession.session_end == None) | (OmadaSession.session_end >= lo),  # noqa: E711
    )
    if space_id is not None:
        q = q.filter(OmadaSession.space_id == space_id)
    if ip:
        q = q.filter(OmadaSession.client_ip == ip)
    return q.all()

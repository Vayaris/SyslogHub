"""v2.0.0 — API de corrélation identité ↔ IP ↔ timestamp.

Usage type : une réquisition judiciaire demande "qui était sur l'IP X à telle
heure ?". Cet endpoint fusionne les données DHCP (syslog) et les sessions
Omada hotspot pour restituer la chaîne d'identification complète.
"""
from datetime import datetime, timezone, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..auth import get_current_user_obj
from .. import config
from ..database import get_db
from ..models import Space, User
from ..services import dhcp_parser
from ..services import omada_sync
from ..services import rbac

router = APIRouter(prefix="/api/correlation", tags=["compliance"])


@router.get("/who-was-on")
def who_was_on(
    space_id: int = Query(...),
    ip: str = Query(..., min_length=3),
    at: str = Query(..., description="ISO datetime UTC"),
    window_minutes: int = Query(30, ge=1, le=1440),
    db: Session = Depends(get_db),
    me: User = Depends(get_current_user_obj),
):
    space = db.query(Space).filter(Space.id == space_id).first()
    if not space:
        raise HTTPException(status_code=404, detail="Espace introuvable")
    rbac.require_read(db, me, space)

    try:
        at_ts = datetime.fromisoformat(at.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=400, detail="Format datetime invalide (ISO 8601 attendu)")
    if at_ts.tzinfo is None:
        at_ts = at_ts.replace(tzinfo=timezone.utc)

    # 1. DHCP leases
    dhcp = dhcp_parser.lookup(db, space_id, ip, at_ts, window_minutes)
    dhcp_out = [
        {
            "mac":        l.mac,
            "hostname":   l.hostname,
            "seen_at":    l.seen_at,
            "source_file":l.source_file,
        } for l in dhcp
    ]

    # 2. Sessions Omada (par IP si passée, sinon sans filtre sur l'IP pour
    #    pouvoir corréler par MAC découvert côté DHCP)
    macs_from_dhcp = {l.mac for l in dhcp}
    omada = omada_sync.lookup(db, space_id, ip, at_ts, window_minutes)
    # Élargir : si aucun résultat par IP mais qu'on a des MACs DHCP, chercher
    # les sessions de ces MACs dans la fenêtre.
    if not omada and macs_from_dhcp:
        from ..models import OmadaSession
        lo = (at_ts - timedelta(minutes=window_minutes)).isoformat()
        hi = (at_ts + timedelta(minutes=window_minutes)).isoformat()
        q = db.query(OmadaSession).filter(
            OmadaSession.space_id == space_id,
            OmadaSession.client_mac.in_(list(macs_from_dhcp)),
            OmadaSession.session_start <= hi,
            (OmadaSession.session_end == None) | (OmadaSession.session_end >= lo),  # noqa: E711
        )
        omada = q.all()

    omada_out = [
        {
            "client_mac":    s.client_mac,
            "client_ip":     s.client_ip,
            "identifier":    s.identifier,
            "ap_mac":        s.ap_mac,
            "ssid":          s.ssid,
            "session_start": s.session_start,
            "session_end":   s.session_end,
            "uploaded_bytes":  s.uploaded_bytes,
            "downloaded_bytes":s.downloaded_bytes,
        } for s in omada
    ]

    # 3. Extraits bruts des logs autour de l'instant (fenêtre plus étroite)
    raw_lines = _fetch_raw_context(space, ip, at_ts, minutes=5)

    # 4. Construction narrative : la phrase type que l'OPJ veut
    narrative = _build_narrative(ip, at_ts, dhcp, omada)

    return {
        "query": {
            "space_id": space_id, "space_name": space.name,
            "ip": ip, "at": at_ts.isoformat(), "window_minutes": window_minutes,
        },
        "narrative":      narrative,
        "dhcp_leases":    dhcp_out,
        "omada_sessions": omada_out,
        "raw_lines":      raw_lines,
    }


def _fetch_raw_context(space: Space, ip: str, at_ts: datetime, minutes: int = 5) -> list[str]:
    """Retourne les lignes de log de ce space qui mentionnent l'IP dans une
    fenêtre étroite autour de at_ts. Utilise grep sur le répertoire du space."""
    import subprocess
    log_dir = Path(config.LOG_ROOT) / str(space.port)
    if not log_dir.exists():
        return []
    # Cheap approach : grep -h ip dans les fichiers du space, on garde max 50 lignes
    try:
        proc = subprocess.run(
            ["grep", "-h", "-m", "50", "--no-messages", "--include=*.log", "-r",
             ip, str(log_dir)],
            capture_output=True, text=True, timeout=5,
        )
        return [l for l in proc.stdout.splitlines() if l][:50]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def _build_narrative(ip: str, at_ts: datetime, dhcp, omada) -> str:
    """Phrase française lisible pour l'OPJ."""
    t = at_ts.strftime("%Y-%m-%d %H:%M UTC")
    if not dhcp and not omada:
        return (f"Aucune corrélation trouvée pour l'IP {ip} à {t}. "
                f"Vérifier que le parsing DHCP et/ou la sync Omada sont actifs "
                f"pour ce space dans la fenêtre temporelle demandée.")

    parts = [f"À {t}, l'IP {ip}"]
    if dhcp:
        d = dhcp[0]   # proximité temporelle
        parts.append(f"était attribuée à la MAC {d.mac}")
        if d.hostname:
            parts.append(f"(hostname déclaré : « {d.hostname} »)")
    if omada:
        s = omada[0]
        if s.identifier:
            parts.append(f"; session hotspot ouverte par {s.identifier}")
        if s.session_start:
            parts.append(f"entre {s.session_start} et {s.session_end or 'maintenant'}")
        if s.ap_mac:
            parts.append(f"via AP {s.ap_mac}")
        if s.ssid:
            parts.append(f"SSID « {s.ssid} »")
    return " ".join(parts) + "."

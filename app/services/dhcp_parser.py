"""v2.0.0 — parseur DHCP pour la corrélation identité RGPD.

Les réquisitions judiciaires pour WiFi public demandent toujours la même
chose : « qui était sur l'IP X à tel moment ». La réponse passe par la
corrélation DHCP lease (MAC ↔ IP ↔ plage horaire). Ce parseur extrait les
lignes DHCPACK des logs syslog entrants, quel que soit le firmware source
(ISC dhcpd, dnsmasq, Mikrotik, pfSense, Cisco, OpenWRT).

Utilisé par `scripts/dhcp_sweep.py` (cron nightly, idempotent via UNIQUE).
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from sqlalchemy.orm import Session

from ..models import DhcpLease, Space

log = logging.getLogger("syslog-server")


# Les patterns sont évalués dans l'ordre — dès qu'un match réussit, la ligne
# est traitée. Ordre = du plus courant au moins courant.
_DHCP_PATTERNS = [
    # ISC dhcpd 4.x / dnsmasq / OpenWRT :
    # "dhcpd: DHCPACK on 10.0.0.42 to aa:bb:cc:dd:ee:ff (iPhone-de-Tristan) via eth0"
    # "dnsmasq: DHCPACK(br-lan) 10.1.1.5 aa:bb:cc:dd:ee:ff hostname"
    re.compile(
        r'DHCPACK(?:\([^)]*\))?\s+(?:on\s+|to\s+)?'
        r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?:to\s+)?'
        r'(?P<mac>[\da-fA-F][\da-fA-F](?:[:-][\da-fA-F]{2}){5})'
        r'(?:\s+\((?P<hostname>[^)]+)\)|\s+(?P<hostname2>[\w.-]{2,}))?',
        re.I,
    ),
    # Mikrotik RouterOS :
    # "dhcp,info assigned 192.168.1.42 for aa:bb:cc:dd:ee:ff"
    re.compile(
        r'dhcp\S*\s+assigned\s+'
        r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+'
        r'(?:for|to)\s+(?P<mac>[\da-fA-F][\da-fA-F](?:[:-][\da-fA-F]{2}){5})',
        re.I,
    ),
    # pfSense / OPNsense (dhcpd-leases) :
    # "DHCPACK on 192.168.1.42 to aa:bb:cc:dd:ee:ff (hostname)"
    # Couvert par le premier pattern, mais garde un fallback explicite :
    re.compile(
        r'DHCPACK\s+on\s+'
        r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+to\s+'
        r'(?P<mac>[\da-fA-F][\da-fA-F](?:[:-][\da-fA-F]{2}){5})'
        r'(?:\s+\((?P<hostname>\S+)\))?',
        re.I,
    ),
    # Cisco IOS DHCP :
    # "DHCPD: assigned IP address 10.1.1.10 to client 0100.5e00.0001"
    re.compile(
        r'DHCPD:?\s*assigned IP address\s+'
        r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+to client.*?'
        r'(?:MAC|Hardware\s+address)\s+(?P<mac>[\da-fA-F.:-]{12,17})',
        re.I,
    ),
]

# Heuristique d'extraction du timestamp syslog RFC3164 : "Apr 24 15:30:12 ..."
_SYSLOG_TS_RE = re.compile(
    r'^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
)


def _norm_mac(mac: str) -> str:
    """Format canonique : aa:bb:cc:dd:ee:ff (lowercase, colon-separated)."""
    raw = re.sub(r'[:\-.]', '', mac).lower()
    if len(raw) != 12:
        return mac.lower()
    return ":".join(raw[i:i+2] for i in range(0, 12, 2))


def parse_line(line: str, now: datetime | None = None) -> dict | None:
    """Extrait (mac, ip, hostname, seen_at) d'une ligne syslog, ou None."""
    for pat in _DHCP_PATTERNS:
        m = pat.search(line)
        if not m:
            continue
        d = m.groupdict()
        mac = _norm_mac(d.get("mac", ""))
        ip  = d.get("ip", "")
        if not mac or not ip:
            continue
        hostname = (d.get("hostname") or d.get("hostname2") or "").strip() or None

        # Date : si RFC3164 prefix présent, l'utiliser (année = celle du now)
        ts_match = _SYSLOG_TS_RE.match(line)
        seen_at = now or datetime.now(timezone.utc)
        if ts_match:
            try:
                now_y = seen_at.year
                dt = datetime.strptime(
                    f"{now_y} {ts_match.group('ts')}",
                    "%Y %b %d %H:%M:%S",
                ).replace(tzinfo=timezone.utc)
                # Heuristique : si la date tombe dans le futur, c'est que les
                # logs sont de l'année précédente.
                if dt > seen_at:
                    dt = dt.replace(year=now_y - 1)
                seen_at = dt
            except ValueError:
                pass

        return {"mac": mac, "ip": ip, "hostname": hostname, "seen_at": seen_at.isoformat()}
    return None


def sweep_file(db: Session, space: Space, path: Path) -> int:
    """Parse un fichier log et upsert les leases trouvés. Retourne le nombre
    de nouvelles lignes insérées (les doublons via UNIQUE sont comptés 0)."""
    opener = None
    if path.suffix == ".gz":
        import gzip
        opener = lambda p: gzip.open(p, "rt", errors="replace")
    else:
        opener = lambda p: open(p, "r", errors="replace")

    inserted = 0
    batch = []
    try:
        with opener(path) as fh:
            for raw in fh:
                hit = parse_line(raw)
                if not hit:
                    continue
                batch.append({**hit, "source_file": path.name})
                if len(batch) >= 100:
                    inserted += _flush(db, space.id, batch)
                    batch = []
            if batch:
                inserted += _flush(db, space.id, batch)
    except OSError as e:
        log.warning(f"dhcp_parser: cannot read {path}: {e}")
    return inserted


def _flush(db: Session, space_id: int, batch: list[dict]) -> int:
    """Insert ignore (UNIQUE sur space_id, mac, ip, seen_at)."""
    inserted = 0
    for item in batch:
        lease = DhcpLease(
            space_id   = space_id,
            mac        = item["mac"],
            ip         = item["ip"],
            hostname   = item.get("hostname"),
            seen_at    = item["seen_at"],
            source_file= item.get("source_file"),
        )
        db.add(lease)
        try:
            db.commit()
            inserted += 1
        except Exception:
            db.rollback()   # doublon UNIQUE — on ignore
    return inserted


def lookup(
    db: Session,
    space_id: int | None,
    ip: str,
    at_ts: datetime,
    window_minutes: int = 30,
) -> list[DhcpLease]:
    """Cherche les leases de cette IP dans la fenêtre [at - w, at + w].

    Retourne les leases triées par proximité de seen_at à at_ts."""
    from datetime import timedelta
    lo = (at_ts - timedelta(minutes=window_minutes)).isoformat()
    hi = (at_ts + timedelta(minutes=window_minutes)).isoformat()
    q = db.query(DhcpLease).filter(
        DhcpLease.ip == ip,
        DhcpLease.seen_at >= lo,
        DhcpLease.seen_at <= hi,
    )
    if space_id is not None:
        q = q.filter(DhcpLease.space_id == space_id)
    rows = q.all()
    # Tri : proximité de `at_ts`
    rows.sort(key=lambda r: abs(
        (datetime.fromisoformat(r.seen_at) - at_ts).total_seconds()
    ))
    return rows

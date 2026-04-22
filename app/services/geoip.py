"""GeoIP country + rDNS lookups for public IPs.

The MaxMind reader is opened lazily and cached process-wide. If the mmdb
file is missing (download failed or GeoIP not yet installed), lookups
silently return None — no crash.

rDNS uses socket.gethostbyaddr with a per-call timeout + an in-memory
TTL cache so that repeat lookups within an hour are free. Lookups against
RFC1918 / link-local / loopback addresses are skipped.
"""
import ipaddress
import logging
import socket
import time
from pathlib import Path
from typing import Optional

log = logging.getLogger("syslog-server")

MMDB_PATH = Path("/opt/syslog-server/data/dbip-country-lite.mmdb")

_reader = None
_reader_failed = False

# ip -> (name_or_None, inserted_at_epoch_seconds)
_rdns_cache: dict[str, tuple[Optional[str], float]] = {}
_RDNS_TTL = 3600.0  # 1 h


def _get_reader():
    """Lazily open the mmdb reader. Returns None if unavailable."""
    global _reader, _reader_failed
    if _reader is not None:
        return _reader
    if _reader_failed:
        return None
    if not MMDB_PATH.exists():
        _reader_failed = True
        return None
    try:
        import maxminddb
        _reader = maxminddb.open_database(str(MMDB_PATH))
        return _reader
    except Exception as e:
        log.warning(f"geoip: failed to open {MMDB_PATH}: {e}")
        _reader_failed = True
        return None


def _is_public(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified
    )


def country(ip: str) -> Optional[str]:
    """Return an ISO-3166 country code (e.g. "FR") or None."""
    if not _is_public(ip):
        return None
    reader = _get_reader()
    if reader is None:
        return None
    try:
        row = reader.get(ip)
    except Exception:
        return None
    if not row:
        return None
    c = row.get("country") or {}
    return c.get("iso_code") or None


def rdns(ip: str, timeout: float = 0.5) -> Optional[str]:
    """Reverse DNS for a public IP, with a 1-hour in-memory cache.

    Returns None on private IPs, lookup failure, or timeout."""
    if not _is_public(ip):
        return None

    now = time.time()
    cached = _rdns_cache.get(ip)
    if cached and (now - cached[1]) < _RDNS_TTL:
        return cached[0]

    # Temporarily lower the default socket timeout just for this call. The
    # stdlib doesn't expose a per-call timeout on gethostbyaddr.
    prev = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        host, _, _ = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        host = None
    except Exception:
        host = None
    finally:
        socket.setdefaulttimeout(prev)

    _rdns_cache[ip] = (host, now)
    return host

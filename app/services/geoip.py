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
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Optional

log = logging.getLogger("syslog-server")

MMDB_PATH = Path("/opt/syslog-server/data/dbip-country-lite.mmdb")

_reader = None
_reader_failed = False

# ip -> (name_or_None, inserted_at_epoch_seconds). Bounded LRU — UDP syslog
# sources are spoofable, so an unbounded dict is an open memory-growth vector.
_RDNS_MAX = 2000
_RDNS_TTL = 3600.0  # 1 h
_rdns_cache: "OrderedDict[str, tuple[Optional[str], float]]" = OrderedDict()
_rdns_lock = threading.Lock()


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


_rdns_default_timeout_set = False


def _ensure_default_timeout(timeout: float) -> None:
    """Set the process-wide default socket timeout exactly once, so every
    blocking name-resolution call has a bounded wall time. Previously we
    toggled the global around each call — which races in the threadpool and
    can leave other threads with the wrong timeout (or no timeout at all)."""
    global _rdns_default_timeout_set
    if _rdns_default_timeout_set:
        return
    with _rdns_lock:
        if _rdns_default_timeout_set:
            return
        if socket.getdefaulttimeout() is None:
            socket.setdefaulttimeout(timeout)
        _rdns_default_timeout_set = True


def rdns(ip: str, timeout: float = 0.5) -> Optional[str]:
    """Reverse DNS for a public IP, with a 1-hour bounded-LRU cache.

    Returns None on private IPs, lookup failure, or timeout."""
    if not _is_public(ip):
        return None

    now = time.time()
    with _rdns_lock:
        cached = _rdns_cache.get(ip)
        if cached and (now - cached[1]) < _RDNS_TTL:
            _rdns_cache.move_to_end(ip)
            return cached[0]

    _ensure_default_timeout(timeout)
    try:
        host, _, _ = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        host = None
    except Exception:
        host = None

    with _rdns_lock:
        _rdns_cache[ip] = (host, now)
        _rdns_cache.move_to_end(ip)
        while len(_rdns_cache) > _RDNS_MAX:
            _rdns_cache.popitem(last=False)
    return host

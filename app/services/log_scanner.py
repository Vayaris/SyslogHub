import asyncio
import gzip
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from .. import config

_AP_MAC_RE = re.compile(r'AP MAC=([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})')

# Filenames starting with "_" are reserved (e.g. "_all.log" for LAN-mode unified
# log). Per-IP scans must skip them since they aren't tied to a source IP.
_RESERVED_PREFIX = "_"


def _merged_log_path(port: int):
    return Path(config.LOG_ROOT) / str(port) / "_all.log"


def extract_ap_mac(line: str) -> str | None:
    """Extract AP MAC address from a log line. Returns None if not present."""
    m = _AP_MAC_RE.search(line)
    return m.group(1) if m else None


def list_ap_macs(port: int) -> list[str]:
    """Scan all log files (active + rotated) in the space, return sorted unique AP MACs."""
    log_dir = Path(config.LOG_ROOT) / str(port)
    macs: set[str] = set()
    if not log_dir.exists():
        return []
    try:
        files = [f for f in log_dir.iterdir() if f.is_file()]
    except PermissionError:
        return []
    for f in files:
        if f.name.startswith(_RESERVED_PREFIX):
            continue
        try:
            if f.suffix == ".gz":
                import gzip as _gz
                with _gz.open(f, "rt", errors="replace") as fh:
                    for line in fh:
                        mac = extract_ap_mac(line)
                        if mac:
                            macs.add(mac)
            else:
                with open(f, "r", errors="replace") as fh:
                    for line in fh:
                        mac = extract_ap_mac(line)
                        if mac:
                            macs.add(mac)
        except OSError:
            pass
    return sorted(macs)


def _format_dt(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _ip_to_filename(ip: str) -> str:
    """Encode IPv6 colons to dashes for filesystem safety."""
    return ip.replace(":", "-")


def _filename_to_ip(name: str) -> str:
    """Reverse: restore IPv6 colons. Only for names that look like encoded IPv6."""
    # Heuristic: if name has dashes in IPv6 positions, try to restore
    # Simple approach: stored as-is on Linux (ext4 allows colons), but
    # we also handle dash-encoded variants for compatibility.
    return name


def get_space_stats(port: int) -> dict:
    log_dir = Path(config.LOG_ROOT) / str(port)
    if not log_dir.exists():
        return {"source_count": 0, "total_size_bytes": 0, "last_seen": None}

    sources = set()
    total_size = 0
    last_mtime = 0.0

    try:
        entries = list(log_dir.iterdir())
    except PermissionError:
        entries = []

    for f in entries:
        if not f.is_file():
            continue
        if f.name.startswith(_RESERVED_PREFIX):
            continue
        stat = f.stat()
        total_size += stat.st_size
        if stat.st_mtime > last_mtime:
            last_mtime = stat.st_mtime
        name = f.name
        if name.endswith(".log"):
            sources.add(name[:-4])
        elif ".log." in name:
            sources.add(name.split(".log.")[0])

    return {
        "source_count": len(sources),
        "total_size_bytes": total_size,
        "last_seen": _format_dt(last_mtime) if last_mtime else None,
    }


def first_ap_mac_in(path: Path, max_lines: int = 200) -> str | None:
    """Scan the last `max_lines` of an active log file for an `AP MAC=` tag.
    Returns the first MAC found (not necessarily chronologically earliest),
    used as a fallback when Omada IP lookup fails."""
    if not path.exists() or path.name.endswith(".gz"):
        return None
    try:
        raw = _tail_file(path, max_lines)
    except OSError:
        return None
    for line in raw:
        mac = extract_ap_mac(line.decode("utf-8", errors="replace"))
        if mac:
            return mac
    return None


def list_sources(port: int) -> list[dict]:
    log_dir = Path(config.LOG_ROOT) / str(port)
    if not log_dir.exists():
        return []

    sources: dict[str, dict] = {}
    for f in log_dir.iterdir():
        if not f.is_file():
            continue
        if f.name.startswith(_RESERVED_PREFIX):
            continue
        name = f.name
        if name.endswith(".log"):
            ip = name[:-4]
        elif ".log." in name:
            ip = name.split(".log.")[0]
        else:
            continue

        stat = f.stat()
        if ip not in sources:
            sources[ip] = {
                "ip": ip,
                "filename": name,
                "size_bytes": stat.st_size,
                "line_count": _estimate_lines(f),
                "last_modified": _format_dt(stat.st_mtime),
            }
        else:
            existing_mtime = datetime.fromisoformat(
                sources[ip]["last_modified"]
            ).timestamp()
            if stat.st_mtime > existing_mtime:
                sources[ip]["filename"] = name
                sources[ip]["last_modified"] = _format_dt(stat.st_mtime)
            sources[ip]["size_bytes"] += stat.st_size

    return sorted(sources.values(), key=lambda x: x["last_modified"], reverse=True)


def list_files(port: int, ip: str) -> list[dict]:
    log_dir = Path(config.LOG_ROOT) / str(port)
    if not log_dir.exists():
        return []

    results = []
    # Match both direct IP and dash-encoded IPv6
    encoded_ip = _ip_to_filename(ip)
    prefixes = {ip + ".log", encoded_ip + ".log"}

    for f in log_dir.iterdir():
        if not f.is_file():
            continue
        if f.name.startswith(_RESERVED_PREFIX):
            continue
        name = f.name
        # Match exact .log or rotated variants (.log.1, .log.2.gz, etc.)
        is_match = any(
            name == p or name.startswith(p + ".") or name.startswith(p[:-4] + ".log.")
            for p in prefixes
        ) or name == ip + ".log" or name.startswith(ip + ".log.")
        if not is_match:
            continue
        stat = f.stat()
        is_rotated = not (name == ip + ".log" or name == encoded_ip + ".log")
        results.append({
            "filename": name,
            "size_bytes": stat.st_size,
            "last_modified": _format_dt(stat.st_mtime),
            "is_rotated": is_rotated,
        })

    return sorted(results, key=lambda x: x["filename"])


def _estimate_lines(path: Path) -> int:
    # Use wc -l for accuracy on accessible files
    try:
        result = subprocess.run(
            ["wc", "-l", str(path)],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return int(result.stdout.strip().split()[0])
    except Exception:
        pass
    # Fallback: sample-based estimation
    try:
        size = path.stat().st_size
        if size == 0:
            return 0
        with open(path, "rb") as f:
            sample = f.read(8192)
        newlines = sample.count(b"\n")
        if newlines == 0:
            return 1
        avg_line = len(sample) / newlines
        return max(1, int(size / avg_line))
    except OSError:
        return 0


def _tail_file(path: Path, max_lines: int) -> list[bytes]:
    """Read last max_lines lines efficiently using reverse seek — no full file load."""
    CHUNK = 1 << 16  # 64 KB
    with open(path, "rb") as f:
        f.seek(0, 2)
        size = f.tell()
        if size == 0:
            return []
        buf = b""
        pos = size
        while pos > 0:
            read_size = min(CHUNK, pos)
            pos -= read_size
            f.seek(pos)
            buf = f.read(read_size) + buf
            lines = buf.split(b"\n")
            # Keep an extra line at the front as it may be partial
            if len(lines) > max_lines + 1:
                buf = b"\n".join(lines[-(max_lines + 1):])
                break
    lines = buf.split(b"\n")
    # Remove empty trailing line from final newline
    if lines and lines[-1] == b"":
        lines = lines[:-1]
    return lines[-max_lines:] if max_lines else lines


def read_log_tail(
    path: Path, lines: int = 100, offset: int = 0,
    filter_str: str = "", ap_mac_filter: str = ""
) -> dict:
    try:
        is_gz = str(path).endswith(".gz")

        if is_gz:
            # Stream-decompress and keep only the last N lines in a bounded
            # deque. A rotated .gz can decompress to multiple GB — loading
            # the full file with readlines() would OOM a small VM.
            from collections import deque
            keep = max(lines + offset + 1000, 5000)
            buf: deque[str] = deque(maxlen=keep)
            total = 0
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
                for line in f:
                    buf.append(line.rstrip("\n"))
                    total += 1
            raw_lines = list(buf)
        else:
            raw_bytes = _tail_file(path, max_lines=max(lines + offset + 1000, 5000))
            raw_lines = [l.decode("utf-8", errors="replace") for l in raw_bytes]
            total = _estimate_lines(path)

        if ap_mac_filter:
            raw_lines = [l for l in raw_lines if ap_mac_filter.lower() in l.lower()]

        if filter_str:
            fl = filter_str.lower()
            raw_lines = [l for l in raw_lines if fl in l.lower()]

        # Reverse pagination from end: offset=0 → last `lines` lines
        end = max(0, len(raw_lines) - offset)
        start = max(0, end - lines)
        page = raw_lines[start:end]

        return {
            "lines": page,
            "total_lines": total,
            "has_more": start > 0,
        }
    except OSError:
        return {"lines": [], "total_lines": 0, "has_more": False}


def total_log_size() -> int:
    log_root = Path(config.LOG_ROOT)
    if not log_root.exists():
        return 0
    total = 0
    for f in log_root.rglob("*"):
        if f.is_file():
            try:
                total += f.stat().st_size
            except OSError:
                pass
    return total


def volume_by_day(days: int = 7) -> list[dict]:
    """Return per-day log volume for the last N days."""
    from collections import defaultdict
    from datetime import date, timedelta

    log_root = Path(config.LOG_ROOT)
    today = date.today()
    buckets: dict[str, int] = defaultdict(int)

    # Pre-fill all days with 0
    for i in range(days):
        d = (today - timedelta(days=days - 1 - i)).isoformat()
        buckets[d] = 0

    if log_root.exists():
        for f in log_root.rglob("*"):
            if not f.is_file():
                continue
            try:
                mtime_date = datetime.fromtimestamp(
                    f.stat().st_mtime, tz=timezone.utc
                ).date().isoformat()
                if mtime_date in buckets:
                    buckets[mtime_date] += f.stat().st_size
            except OSError:
                pass

    return [{"date": d, "bytes": buckets[d]} for d in sorted(buckets)]


def files_in_date_range(port: int, ip: str,
                        start_ts: float, end_ts: float) -> list[Path]:
    """
    Return rotated + active log files for {ip} whose content overlaps
    [start_ts, end_ts]. With daily rotation, a file's mtime marks the
    last write before it was rotated, so its content sits within the
    same day as its mtime. We accept a one-day buffer on each side to
    cover mid-day rotations and slight boundary drift.
    """
    log_dir = Path(config.LOG_ROOT) / str(port)
    if not log_dir.exists():
        return []
    lo = start_ts - 86400
    hi = end_ts + 86400
    entries = [
        (f, f.stat().st_mtime)
        for f in log_dir.iterdir()
        if f.is_file() and not f.name.startswith(_RESERVED_PREFIX)
        and (f.name == f"{ip}.log" or f.name.startswith(f"{ip}.log."))
    ]
    entries = [(f, m) for (f, m) in entries if lo <= m <= hi]
    entries.sort(key=lambda t: t[1])
    return [f for (f, _) in entries]


async def tail_stream(path: Path, max_idle_seconds: int = 900,
                      poll_interval: float = 0.5,
                      burst_limit: int = 200,
                      max_total_seconds: int = 4 * 3600):
    """Async generator that yields each new line appended to `path`.

    Starts from EOF (no backfill). Designed to be safe under high log rates
    AND long-idle tabs:
      - `burst_limit` lines per batch max, then an `await asyncio.sleep(0)`
        yields to the event loop so Starlette can notice client disconnect
        (otherwise the generator can pin one CPU and buffer RAM indefinitely
        if the consumer has hung up).
      - `max_idle_seconds` closes the stream when no line has been received
        for this long (forgotten tabs, laptop suspend, etc.).
      - `max_total_seconds` is an absolute cap — even a lively stream is
        closed after 4 h to force clients to reconnect; prevents descriptor
        leaks when a browser reconnects silently on its own.
    """
    loop = asyncio.get_event_loop()
    start = loop.time()
    last_activity = start
    with open(path, "r", errors="replace") as f:
        f.seek(0, 2)  # start at EOF
        while True:
            if loop.time() - start > max_total_seconds:
                return
            line = f.readline()
            if line:
                last_activity = loop.time()
                yield line.rstrip("\n")
                # Every `burst_limit` lines, surrender control to the loop so
                # disconnect detection and cancellation can fire even under a
                # torrent of incoming lines.
                if burst_limit > 0:
                    burst_limit -= 1
                    if burst_limit == 0:
                        await asyncio.sleep(0)
                        burst_limit = 200
            else:
                if loop.time() - last_activity > max_idle_seconds:
                    return
                await asyncio.sleep(poll_interval)


def stream_file_contents(path: Path):
    """Yield raw bytes from a log file, transparently decompressing .gz."""
    if path.name.endswith(".gz"):
        with gzip.open(path, "rb") as f:
            while chunk := f.read(65536):
                yield chunk
    else:
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                yield chunk

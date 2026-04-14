import os
import gzip
from datetime import datetime, timezone
from pathlib import Path
from .. import config


def _format_dt(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def get_space_stats(port: int) -> dict:
    log_dir = Path(config.LOG_ROOT) / str(port)
    if not log_dir.exists():
        return {"source_count": 0, "total_size_bytes": 0, "last_seen": None}

    sources = set()
    total_size = 0
    last_mtime = 0.0

    for f in log_dir.iterdir():
        if not f.is_file():
            continue
        stat = f.stat()
        total_size += stat.st_size
        if stat.st_mtime > last_mtime:
            last_mtime = stat.st_mtime
        # Source IP is the stem of .log files (192.168.1.1.log → 192.168.1.1)
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


def list_sources(port: int) -> list[dict]:
    log_dir = Path(config.LOG_ROOT) / str(port)
    if not log_dir.exists():
        return []

    sources: dict[str, dict] = {}
    for f in log_dir.iterdir():
        if not f.is_file():
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
            # Keep most recent file as representative
            if stat.st_mtime > datetime.fromisoformat(
                sources[ip]["last_modified"]
            ).timestamp():
                sources[ip]["filename"] = name
                sources[ip]["size_bytes"] = stat.st_size
                sources[ip]["last_modified"] = _format_dt(stat.st_mtime)
            sources[ip]["size_bytes"] += stat.st_size

    return sorted(sources.values(), key=lambda x: x["last_modified"], reverse=True)


def list_files(port: int, ip: str) -> list[dict]:
    log_dir = Path(config.LOG_ROOT) / str(port)
    if not log_dir.exists():
        return []

    results = []
    for f in log_dir.iterdir():
        if not f.is_file():
            continue
        name = f.name
        is_this_ip = name.startswith(ip + ".log") or name == ip + ".log"
        if not is_this_ip:
            continue
        stat = f.stat()
        is_rotated = name != ip + ".log"
        results.append({
            "filename": name,
            "size_bytes": stat.st_size,
            "last_modified": _format_dt(stat.st_mtime),
            "is_rotated": is_rotated,
        })

    return sorted(results, key=lambda x: x["filename"])


def _estimate_lines(path: Path) -> int:
    try:
        size = path.stat().st_size
        if size == 0:
            return 0
        # Sample first 8KB to estimate average line length
        with open(path, "rb") as f:
            sample = f.read(8192)
        newlines = sample.count(b"\n")
        if newlines == 0:
            return 1
        avg_line = len(sample) / newlines
        return max(1, int(size / avg_line))
    except OSError:
        return 0


def read_log_tail(
    path: Path, lines: int = 100, offset: int = 0, filter_str: str = ""
) -> dict:
    try:
        opener = gzip.open if str(path).endswith(".gz") else open
        mode = "rt" if str(path).endswith(".gz") else "r"

        with opener(path, mode, encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()

        total = len(all_lines)

        if filter_str:
            fl = filter_str.lower()
            all_lines = [l for l in all_lines if fl in l.lower()]

        # Reverse pagination from end: offset=0 is last `lines` lines
        end = max(0, len(all_lines) - offset)
        start = max(0, end - lines)
        page = all_lines[start:end]

        return {
            "lines": [l.rstrip("\n") for l in page],
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

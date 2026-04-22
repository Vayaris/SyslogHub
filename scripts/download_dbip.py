#!/usr/bin/env python3
"""Download the db-ip.com Country Lite mmdb (CC-BY 4.0, monthly refresh).

Idempotent:
  - Skip if /opt/syslog-server/data/dbip-country-lite.mmdb exists and mtime
    is less than 35 days old.
  - Tries the current month first, falls back one month if 404.
  - Prints a single summary line; exits 0 on success and 0 on skip; exits
    non-zero only on unrecoverable network / file errors (callers in
    install.sh / update.sh can ignore this → GeoIP disabled silently).
"""
import gzip
import os
import sys
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

DATA_DIR = Path("/opt/syslog-server/data")
TARGET = DATA_DIR / "dbip-country-lite.mmdb"
MAX_AGE_DAYS = 35
URL_TMPL = "https://download.db-ip.com/free/dbip-country-lite-{year:04d}-{month:02d}.mmdb.gz"


def _needs_refresh() -> bool:
    if not TARGET.exists():
        return True
    age_days = (time.time() - TARGET.stat().st_mtime) / 86400
    return age_days >= MAX_AGE_DAYS


def _try_download(year: int, month: int) -> bool:
    url = URL_TMPL.format(year=year, month=month)
    tmp = TARGET.with_suffix(".mmdb.tmp")
    # Cloudflare blocks the default python-urllib User-Agent with 403.
    req = urllib.request.Request(url, headers={
        "User-Agent": "SyslogHub/1.9 (+download_dbip.py)",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()
    except Exception as e:
        print(f"  ↳ {year}-{month:02d}: {e}")
        return False
    try:
        decompressed = gzip.decompress(data)
    except Exception as e:
        print(f"  ↳ decompress failed: {e}")
        return False
    tmp.write_bytes(decompressed)
    tmp.replace(TARGET)
    print(f"✓ GeoIP DB updated from {year}-{month:02d} "
          f"({len(decompressed) // 1024} KB)")
    return True


def main() -> int:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if not _needs_refresh():
        age = (time.time() - TARGET.stat().st_mtime) / 86400
        print(f"✓ GeoIP DB is fresh ({age:.0f} days old), skipping download.")
        return 0

    now = datetime.now(timezone.utc)
    # Try current month, then walk back a few months. db-ip.com publishes
    # the current month's file a few days into the month, and very recent
    # months can briefly 403 while CDN warms up.
    for offset in range(0, 4):
        target = now - timedelta(days=offset * 30)
        if _try_download(target.year, target.month):
            return 0

    print("✗ GeoIP DB download failed (last 4 months tried); "
          "GeoIP enrichment will be disabled until next run.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())

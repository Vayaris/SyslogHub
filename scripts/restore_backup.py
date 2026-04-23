#!/usr/bin/env python3
"""Decrypt a SyslogHub backup (.db.enc) produced by backup_db.py.

Usage:
    restore_backup.py <path-to-backup.db.enc> [output.db]

Requires the master key at /opt/syslog-server/config/secrets.key (mode
0400 root:root). If you migrate to a new host, copy that file along with
the backup — without it the backup is unreadable (by design).
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, "/opt/syslog-server")
from app.services import crypto as crypto_svc


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print(__doc__, file=sys.stderr)
        return 1

    src = Path(argv[1])
    if not src.exists():
        print(f"ERROR: backup not found at {src}", file=sys.stderr)
        return 1

    dst = Path(argv[2]) if len(argv) > 2 else src.with_suffix("")
    if dst.suffix == ".enc":
        dst = dst.with_suffix("")  # syslog-server_xxx.db.enc → syslog-server_xxx.db
    if dst.exists():
        print(f"ERROR: refusing to overwrite existing {dst}", file=sys.stderr)
        return 1

    ciphertext = src.read_bytes()
    try:
        plain = crypto_svc.decrypt_bytes(ciphertext)
    except Exception as e:
        print(f"ERROR: decrypt failed ({e}). Wrong master key?", file=sys.stderr)
        return 2

    fd = os.open(str(dst), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, plain)
    finally:
        os.close(fd)
    print(f"Restored to {dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

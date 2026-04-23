"""No-logs alert checker — triggered every 10 min by syslog-alerts.timer."""
import logging
import smtplib
import ssl
import time
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

import requests
from sqlalchemy.orm import Session

from .. import config
from ..models import Setting, Space

_log = logging.getLogger("syslog-server.alerts")
_RESERVED_PREFIX = "_"

_SMTP_KEYS = [
    "smtp_host", "smtp_port", "smtp_username", "smtp_password",
    "smtp_from_email", "smtp_default_to", "alerts_global_enabled",
]


def get_settings(db: Session) -> dict:
    from . import crypto as _crypto
    rows = db.query(Setting).filter(Setting.key.in_(_SMTP_KEYS)).all()
    out = {r.key: r.value for r in rows}
    # v1.10.0 — smtp_password is Fernet-wrapped at rest. Legacy cleartext
    # rows still work (decrypt() passes them through).
    if "smtp_password" in out:
        out["smtp_password"] = _crypto.decrypt(out["smtp_password"])
    return out


def _latest_log_mtime(port: int) -> float | None:
    d = Path(config.LOG_ROOT) / str(port)
    if not d.exists():
        return None
    best = 0.0
    for f in d.iterdir():
        if not f.is_file() or f.name.startswith(_RESERVED_PREFIX):
            continue
        try:
            m = f.stat().st_mtime
            if m > best:
                best = m
        except OSError:
            continue
    return best if best > 0 else None


def send_email(smtp: dict, to_email: str, subject: str, body: str) -> None:
    host = smtp.get("smtp_host")
    user = smtp.get("smtp_username")
    pwd = smtp.get("smtp_password")
    if not (host and user and pwd):
        raise RuntimeError("SMTP non configuré (host/username/password manquant)")
    msg = EmailMessage()
    msg["From"] = smtp.get("smtp_from_email") or user
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)
    port = int(smtp.get("smtp_port") or 587)
    with smtplib.SMTP(host, port, timeout=15) as s:
        s.starttls(context=ssl.create_default_context())
        s.login(user, pwd)
        s.send_message(msg)


def send_webhook(url: str, payload: dict) -> None:
    requests.post(url, json=payload, timeout=10).raise_for_status()


def _notify(space: Space, smtp: dict, event: str, latest_mtime: float | None):
    hours = space.alert_threshold_hours or 24
    subject = (
        f"[SyslogHub] {space.name} : aucun log depuis {hours}h"
        if event == "down"
        else f"[SyslogHub] {space.name} : logs de retour"
    )
    last_seen = (
        datetime.fromtimestamp(latest_mtime, tz=timezone.utc).isoformat()
        if latest_mtime else "jamais"
    )
    body = (
        f"Espace : {space.name} (port {space.port})\n"
        f"État   : {event.upper()}\n"
        f"Seuil  : {hours}h\n"
        f"Dernier log : {last_seen}\n"
    )
    to_email = space.alert_email_to or smtp.get("smtp_default_to")
    if to_email and smtp.get("smtp_host"):
        try:
            send_email(smtp, to_email, subject, body)
        except Exception as e:
            _log.warning(f"email alert failed ({space.name}): {e}")
    if space.alert_webhook_url:
        try:
            send_webhook(space.alert_webhook_url, {
                "event": event,
                "space": space.name,
                "port": space.port,
                "threshold_hours": hours,
                "last_log_at": last_seen,
            })
        except Exception as e:
            _log.warning(f"webhook alert failed ({space.name}): {e}")


def run_all_checks(db: Session) -> dict:
    settings = get_settings(db)
    if settings.get("alerts_global_enabled", "false") != "true":
        return {"skipped": "alerts_global_enabled=false"}
    spaces = db.query(Space).filter(Space.alerts_enabled == True).all()  # noqa: E712
    now = time.time()
    fired = 0
    recovered = 0
    for sp in spaces:
        latest = _latest_log_mtime(sp.port)
        if latest is None:
            continue  # espace jamais alimenté — ne pas tirer
        hours = sp.alert_threshold_hours or 24
        is_down = (now - latest) > hours * 3600
        cur = sp.alert_state or "ok"
        if is_down and cur == "ok":
            _notify(sp, settings, "down", latest)
            sp.alert_state = "firing"
            sp.alert_last_transition_at = datetime.now(timezone.utc).isoformat()
            fired += 1
        elif not is_down and cur == "firing":
            _notify(sp, settings, "recovery", latest)
            sp.alert_state = "ok"
            sp.alert_last_transition_at = datetime.now(timezone.utc).isoformat()
            recovered += 1
    db.commit()
    return {"checked": len(spaces), "fired": fired, "recovered": recovered}


def send_test_email(smtp: dict, to_email: str) -> None:
    send_email(
        smtp, to_email, "[SyslogHub] Test d'alerte",
        "Ceci est un email de test depuis SyslogHub. Configuration OK.",
    )

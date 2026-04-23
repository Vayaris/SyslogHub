from sqlalchemy import Column, Integer, String, Boolean, Text
from .database import Base
from datetime import datetime, timezone


def _now():
    return datetime.now(timezone.utc).isoformat()


class Space(Base):
    __tablename__ = "spaces"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    port = Column(Integer, nullable=False, unique=True)
    enabled = Column(Boolean, nullable=False, default=True)
    description = Column(Text, nullable=True)
    allowed_ip = Column(String(45), nullable=True)
    tcp_enabled = Column(Boolean, nullable=False, default=False)
    lan_mode = Column(Boolean, nullable=False, default=False)

    # Per-space Omada SDN integration (optional)
    omada_base_url      = Column(Text, nullable=True)
    omada_id            = Column(Text, nullable=True)
    omada_client_id     = Column(Text, nullable=True)
    omada_client_secret = Column(Text, nullable=True)
    omada_site_name     = Column(Text, nullable=True)
    omada_verify_ssl    = Column(Boolean, nullable=False, default=False)
    omada_controller_ip = Column(String(45), nullable=True)  # v1.9.0 — alias contrôleur

    # Per-space no-log alerts (v1.7.0)
    alerts_enabled           = Column(Boolean, nullable=False, default=False)
    alert_threshold_hours    = Column(Integer, nullable=False, default=24)
    alert_email_to           = Column(Text, nullable=True)
    alert_webhook_url        = Column(Text, nullable=True)
    alert_state              = Column(String(8), nullable=False, default="ok")
    alert_last_transition_at = Column(String(32), nullable=True)

    created_at = Column(String(32), nullable=False, default=_now)
    updated_at = Column(String(32), nullable=False, default=_now, onupdate=_now)


class Setting(Base):
    __tablename__ = "settings"

    key = Column(String(64), primary_key=True)
    value = Column(Text, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    ts         = Column(String(32), nullable=False, index=True)
    username   = Column(String(100), nullable=True)
    action     = Column(String(40), nullable=False, index=True)
    ip         = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)
    details    = Column(Text, nullable=True)  # JSON string, optional


class ActiveSession(Base):
    __tablename__ = "active_sessions"

    id           = Column(String(32), primary_key=True)  # hex uuid4
    username     = Column(String(100), nullable=False, index=True)
    created_at   = Column(String(32), nullable=False)
    last_seen_at = Column(String(32), nullable=False)
    ip           = Column(String(45), nullable=True)
    user_agent   = Column(String(255), nullable=True)
    revoked      = Column(Boolean, nullable=False, default=False)


class LoginAttempt(Base):
    """v1.10.0 — records every login-adjacent auth event (password check,
    TOTP step, password-confirm-for-sensitive-action) for application-level
    brute-force lockout by username. Nginx already rate-limits by IP, but
    an attacker on a botnet trivially side-steps IP limits."""
    __tablename__ = "login_attempts"

    id       = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), nullable=False, index=True)
    ip       = Column(String(45), nullable=True)
    ts       = Column(String(32), nullable=False, index=True)
    success  = Column(Boolean, nullable=False, default=False)

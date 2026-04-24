from sqlalchemy import Column, Integer, String, Boolean, Text, ForeignKey, UniqueConstraint, Index
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

    # v2.0.0 — Conformité LCEN/RGPD
    retention_days      = Column(Integer, nullable=False, default=365)      # LCEN default 1 an
    branding_logo_path  = Column(Text, nullable=True)
    branding_color      = Column(String(16), nullable=True)
    dhcp_parse_enabled  = Column(Boolean, nullable=False, default=False)
    omada_sync_enabled  = Column(Boolean, nullable=False, default=False)
    chain_enabled       = Column(Boolean, nullable=False, default=True)

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


# ── v2.0.0 — multi-utilisateurs + RBAC par space ─────────────────────────────

class User(Base):
    __tablename__ = "users"

    id             = Column(Integer, primary_key=True, autoincrement=True)
    username       = Column(String(100), nullable=False, unique=True)
    email          = Column(String(255), nullable=True, unique=True)
    password_hash  = Column(Text, nullable=True)       # NULL = OIDC only
    totp_secret    = Column(Text, nullable=True)
    totp_enabled   = Column(Boolean, nullable=False, default=False)
    totp_last_counter = Column(Integer, nullable=False, default=0)
    role_global    = Column(String(16), nullable=False, default="operator")  # admin | operator
    oidc_subject   = Column(Text, nullable=True, unique=True)
    disabled       = Column(Boolean, nullable=False, default=False)
    created_at     = Column(String(32), nullable=False, default=_now)
    last_login_at  = Column(String(32), nullable=True)


class SpaceRole(Base):
    __tablename__ = "space_roles"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    user_id    = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    space_id   = Column(Integer, ForeignKey("spaces.id", ondelete="CASCADE"), nullable=False)
    role       = Column(String(16), nullable=False)    # owner | operator | readonly
    granted_at = Column(String(32), nullable=False, default=_now)
    granted_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    __table_args__ = (UniqueConstraint("user_id", "space_id", name="uq_space_roles"),)


# ── v2.0.0 — intégrité légale (chaîne SHA-256 + TSA RFC3161) ─────────────────

class LogChain(Base):
    __tablename__ = "log_chain"

    id                = Column(Integer, primary_key=True, autoincrement=True)
    space_id          = Column(Integer, ForeignKey("spaces.id", ondelete="CASCADE"), nullable=False)
    day               = Column(String(10), nullable=False)     # YYYY-MM-DD
    manifest_path     = Column(Text, nullable=False)
    manifest_sha256   = Column(String(64), nullable=False)
    prev_sha256       = Column(String(64), nullable=True)
    files_count       = Column(Integer, nullable=False)
    total_bytes       = Column(Integer, nullable=False)
    tsa_status        = Column(String(24), nullable=False, default="pending")
    tsa_receipt_path  = Column(Text, nullable=True)
    tsa_serial        = Column(Text, nullable=True)
    tsa_url           = Column(Text, nullable=True)
    tsa_gen_time      = Column(String(32), nullable=True)
    tsa_attempts      = Column(Integer, nullable=False, default=0)
    tsa_last_error    = Column(Text, nullable=True)
    created_at        = Column(String(32), nullable=False, default=_now)

    __table_args__ = (UniqueConstraint("space_id", "day", name="uq_log_chain_day"),)


# ── v2.0.0 — réquisitions judiciaires + legal hold ───────────────────────────

class Requisition(Base):
    __tablename__ = "requisitions"

    id                = Column(Integer, primary_key=True, autoincrement=True)
    number            = Column(Text, nullable=False)
    opj_name          = Column(Text, nullable=False)
    opj_service       = Column(Text, nullable=True)
    opj_email         = Column(Text, nullable=True)
    justification     = Column(Text, nullable=False)
    space_id          = Column(Integer, ForeignKey("spaces.id", ondelete="SET NULL"), nullable=True)
    time_from         = Column(String(32), nullable=False)
    time_to           = Column(String(32), nullable=False)
    status            = Column(String(16), nullable=False, default="draft")   # draft | exported | closed
    created_at        = Column(String(32), nullable=False, default=_now)
    created_by        = Column(Integer, ForeignKey("users.id"), nullable=False)
    exported_at       = Column(String(32), nullable=True)
    bundle_path       = Column(Text, nullable=True)
    bundle_sha256     = Column(String(64), nullable=True)
    bundle_size_bytes = Column(Integer, nullable=True)
    closed_at         = Column(String(32), nullable=True)
    closed_by         = Column(Integer, ForeignKey("users.id"), nullable=True)
    notes             = Column(Text, nullable=True)


class LegalHold(Base):
    __tablename__ = "legal_holds"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    requisition_id  = Column(Integer, ForeignKey("requisitions.id", ondelete="CASCADE"), nullable=False)
    space_id        = Column(Integer, ForeignKey("spaces.id", ondelete="CASCADE"), nullable=True)  # NULL = tous
    time_from       = Column(String(32), nullable=False)
    time_to         = Column(String(32), nullable=False)
    active          = Column(Boolean, nullable=False, default=True)
    created_at      = Column(String(32), nullable=False, default=_now)


# ── v2.0.0 — corrélation identité (DHCP + Omada hotspot) ─────────────────────

class DhcpLease(Base):
    __tablename__ = "dhcp_leases"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    space_id    = Column(Integer, ForeignKey("spaces.id", ondelete="CASCADE"), nullable=False)
    mac         = Column(String(32), nullable=False)
    ip          = Column(String(45), nullable=False)
    hostname    = Column(Text, nullable=True)
    seen_at     = Column(String(32), nullable=False)
    source_file = Column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint("space_id", "mac", "ip", "seen_at", name="uq_dhcp_lease"),
        Index("idx_dhcp_mac_time", "mac", "seen_at"),
        Index("idx_dhcp_ip_time", "ip", "seen_at"),
        Index("idx_dhcp_space_time", "space_id", "seen_at"),
    )


class OmadaSession(Base):
    __tablename__ = "omada_sessions"

    id                = Column(Integer, primary_key=True, autoincrement=True)
    space_id          = Column(Integer, ForeignKey("spaces.id", ondelete="CASCADE"), nullable=False)
    client_mac        = Column(String(32), nullable=False)
    client_ip         = Column(String(45), nullable=True)
    identifier        = Column(Text, nullable=True)         # user hotspot (email/SMS/code)
    ap_mac            = Column(String(32), nullable=True)
    ssid              = Column(Text, nullable=True)
    session_start     = Column(String(32), nullable=False)
    session_end       = Column(String(32), nullable=True)
    uploaded_bytes    = Column(Integer, nullable=True)
    downloaded_bytes  = Column(Integer, nullable=True)
    pulled_at         = Column(String(32), nullable=False, default=_now)

    __table_args__ = (
        UniqueConstraint("space_id", "client_mac", "session_start", name="uq_omada_session"),
        Index("idx_omada_mac_time", "client_mac", "session_start"),
        Index("idx_omada_ip_time", "client_ip", "session_start"),
    )

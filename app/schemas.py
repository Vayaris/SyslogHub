import ipaddress
from pydantic import BaseModel, Field, field_validator
from typing import Optional


class SpaceStats(BaseModel):
    source_count: int
    total_size_bytes: int
    last_seen: Optional[str]


class SpaceOut(BaseModel):
    id: int
    name: str
    port: int
    enabled: bool
    description: Optional[str]
    allowed_ip: Optional[str]
    tcp_enabled: bool
    lan_mode: bool = False
    # Omada (read-only view; client_secret never returned)
    omada_base_url:   Optional[str] = None
    omada_id:         Optional[str] = None
    omada_client_id:  Optional[str] = None
    omada_verify_ssl: bool = False
    omada_configured: bool = False
    omada_controller_ip: Optional[str] = None
    # Alerts (v1.7.0)
    alerts_enabled:        bool = False
    alert_threshold_hours: int = 24
    alert_email_to:        Optional[str] = None
    alert_webhook_url:     Optional[str] = None
    alert_state:           str = "ok"
    alert_last_transition_at: Optional[str] = None
    # v2.0.0 — conformité LCEN/RGPD
    retention_days:     int = 365
    branding_logo_path: Optional[str] = None
    branding_color:     Optional[str] = None
    dhcp_parse_enabled: bool = False
    omada_sync_enabled: bool = False
    chain_enabled:      bool = True
    created_at: str
    updated_at: str
    stats: Optional[SpaceStats] = None

    class Config:
        from_attributes = True


class SpaceCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    port: int = Field(..., ge=1, le=65535)
    description: Optional[str] = Field(None, max_length=255)
    allowed_ip: Optional[str] = Field(None, max_length=45)
    tcp_enabled: bool = False
    lan_mode: bool = False
    # Omada (optional, all-or-nothing for the 4 required fields)
    omada_base_url:      Optional[str] = None
    omada_id:            Optional[str] = None
    omada_client_id:     Optional[str] = None
    omada_client_secret: Optional[str] = None
    omada_verify_ssl:    bool = False
    omada_controller_ip: Optional[str] = None
    # Alerts (v1.7.0)
    alerts_enabled:        Optional[bool] = None
    alert_threshold_hours: Optional[int] = Field(None, ge=1, le=720)
    alert_email_to:        Optional[str] = None
    alert_webhook_url:     Optional[str] = None
    # v2.0.0
    retention_days:        Optional[int] = Field(None, ge=1, le=3650)
    branding_color:        Optional[str] = Field(None, max_length=16)
    dhcp_parse_enabled:    Optional[bool] = None
    omada_sync_enabled:    Optional[bool] = None
    chain_enabled:         Optional[bool] = None

    @field_validator("allowed_ip")
    @classmethod
    def validate_ip(cls, v):
        if v is None or v.strip() == "":
            return None
        try:
            ipaddress.ip_address(v.strip())
            return v.strip()
        except ValueError:
            raise ValueError(f"Adresse IP invalide : {v}")


class SpaceUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=255)
    enabled: Optional[bool] = None
    allowed_ip: Optional[str] = Field(None, max_length=45)
    tcp_enabled: Optional[bool] = None
    lan_mode: Optional[bool] = None
    # Omada (partial updates). Empty string on a text field means "clear".
    omada_base_url:      Optional[str] = None
    omada_id:            Optional[str] = None
    omada_client_id:     Optional[str] = None
    omada_client_secret: Optional[str] = None  # Empty/None = keep; value = overwrite
    omada_verify_ssl:    Optional[bool] = None
    omada_controller_ip: Optional[str] = None
    # Alerts (v1.7.0). Empty string on text fields = clear.
    alerts_enabled:        Optional[bool] = None
    alert_threshold_hours: Optional[int] = Field(None, ge=1, le=720)
    alert_email_to:        Optional[str] = None
    alert_webhook_url:     Optional[str] = None
    # v2.0.0
    retention_days:        Optional[int] = Field(None, ge=1, le=3650)
    branding_color:        Optional[str] = Field(None, max_length=16)
    dhcp_parse_enabled:    Optional[bool] = None
    omada_sync_enabled:    Optional[bool] = None
    chain_enabled:         Optional[bool] = None

    @field_validator("allowed_ip")
    @classmethod
    def validate_ip(cls, v):
        if v is None or v.strip() == "":
            return None
        try:
            ipaddress.ip_address(v.strip())
            return v.strip()
        except ValueError:
            raise ValueError(f"Adresse IP invalide : {v}")


class LoginRequest(BaseModel):
    username: str
    password: str


class SettingsOut(BaseModel):
    retention_days: int
    admin_username: str
    password_must_change: bool = False


class SettingsUpdate(BaseModel):
    retention_days: Optional[int] = Field(None, ge=1, le=3650)
    admin_username: Optional[str] = Field(None, min_length=1, max_length=64)
    current_password: Optional[str] = None
    new_password: Optional[str] = Field(None, min_length=6)


class AlertsConfigOut(BaseModel):
    enabled: bool
    smtp_host: Optional[str] = None
    smtp_port: Optional[int] = None
    smtp_username: Optional[str] = None
    smtp_from_email: Optional[str] = None
    smtp_default_to: Optional[str] = None
    smtp_password_set: bool = False


class AlertsConfigUpdate(BaseModel):
    enabled: Optional[bool] = None
    smtp_host: Optional[str] = None
    smtp_port: Optional[int] = Field(None, ge=1, le=65535)
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None  # empty/None = keep; value = overwrite
    smtp_from_email: Optional[str] = None
    smtp_default_to: Optional[str] = None


class AlertTestRequest(BaseModel):
    to_email: str = Field(..., min_length=3, max_length=254)


class TestLogRequest(BaseModel):
    message: str = Field(default="Test depuis SyslogHub", min_length=1, max_length=512)


class SystemStatus(BaseModel):
    rsyslog_active: bool
    nginx_active: bool
    total_log_size_bytes: int
    total_spaces: int
    enabled_spaces: int
    db_size_bytes: int


class SourceInfo(BaseModel):
    ip: str
    filename: str
    size_bytes: int
    line_count: int
    last_modified: str
    device_name:  Optional[str] = None
    device_model: Optional[str] = None
    geoip_country: Optional[str] = None  # ISO-3166 alpha-2, only for public IPs
    rdns_name:     Optional[str] = None


class SourceListResponse(BaseModel):
    items: list[SourceInfo]
    total: int
    page: int
    per_page: int
    pages: int


class FileInfo(BaseModel):
    filename: str
    size_bytes: int
    last_modified: str
    is_rotated: bool


class LogViewResult(BaseModel):
    lines: list[str]
    total_lines: int
    has_more: bool


class SearchResult(BaseModel):
    space_id: int
    space_name: str
    port: int
    source_ip: str
    filename: str
    line_number: int
    line: str


class SearchResponse(BaseModel):
    results: list[SearchResult]
    truncated: bool


class AuditEntry(BaseModel):
    id: int
    ts: str
    username: Optional[str] = None
    action: str
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    details: Optional[str] = None  # JSON string (already serialised by log_event)


class AuditListResponse(BaseModel):
    items: list[AuditEntry]
    total: int
    page: int
    per_page: int
    pages: int


class SessionInfo(BaseModel):
    id: str
    username: str
    created_at: str
    last_seen_at: str
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    is_current: bool = False


class TOTPSetupResponse(BaseModel):
    uri: str
    svg: str


class TOTPActivateRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=10)


class TOTPDisableRequest(BaseModel):
    password: str = Field(..., min_length=1)


class TOTPStatus(BaseModel):
    enabled: bool
    pending: bool = False


class TOTPLoginRequest(BaseModel):
    tx_id: str
    code: str = Field(..., min_length=6, max_length=10)


class OIDCConfigOut(BaseModel):
    enabled: bool
    discovery_url: Optional[str] = None
    client_id: Optional[str] = None
    allowlist: Optional[str] = None
    button_label: Optional[str] = None
    client_secret_set: bool = False
    require_verified_email: bool = True


class OIDCConfigUpdate(BaseModel):
    enabled: Optional[bool] = None
    discovery_url: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None  # empty/None = keep
    allowlist: Optional[str] = None
    button_label: Optional[str] = None
    require_verified_email: Optional[bool] = None


# ── v2.0.0 — Users & RBAC ────────────────────────────────────────────────────

class UserOut(BaseModel):
    id: int
    username: str
    email: Optional[str] = None
    role_global: str
    disabled: bool
    has_password: bool
    totp_enabled: bool
    oidc_subject: Optional[str] = None
    created_at: str
    last_login_at: Optional[str] = None

    class Config:
        from_attributes = True


class UserCreate(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    email: Optional[str] = Field(None, max_length=255)
    password: Optional[str] = Field(None, min_length=8)
    role_global: str = Field(default="operator")

    @field_validator("role_global")
    @classmethod
    def _check_role(cls, v):
        if v not in ("admin", "operator"):
            raise ValueError("role_global doit être 'admin' ou 'operator'")
        return v


class UserUpdate(BaseModel):
    username: Optional[str] = Field(None, min_length=1, max_length=100)
    email: Optional[str] = Field(None, max_length=255)
    role_global: Optional[str] = None
    disabled: Optional[bool] = None
    new_password: Optional[str] = Field(None, min_length=8)

    @field_validator("role_global")
    @classmethod
    def _check_role(cls, v):
        if v is None:
            return v
        if v not in ("admin", "operator"):
            raise ValueError("role_global doit être 'admin' ou 'operator'")
        return v


class SpaceRoleOut(BaseModel):
    id: int
    user_id: int
    space_id: int
    space_name: Optional[str] = None
    role: str
    granted_at: str

    class Config:
        from_attributes = True


class SpaceRoleUpdate(BaseModel):
    role: str = Field(..., description="owner | operator | readonly")

    @field_validator("role")
    @classmethod
    def _check_role(cls, v):
        if v not in ("owner", "operator", "readonly"):
            raise ValueError("role doit être owner, operator ou readonly")
        return v


class MeResponse(BaseModel):
    username: str
    email: Optional[str] = None
    role_global: str
    is_admin: bool
    totp_enabled: bool
    password_must_change: bool = False



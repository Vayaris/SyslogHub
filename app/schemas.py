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


class SettingsUpdate(BaseModel):
    retention_days: Optional[int] = Field(None, ge=1, le=3650)
    admin_username: Optional[str] = Field(None, min_length=1, max_length=64)
    current_password: Optional[str] = None
    new_password: Optional[str] = Field(None, min_length=6)


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

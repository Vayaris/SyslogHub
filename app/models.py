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

    # Per-space Omada SDN integration (optional)
    omada_base_url      = Column(Text, nullable=True)
    omada_id            = Column(Text, nullable=True)
    omada_client_id     = Column(Text, nullable=True)
    omada_client_secret = Column(Text, nullable=True)
    omada_site_name     = Column(Text, nullable=True)
    omada_verify_ssl    = Column(Boolean, nullable=False, default=False)

    created_at = Column(String(32), nullable=False, default=_now)
    updated_at = Column(String(32), nullable=False, default=_now, onupdate=_now)


class Setting(Base):
    __tablename__ = "settings"

    key = Column(String(64), primary_key=True)
    value = Column(Text, nullable=False)

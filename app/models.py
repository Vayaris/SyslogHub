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
    created_at = Column(String(32), nullable=False, default=_now)
    updated_at = Column(String(32), nullable=False, default=_now, onupdate=_now)


class Setting(Base):
    __tablename__ = "settings"

    key = Column(String(64), primary_key=True)
    value = Column(Text, nullable=False)

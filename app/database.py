import secrets
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker
from . import config

engine = create_engine(
    f"sqlite:///{config.DB_PATH}",
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    import bcrypt
    from .models import Space, Setting

    Base.metadata.create_all(bind=engine)

    # Migrations: add columns added after initial release
    _migrations = [
        "ALTER TABLE spaces ADD COLUMN allowed_ip TEXT",
        "ALTER TABLE spaces ADD COLUMN tcp_enabled INTEGER NOT NULL DEFAULT 0",
    ]
    with engine.connect() as conn:
        for stmt in _migrations:
            try:
                conn.execute(text(stmt))
                conn.commit()
            except Exception:
                pass  # Column already exists

    db = SessionLocal()
    try:
        defaults = {
            "retention_days": "90",
            "admin_username": "admin",
            "admin_password_hash": bcrypt.hashpw(b"changeme", bcrypt.gensalt()).decode(),
            "session_secret": secrets.token_hex(32),
        }
        for key, value in defaults.items():
            existing = db.query(Setting).filter(Setting.key == key).first()
            if not existing:
                db.add(Setting(key=key, value=value))

        existing_space = db.query(Space).filter(Space.port == 514).first()
        if not existing_space:
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc).isoformat()
            db.add(Space(
                name="Default",
                port=514,
                enabled=True,
                description="Espace syslog par défaut",
                created_at=now,
                updated_at=now,
            ))

        db.commit()
    finally:
        db.close()

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


def _migrate_global_omada_to_space():
    """Legacy `settings.omada_*` keys → first space's Omada columns, then purge."""
    from .models import Space, Setting
    db = SessionLocal()
    try:
        legacy_keys = [
            "omada_base_url", "omada_id", "omada_client_id",
            "omada_client_secret", "omada_site", "omada_verify_ssl",
        ]
        legacy = {
            r.key: r.value
            for r in db.query(Setting).filter(Setting.key.in_(legacy_keys)).all()
        }
        if not legacy.get("omada_base_url") or not legacy.get("omada_client_secret"):
            # Nothing meaningful to migrate — just drop empty keys if present
            if legacy:
                db.query(Setting).filter(Setting.key.in_(legacy_keys)).delete(synchronize_session=False)
                db.commit()
            return

        target = db.query(Space).order_by(Space.port).first()
        if not target:
            return

        if not target.omada_base_url:
            target.omada_base_url      = legacy.get("omada_base_url")
            target.omada_id            = legacy.get("omada_id")
            target.omada_client_id     = legacy.get("omada_client_id")
            target.omada_client_secret = legacy.get("omada_client_secret")
            target.omada_site_name     = legacy.get("omada_site") or None
            target.omada_verify_ssl    = (legacy.get("omada_verify_ssl") or "false") == "true"

        db.query(Setting).filter(Setting.key.in_(legacy_keys)).delete(synchronize_session=False)
        db.commit()
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
        "ALTER TABLE spaces ADD COLUMN omada_base_url TEXT",
        "ALTER TABLE spaces ADD COLUMN omada_id TEXT",
        "ALTER TABLE spaces ADD COLUMN omada_client_id TEXT",
        "ALTER TABLE spaces ADD COLUMN omada_client_secret TEXT",
        "ALTER TABLE spaces ADD COLUMN omada_site_name TEXT",
        "ALTER TABLE spaces ADD COLUMN omada_verify_ssl INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE spaces ADD COLUMN lan_mode INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE spaces ADD COLUMN alerts_enabled INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE spaces ADD COLUMN alert_threshold_hours INTEGER NOT NULL DEFAULT 24",
        "ALTER TABLE spaces ADD COLUMN alert_email_to TEXT",
        "ALTER TABLE spaces ADD COLUMN alert_webhook_url TEXT",
        "ALTER TABLE spaces ADD COLUMN alert_state TEXT NOT NULL DEFAULT 'ok'",
        "ALTER TABLE spaces ADD COLUMN alert_last_transition_at TEXT",
        "ALTER TABLE spaces ADD COLUMN omada_controller_ip TEXT",
    ]
    with engine.connect() as conn:
        for stmt in _migrations:
            try:
                conn.execute(text(stmt))
                conn.commit()
            except Exception:
                pass  # Column already exists

    # One-time migration: move legacy global Omada config onto the first space
    _migrate_global_omada_to_space()

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

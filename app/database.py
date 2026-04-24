import os
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


def _migrate_v2_users():
    """v2.0.0 — bootstrap the `users` table from the legacy admin settings.

    We keep the legacy `admin_*` settings keys in place (fallback used by the
    still-running v1.x code paths during the ramp-up of v2). A flag
    `v2_users_migrated` makes this idempotent."""
    from .models import Setting, User

    db = SessionLocal()
    try:
        flag = db.query(Setting).filter(Setting.key == "v2_users_migrated").first()
        if flag and flag.value == "true":
            return

        # Gather legacy admin identity
        rows = {
            r.key: r.value
            for r in db.query(Setting).filter(Setting.key.in_([
                "admin_username", "admin_password_hash",
                "admin_totp_enabled", "admin_totp_secret", "admin_totp_last_counter",
            ])).all()
        }
        username = rows.get("admin_username") or "admin"
        phash    = rows.get("admin_password_hash")
        if not phash:
            # Nothing to migrate yet (fresh install — init_db seeds the legacy
            # keys just above, so on next call this function will pick them up).
            return

        existing = db.query(User).filter(User.username == username).first()
        if existing is None:
            from datetime import datetime, timezone
            db.add(User(
                username      = username,
                password_hash = phash,
                totp_secret   = rows.get("admin_totp_secret"),
                totp_enabled  = (rows.get("admin_totp_enabled") == "true"),
                totp_last_counter = int(rows.get("admin_totp_last_counter") or 0),
                role_global   = "admin",
                created_at    = datetime.now(timezone.utc).isoformat(),
            ))

        # Record the migration
        if flag:
            flag.value = "true"
        else:
            db.add(Setting(key="v2_users_migrated", value="true"))
        db.commit()
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
        # v2.0.0 — conformité LCEN/RGPD
        "ALTER TABLE spaces ADD COLUMN retention_days INTEGER NOT NULL DEFAULT 365",
        "ALTER TABLE spaces ADD COLUMN branding_logo_path TEXT",
        "ALTER TABLE spaces ADD COLUMN branding_color TEXT",
        "ALTER TABLE spaces ADD COLUMN dhcp_parse_enabled INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE spaces ADD COLUMN omada_sync_enabled INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE spaces ADD COLUMN chain_enabled INTEGER NOT NULL DEFAULT 1",
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

    # v2.0.0 — migrate legacy admin settings → users row
    _migrate_v2_users()

    db = SessionLocal()
    try:
        defaults = {
            "retention_days": "90",
            "admin_username": "admin",
            "admin_password_hash": bcrypt.hashpw(b"changeme", bcrypt.gensalt()).decode(),
            "session_secret": secrets.token_hex(32),
        }
        seeded_default_password = False
        for key, value in defaults.items():
            existing = db.query(Setting).filter(Setting.key == key).first()
            if not existing:
                db.add(Setting(key=key, value=value))
                if key == "admin_password_hash":
                    seeded_default_password = True

        # If we just seeded the default `changeme` hash, flag the account so
        # the UI blocks everything until a real password is set. The flag is
        # cleared in routers/settings.py::update_settings when a new password
        # is accepted.
        if seeded_default_password:
            if not db.query(Setting).filter(Setting.key == "admin_password_must_change").first():
                db.add(Setting(key="admin_password_must_change", value="true"))

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

    # The DB holds the admin bcrypt hash + integration secrets. Enforce 0600
    # on every init so a stale 0644 from an older install is corrected.
    try:
        os.chmod(config.DB_PATH, 0o600)
    except OSError:
        pass

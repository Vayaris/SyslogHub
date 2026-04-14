import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment file
_env_path = Path("/opt/syslog-server/config/app.env")
if _env_path.exists():
    load_dotenv(_env_path)

LOG_ROOT = os.getenv("LOG_ROOT", "/var/log/syslog-server")
DB_PATH = os.getenv("DB_PATH", "/opt/syslog-server/data/syslog-server.db")
SECRET_KEY = os.getenv("SECRET_KEY", "changeme-please-set-a-real-secret")
SESSION_MAX_AGE = int(os.getenv("SESSION_MAX_AGE", "86400"))
BIND_HOST = os.getenv("BIND_HOST", "127.0.0.1")
BIND_PORT = int(os.getenv("BIND_PORT", "8000"))
APP_BASE = Path("/opt/syslog-server")
RSYSLOG_CONF = "/etc/rsyslog.d/99-syslog-server.conf"
RSYSLOG_CONF_BAK = "/etc/rsyslog.d/99-syslog-server.conf.bak"

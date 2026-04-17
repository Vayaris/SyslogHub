"""
TP-Link Omada SDN — Northbound OpenAPI (client_credentials flow).

Token URL : POST {base}/openapi/authorize/token?grant_type=client_credentials
Body (JSON) : {"omadacId": "...", "client_id": "...", "client_secret": "..."}
API calls  : GET {base}/openapi/v1/msp/{omadacId}/...   (MSP mode, auto-detected)
             GET {base}/openapi/v1/{omadacId}/...       (standard mode)
Headers    : Authorization: AccessToken={token}
             Accept: application/json   (required — without it the controller returns Spring 400)
"""
import time
import logging
from threading import Lock

log = logging.getLogger("syslog-server")

try:
    import requests as _req  # noqa: F401
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False


class OmadaClient:
    TOKEN_TTL = 7200   # 2h default
    CACHE_TTL = 900    # 15 min AP cache

    def __init__(
        self,
        base_url: str,
        omada_id: str,
        client_id: str,
        client_secret: str,
        site_name: str = "Default",
        verify_ssl: bool = False,
    ):
        self.base          = base_url.rstrip("/")
        self.omada_id      = omada_id.strip()
        self.client_id     = client_id.strip()
        self.client_secret = client_secret
        self.site_name     = site_name.strip()
        self.verify        = verify_ssl

        self._token: str | None = None
        self._token_expires_at: float = 0.0
        self._msp_mode: bool | None = None
        self._cache: list[dict] | None = None
        self._cache_ts: float = 0.0
        self._lock = Lock()

    # ── private helpers ────────────────────────────────────────────────────────

    def _detect_mode(self):
        """Detect MSP mode via public /api/info (no auth required)."""
        if self._msp_mode is not None:
            return
        import requests
        try:
            r = requests.get(f"{self.base}/api/info", verify=self.verify, timeout=10)
            info = r.json().get("result", {})
            self._msp_mode = bool(info.get("mspMode", False))
        except Exception as e:
            log.warning(f"Omada: mspMode detection failed ({e}), defaulting to standard mode")
            self._msp_mode = False

    def _api_root(self) -> str:
        self._detect_mode()
        seg = "msp/" if self._msp_mode else ""
        return f"{self.base}/openapi/v1/{seg}{self.omada_id}"

    def _fetch_token(self):
        import requests
        r = requests.post(
            f"{self.base}/openapi/authorize/token",
            params={"grant_type": "client_credentials"},
            json={
                "omadacId":      self.omada_id,
                "client_id":     self.client_id,
                "client_secret": self.client_secret,
            },
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            verify=self.verify,
            timeout=15,
        )
        try:
            data = r.json()
        except Exception:
            r.raise_for_status()
            raise
        if data.get("errorCode", -1) != 0:
            raise ValueError(
                f"Omada token error ({data.get('errorCode')}): {data.get('msg', 'unknown')}"
            )
        result = data["result"]
        self._token = result["accessToken"]
        expires_in = result.get("expiresIn", self.TOKEN_TTL)
        self._token_expires_at = time.time() + expires_in - 60

    def _ensure_token(self):
        if self._token and time.time() < self._token_expires_at:
            return
        self._fetch_token()

    def _get(self, path: str, params: dict | None = None) -> dict | list:
        import requests
        self._ensure_token()
        url = f"{self._api_root()}{path}"
        headers = {
            "Authorization": f"AccessToken={self._token}",
            "Accept":        "application/json",
        }
        r = requests.get(url, headers=headers, params=params or {}, verify=self.verify, timeout=15)
        try:
            data = r.json()
        except Exception:
            r.raise_for_status()
            raise
        # Token expired → refresh once and retry
        if isinstance(data, dict) and data.get("errorCode") in (-44112, -44113):
            self._token = None
            self._ensure_token()
            headers["Authorization"] = f"AccessToken={self._token}"
            r = requests.get(url, headers=headers, params=params or {}, verify=self.verify, timeout=15)
            data = r.json()
        if isinstance(data, dict) and data.get("errorCode", -1) != 0:
            raise ValueError(
                f"Omada API error on {path}: "
                f"({data.get('errorCode')}) {data.get('msg', 'unknown')}"
            )
        return data.get("result", {}) if isinstance(data, dict) else data

    # ── public API ─────────────────────────────────────────────────────────────

    @staticmethod
    def _norm_mac(mac: str) -> str:
        return (mac or "").replace(":", "").replace("-", "").lower()

    def get_sites(self) -> list[dict]:
        result = self._get("/sites", params={"page": 1, "pageSize": 200})
        if isinstance(result, dict):
            return result.get("data", [])
        return result or []

    def get_aps(self, force: bool = False) -> list[dict]:
        """Return all APs across the MSP/controller, cached for CACHE_TTL seconds."""
        with self._lock:
            now = time.time()
            if not force and self._cache is not None and (now - self._cache_ts) < self.CACHE_TTL:
                return self._cache
            result = self._get(
                "/devices/known-devices",
                params={"page": 1, "pageSize": 1000},
            )
            raw = result.get("data", []) if isinstance(result, dict) else (result or [])
            aps = [d for d in raw if (d.get("type") or "").lower() == "ap"]
            self._cache = aps
            self._cache_ts = now
            return aps

    def get_ap_by_mac(self, mac: str) -> dict | None:
        target = self._norm_mac(mac)
        if not target:
            return None
        for ap in self.get_aps():
            if self._norm_mac(ap.get("mac", "")) == target:
                return ap
        return None

    def test_connection(self) -> dict:
        sites = self.get_sites()
        aps   = self.get_aps(force=True)
        matched = any(
            (s.get("siteName") == self.site_name or s.get("name") == self.site_name)
            for s in sites
        )
        return {
            "ok": True,
            "controller": self.base,
            "omada_id":   self.omada_id,
            "msp_mode":   bool(self._msp_mode),
            "sites_total": len(sites),
            "site_name":   self.site_name,
            "site_found":  matched,
            "ap_count":    len(aps),
            "sample": [
                {
                    "mac":    a.get("mac"),
                    "name":   a.get("name"),
                    "model":  a.get("model"),
                    "ip":     a.get("ip"),
                    "status": a.get("status"),
                    "site":   a.get("siteName"),
                    "customer": a.get("customerName"),
                }
                for a in aps[:5]
            ],
        }


# ── Module-level singleton ─────────────────────────────────────────────────────

_client: OmadaClient | None = None


def get_client() -> OmadaClient | None:
    return _client


def build_client(
    base_url: str,
    omada_id: str,
    client_id: str,
    client_secret: str,
    site_name: str = "Default",
    verify_ssl: bool = False,
    # Legacy kwargs — ignored
    admin_username: str = "",
    admin_password: str = "",
) -> OmadaClient:
    global _client
    _client = OmadaClient(
        base_url=base_url,
        omada_id=omada_id,
        client_id=client_id,
        client_secret=client_secret,
        site_name=site_name,
        verify_ssl=verify_ssl,
    )
    return _client


def clear_client():
    global _client
    _client = None

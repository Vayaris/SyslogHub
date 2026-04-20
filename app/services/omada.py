"""
TP-Link Omada SDN — Northbound OpenAPI (client_credentials flow).

Token URL : POST {base}/openapi/authorize/token?grant_type=client_credentials
Body (JSON) : {"omadacId": "...", "client_id": "...", "client_secret": "..."}
API calls  : GET {base}/openapi/v1/msp/{omadacId}/...   (MSP mode, auto-detected)
             GET {base}/openapi/v1/{omadacId}/...       (standard mode)
Headers    : Authorization: AccessToken={token}
             Accept: application/json   (required — without it the controller returns Spring 400)

Sites, customers (MSP) and devices are all discovered automatically — the caller
only provides base_url + omada_id + client credentials. `/devices/known-devices`
returns all equipment types (AP, switch, gateway, …).
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
        verify_ssl: bool = False,
    ):
        self.base          = base_url.rstrip("/")
        self.omada_id      = omada_id.strip()
        self.client_id     = client_id.strip()
        self.client_secret = client_secret
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

    def get_devices(self, force: bool = False) -> list[dict]:
        """Return all known devices (AP + switch + gateway…) across the MSP/controller."""
        with self._lock:
            now = time.time()
            if not force and self._cache is not None and (now - self._cache_ts) < self.CACHE_TTL:
                return self._cache
            result = self._get(
                "/devices/known-devices",
                params={"page": 1, "pageSize": 1000},
            )
            raw = result.get("data", []) if isinstance(result, dict) else (result or [])
            self._cache = raw
            self._cache_ts = now
            return raw

    def get_aps(self, force: bool = False) -> list[dict]:
        return [d for d in self.get_devices(force=force)
                if (d.get("type") or "").lower() == "ap"]

    def get_device_by_mac(self, mac: str) -> dict | None:
        target = self._norm_mac(mac)
        if not target:
            return None
        for d in self.get_devices():
            if self._norm_mac(d.get("mac", "")) == target:
                return d
        return None

    def get_ap_by_mac(self, mac: str) -> dict | None:
        d = self.get_device_by_mac(mac)
        if d and (d.get("type") or "").lower() == "ap":
            return d
        return None

    def test_connection(self) -> dict:
        sites = self.get_sites()
        devices = self.get_devices(force=True)

        counts: dict[str, int] = {}
        for d in devices:
            t = (d.get("type") or "unknown").lower()
            counts[t] = counts.get(t, 0) + 1

        customers = {
            d.get("customerName") for d in devices if d.get("customerName")
        }

        return {
            "ok": True,
            "controller":       self.base,
            "omada_id":         self.omada_id,
            "msp_mode":         bool(self._msp_mode),
            "sites_total":      len(sites),
            "customers_total":  len(customers) if self._msp_mode else None,
            "device_count":     len(devices),
            "device_count_by_type": counts,
            "sample": [
                {
                    "mac":      d.get("mac"),
                    "name":     d.get("name"),
                    "model":    d.get("model"),
                    "ip":       d.get("ip"),
                    "type":     d.get("type"),
                    "status":   d.get("status"),
                    "site":     d.get("siteName"),
                    "customer": d.get("customerName"),
                }
                for d in devices[:5]
            ],
        }


# ── Per-space client cache ─────────────────────────────────────────────────────
# Each space can point at its own Omada controller. Clients are built lazily
# from the space's DB row and cached until the space config changes.

_clients: dict[int, OmadaClient] = {}
_cache_lock = Lock()


def _fingerprint(space) -> tuple:
    """Tuple used to detect whether a cached client is still in sync with the DB."""
    return (
        (space.omada_base_url or "").rstrip("/"),
        (space.omada_id or "").strip(),
        (space.omada_client_id or "").strip(),
        space.omada_client_secret or "",
        bool(space.omada_verify_ssl),
    )


def is_configured(space) -> bool:
    return bool(
        space.omada_base_url
        and space.omada_id
        and space.omada_client_id
        and space.omada_client_secret
    )


def get_client_for_space(space) -> OmadaClient | None:
    """Build or return cached Omada client for a given Space row. None if unconfigured."""
    if not is_configured(space):
        _drop(space.id)
        return None
    fp = _fingerprint(space)
    with _cache_lock:
        cached = _clients.get(space.id)
        if cached is not None and getattr(cached, "_fp", None) == fp:
            return cached
        client = OmadaClient(
            base_url=space.omada_base_url,
            omada_id=space.omada_id,
            client_id=space.omada_client_id,
            client_secret=space.omada_client_secret,
            verify_ssl=bool(space.omada_verify_ssl),
        )
        client._fp = fp
        _clients[space.id] = client
        return client


def clear_client_for_space(space_id: int):
    _drop(space_id)


def clear_all_clients():
    with _cache_lock:
        _clients.clear()


def _drop(space_id: int):
    with _cache_lock:
        _clients.pop(space_id, None)

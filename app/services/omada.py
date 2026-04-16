"""TP-Link Omada SDN controller API client with in-memory cache."""
import time
from threading import Lock

try:
    import requests as _requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False


class OmadaClient:
    CACHE_TTL = 900  # 15 minutes

    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        site_name: str,
        verify_ssl: bool = False,
    ):
        self.base = url.rstrip("/")
        self.username = username
        self.password = password
        self.site_name = site_name
        self.verify = verify_ssl
        self._token: str | None = None
        self._omadac_id: str | None = None
        self._site_id: str | None = None
        self._cache: list[dict] | None = None
        self._cache_ts: float = 0.0
        self._lock = Lock()

    def _req(self, method: str, path: str, **kwargs):
        import requests
        headers = kwargs.pop("headers", {})
        cookies = kwargs.pop("cookies", {})
        if self._token:
            headers["Csrf-Token"] = self._token
            cookies["TPOMADA_SESSIONID"] = self._token
        r = requests.request(
            method,
            f"{self.base}{path}",
            headers=headers,
            cookies=cookies,
            verify=self.verify,
            timeout=15,
            **kwargs,
        )
        r.raise_for_status()
        return r.json()

    def _login(self):
        """Authenticate against the Omada controller."""
        # Step 1: get omadacId
        info = self._req("GET", "/api/info")
        self._omadac_id = info["result"]["omadacId"]

        # Step 2: login
        data = self._req(
            "POST",
            f"/{self._omadac_id}/api/v2/login",
            json={"username": self.username, "password": self.password},
        )
        if data.get("errorCode", -1) != 0:
            raise ValueError(f"Omada login failed: {data.get('msg', 'unknown error')}")
        self._token = data["result"]["token"]

    def _resolve_site(self):
        """Resolve site name to site ID."""
        data = self._req("GET", f"/{self._omadac_id}/api/v2/sites",
                         params={"pageSize": 100, "currentPage": 1})
        for site in data.get("result", {}).get("data", []):
            if site.get("name") == self.site_name:
                self._site_id = site["id"]
                return
        raise ValueError(f"Site Omada '{self.site_name}' introuvable")

    def get_aps(self, force: bool = False) -> list[dict]:
        """Return list of APs from Omada, cached for CACHE_TTL seconds."""
        with self._lock:
            if (
                not force
                and self._cache is not None
                and (time.time() - self._cache_ts) < self.CACHE_TTL
            ):
                return self._cache

            if not self._token:
                self._login()
            if not self._site_id:
                self._resolve_site()

            data = self._req(
                "GET",
                f"/{self._omadac_id}/api/v2/sites/{self._site_id}/devices/aps",
                params={"pageSize": 1000, "currentPage": 1},
            )
            self._cache = data.get("result", {}).get("data", [])
            self._cache_ts = time.time()
            return self._cache

    def get_ap_by_mac(self, mac: str) -> dict | None:
        """Find an AP by MAC address (case-insensitive)."""
        mac_lower = mac.lower()
        for ap in self.get_aps():
            if ap.get("mac", "").lower() == mac_lower:
                return ap
        return None

    def test_connection(self) -> dict:
        """Test the connection and return a summary."""
        aps = self.get_aps(force=True)
        return {
            "ok": True,
            "ap_count": len(aps),
            "site": self.site_name,
            "sample": [
                {"mac": ap.get("mac"), "name": ap.get("name"), "model": ap.get("model")}
                for ap in aps[:3]
            ],
        }


# ── Module-level singleton ────────────────────────────────────────────────────

_client: OmadaClient | None = None


def get_client() -> OmadaClient | None:
    return _client


def build_client(
    url: str,
    username: str,
    password: str,
    site_name: str,
    verify_ssl: bool = False,
) -> OmadaClient:
    global _client
    _client = OmadaClient(url, username, password, site_name, verify_ssl)
    return _client


def clear_client():
    global _client
    _client = None

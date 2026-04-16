"""
TP-Link Omada SDN — Northbound OpenAPI client (OAuth2 client_credentials).

Auth flow:
  POST {base}/openapi/authorize/token
  Body (JSON): {clientId, clientSecret, grantType: "client_credentials"}
  Response: {accessToken: "AT-...", refreshToken: "RT-...", expiresIn: 7200}

API calls:
  GET {base}/openapi/v1/{omadaId}/sites
  GET {base}/openapi/v1/{omadaId}/sites/{siteId}/devices
  Authorization: AccessToken={token}
"""
import time
from threading import Lock

try:
    import requests as _req
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False


class OmadaClient:
    CACHE_TTL = 900  # 15 min between AP list refreshes

    def __init__(
        self,
        base_url: str,
        omada_id: str,
        client_id: str,
        client_secret: str,
        site_name: str = "Default",
        verify_ssl: bool = False,
    ):
        self.base = base_url.rstrip("/")
        self.omada_id = omada_id.strip()
        self.client_id = client_id.strip()
        self.client_secret = client_secret.strip()
        self.site_name = site_name.strip()
        self.verify = verify_ssl

        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._token_expires_at: float = 0.0
        self._site_id: str | None = None
        self._cache: list[dict] | None = None
        self._cache_ts: float = 0.0
        self._lock = Lock()

    # ── private helpers ───────────────────────────────────────────────────────

    def _api(self, path: str) -> str:
        return f"{self.base}/openapi/v1/{self.omada_id}{path}"

    def _do_token_request(self, body: dict):
        import requests
        r = requests.post(
            f"{self.base}/openapi/authorize/token",
            json=body,
            verify=self.verify,
            timeout=15,
        )
        r.raise_for_status()
        data = r.json()
        if data.get("errorCode", -1) != 0:
            raise ValueError(f"Omada token error: {data.get('msg', 'unknown')}")
        res = data["result"]
        self._access_token = res["accessToken"]
        self._refresh_token = res.get("refreshToken")
        self._token_expires_at = time.time() + res.get("expiresIn", 7200) - 60

    def _ensure_token(self):
        if self._access_token and time.time() < self._token_expires_at:
            return
        # Try refresh token first to avoid full re-login
        if self._refresh_token:
            try:
                self._do_token_request({
                    "clientId": self.client_id,
                    "clientSecret": self.client_secret,
                    "grantType": "refresh_token",
                    "refreshToken": self._refresh_token,
                })
                return
            except Exception:
                self._refresh_token = None  # Expired — fall through to full login
        # Client credentials flow
        self._do_token_request({
            "clientId": self.client_id,
            "clientSecret": self.client_secret,
            "grantType": "client_credentials",
        })

    def _headers(self) -> dict:
        self._ensure_token()
        return {
            "Authorization": f"AccessToken={self._access_token}",
            "Content-Type": "application/json",
        }

    def _get(self, path: str, params: dict | None = None) -> dict | list:
        import requests
        r = requests.get(
            self._api(path),
            headers=self._headers(),
            params=params,
            verify=self.verify,
            timeout=15,
        )
        r.raise_for_status()
        data = r.json()
        if data.get("errorCode", -1) != 0:
            raise ValueError(f"Omada API error on {path}: {data.get('msg', 'unknown')}")
        return data.get("result", {})

    # ── public API ────────────────────────────────────────────────────────────

    def get_sites(self) -> list[dict]:
        result = self._get("/sites", params={"pageSize": 100, "page": 1})
        if isinstance(result, dict):
            return result.get("data", [])
        return result or []

    def _resolve_site_id(self) -> str:
        if self._site_id:
            return self._site_id
        sites = self.get_sites()
        for site in sites:
            if site.get("name") == self.site_name:
                self._site_id = site["siteId"]
                return self._site_id
        # Fallback: use first site if name not matched
        if sites:
            self._site_id = sites[0]["siteId"]
            return self._site_id
        raise ValueError(f"Aucun site trouvé sur le contrôleur Omada")

    def get_aps(self, force: bool = False) -> list[dict]:
        """Return AP list, cached for CACHE_TTL seconds."""
        with self._lock:
            now = time.time()
            if not force and self._cache is not None and (now - self._cache_ts) < self.CACHE_TTL:
                return self._cache

            site_id = self._resolve_site_id()
            result = self._get(f"/sites/{site_id}/devices", params={"pageSize": 1000, "page": 1})
            devices: list[dict] = result.get("data", []) if isinstance(result, dict) else (result or [])

            self._cache = devices
            self._cache_ts = now
            return self._cache

    def get_ap_by_mac(self, mac: str) -> dict | None:
        """Find an AP by MAC address (case-insensitive). Returns None if not found."""
        mac_lower = mac.lower()
        for ap in self.get_aps():
            if ap.get("mac", "").lower() == mac_lower:
                return ap
        return None

    def test_connection(self) -> dict:
        """Test auth + API access, return a summary dict."""
        sites = self.get_sites()
        aps = self.get_aps(force=True)
        matched_site = next((s for s in sites if s.get("name") == self.site_name), None)
        return {
            "ok": True,
            "controller": self.base,
            "omada_id": self.omada_id,
            "sites_total": len(sites),
            "site_name": self.site_name,
            "site_found": matched_site is not None,
            "ap_count": len(aps),
            "sample": [
                {
                    "mac": ap.get("mac"),
                    "name": ap.get("name"),
                    "model": ap.get("model"),
                    "ip": ap.get("ip") or ap.get("ipAddress"),
                    "status": ap.get("status"),
                }
                for ap in aps[:5]
            ],
        }


# ── Module-level singleton ────────────────────────────────────────────────────

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

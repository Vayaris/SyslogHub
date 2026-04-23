"""Defensive URL validation for outbound HTTP calls.

User-provided URLs (Omada controller base_url, OIDC discovery URL) flow
directly into `requests.get(...)` and Authlib. Without checks, an admin —
or an attacker who somehow reached the admin session — could point them at
cloud-instance metadata (169.254.169.254, fd00:ec2::254), loopback, or
arbitrary LAN hosts to scan the internal network.

`validate_url()` enforces:
  1. A scheme allow-list (default: HTTPS only; HTTPS+HTTP when explicitly
     opted in for LAN endpoints).
  2. A resolved-IP check: every address the hostname resolves to must be
     a regular public address (or an RFC1918 private address, when
     `allow_private=True` for LAN-only integrations like Omada).
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


def _is_forbidden_ip(ip_obj) -> tuple[bool, str]:
    """Return (forbidden, reason)."""
    if ip_obj.is_loopback:
        return True, "IP loopback"
    if ip_obj.is_link_local:
        return True, "IP link-local"
    if ip_obj.is_multicast:
        return True, "IP multicast"
    if ip_obj.is_reserved:
        return True, "IP réservée"
    if ip_obj.is_unspecified:
        return True, "IP non spécifiée (0.0.0.0/::)"
    return False, ""


def validate_url(url: str, allow_private: bool = False) -> tuple[bool, str]:
    """Return `(ok, reason_if_not_ok)`. A valid URL gets `(True, "")`.

    - `allow_private=False` (default): refuse cloud-metadata / loopback /
      link-local / multicast / reserved / unspecified / RFC1918 addresses,
      and require HTTPS.
    - `allow_private=True`: allow HTTP as well as HTTPS, and allow RFC1918
      addresses (a typical Omada controller sits on a LAN IP with a
      self-signed cert). Still refuse the forbidden set above (metadata
      endpoints live in the link-local range for example).
    """
    if not url or not isinstance(url, str):
        return False, "URL vide"

    try:
        parsed = urlparse(url.strip())
    except Exception:
        return False, "URL invalide"

    allowed_schemes = {"https", "http"} if allow_private else {"https"}
    if parsed.scheme.lower() not in allowed_schemes:
        if allow_private:
            return False, f"scheme {parsed.scheme!r} refusé (https ou http uniquement)"
        return False, f"scheme {parsed.scheme!r} refusé (https uniquement)"

    host = parsed.hostname
    if not host:
        return False, "host manquant"

    # Resolve every A/AAAA record to make DNS rebinding harder: all of them
    # must pass the check. If DNS fails, refuse — better than silently
    # passing a URL that might later resolve to something nasty.
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        return False, f"résolution DNS échouée: {e}"

    seen_ips: list[str] = []
    for family, _type, _proto, _canon, sockaddr in infos:
        ip_str = sockaddr[0]
        if ip_str in seen_ips:
            continue
        seen_ips.append(ip_str)
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"IP invalide: {ip_str}"

        bad, reason = _is_forbidden_ip(ip_obj)
        if bad:
            return False, f"{reason} ({ip_str})"
        if ip_obj.is_private and not allow_private:
            return False, f"IP privée refusée ({ip_str})"

    return True, ""

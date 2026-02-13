from __future__ import annotations

import ipaddress
import secrets

from fastapi import Request

_ACCESS_DENIED_DETAIL = (
    "Access denied. Configure MIMIR_API_TOKEN or enable "
    "MIMIR_ALLOW_LOCALHOST_WITHOUT_TOKEN for local use."
)


def is_loopback_host(host: str) -> bool:
    if not host:
        return False
    try:
        addr = ipaddress.ip_address(host.split("%", 1)[0])
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            return addr.ipv4_mapped.is_loopback
        return addr.is_loopback
    except ValueError:
        return host.lower() == "localhost"


def request_token(request: Request) -> str:
    header_value = request.headers.get("authorization", "")
    if header_value.lower().startswith("bearer "):
        return header_value[7:].strip()
    return request.headers.get("x-api-key", "").strip()


def authorize_request(
    request: Request,
    *,
    api_token: str,
    allow_localhost_without_token: bool,
    auth_disabled: bool = False,
) -> tuple[bool, int, str]:
    path = request.url.path
    if request.method == "OPTIONS" or path.startswith("/static"):
        return True, 200, ""

    if auth_disabled:
        return True, 200, ""

    configured_token = api_token.strip()
    if configured_token:
        provided = request_token(request)
        if provided and secrets.compare_digest(provided, configured_token):
            return True, 200, ""
        return False, 401, "Unauthorized"

    if allow_localhost_without_token:
        client_host = request.client.host if request.client else ""
        if is_loopback_host(client_host):
            return True, 200, ""

    return False, 403, _ACCESS_DENIED_DETAIL

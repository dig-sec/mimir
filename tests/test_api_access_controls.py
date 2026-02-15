from __future__ import annotations

from fastapi import Request

from mimir.api.access import authorize_request, is_loopback_host, request_token


def _make_request(
    *,
    path: str = "/api/search",
    method: str = "GET",
    headers: dict[str, str] | None = None,
    client_host: str = "127.0.0.1",
) -> Request:
    header_pairs = [
        (key.lower().encode("latin-1"), str(value).encode("latin-1"))
        for key, value in (headers or {}).items()
    ]
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("latin-1"),
        "query_string": b"",
        "headers": header_pairs,
        "client": (client_host, 42424),
        "server": ("testserver", 80),
    }
    return Request(scope)


def test_is_loopback_host_supports_ipv4_ipv6_and_mapped_ipv4():
    assert is_loopback_host("127.0.0.1")
    assert is_loopback_host("::1")
    assert is_loopback_host("::ffff:127.0.0.1")
    assert is_loopback_host("localhost")
    assert not is_loopback_host("203.0.113.9")


def test_request_token_prefers_bearer_and_falls_back_to_x_api_key():
    req = _make_request(
        headers={"Authorization": "Bearer  abc123  ", "X-API-Key": "fallback"}
    )
    assert request_token(req) == "abc123"

    fallback_req = _make_request(headers={"X-API-Key": "key-token"})
    assert request_token(fallback_req) == "key-token"


def test_access_control_bypasses_options_and_static():
    options_allowed = authorize_request(
        _make_request(method="OPTIONS", path="/api/search", client_host="203.0.113.3"),
        api_token="",
        allow_localhost_without_token=False,
    )
    static_allowed = authorize_request(
        _make_request(path="/static/main.js", client_host="203.0.113.3"),
        api_token="",
        allow_localhost_without_token=False,
    )
    assert options_allowed == (True, 200, "")
    assert static_allowed == (True, 200, "")


def test_access_control_requires_valid_token_when_configured():
    denied = authorize_request(
        _make_request(
            headers={"Authorization": "Bearer wrong"}, client_host="127.0.0.1"
        ),
        api_token="top-secret",
        allow_localhost_without_token=False,
    )
    allowed = authorize_request(
        _make_request(
            headers={"Authorization": "Bearer top-secret"},
            client_host="203.0.113.4",
        ),
        api_token="top-secret",
        allow_localhost_without_token=False,
    )
    assert denied == (False, 401, "Unauthorized")
    assert allowed == (True, 200, "")


def test_access_control_localhost_fallback_and_remote_denied():
    localhost_allowed = authorize_request(
        _make_request(client_host="::ffff:127.0.0.1"),
        api_token="",
        allow_localhost_without_token=True,
    )
    remote_denied = authorize_request(
        _make_request(client_host="203.0.113.8"),
        api_token="",
        allow_localhost_without_token=False,
    )
    assert localhost_allowed == (True, 200, "")
    assert remote_denied[0] is False
    assert remote_denied[1] == 403
    assert "Access denied" in remote_denied[2]

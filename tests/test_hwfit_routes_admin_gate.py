"""Regression tests for the hwfit routes' admin gate + remote-host validation.

Before this fix, /api/hwfit/{system,models,profiles,image-models} accepted a
`host` query param with no auth gate and no format check, and passed it
straight into an `ssh` argv (services/hwfit/hardware._run) — a classic SSH
option-injection vector (host=-oProxyCommand=...) reachable by ANY logged-in
user. The parallel cookbook remote-host feature was already gated by
require_admin + _validate_remote_host/_validate_ssh_port; this test pins that
hwfit now follows the same pattern.

Uses direct endpoint extraction + fake Request objects only — no real DB,
no network, mirrors tests/test_api_token_routes.py's approach.
"""

from types import SimpleNamespace

import pytest

from fastapi import HTTPException

import routes.hwfit_routes as mod


def _admin_mgr(is_admin: bool):
    return SimpleNamespace(is_admin=lambda u: is_admin, is_configured=True)


def _req(current_user, *, is_admin: bool = False):
    app_state = SimpleNamespace(auth_manager=_admin_mgr(is_admin))
    return SimpleNamespace(
        state=SimpleNamespace(current_user=current_user),
        headers={},
        app=SimpleNamespace(state=app_state),
    )


def _get_handler(method: str, path_fragment: str):
    router = mod.setup_hwfit_routes()
    for route in router.routes:
        path = getattr(route, "path", "")
        methods = getattr(route, "methods", None) or set()
        if path_fragment in path and method.upper() in methods:
            return route.endpoint
    raise KeyError(f"No {method} route matching '{path_fragment}'")


_ENDPOINTS = [
    ("GET", "/system"),
    ("GET", "/models"),
    ("GET", "/profiles"),
    ("GET", "/image-models"),
]


@pytest.mark.parametrize("method,fragment", _ENDPOINTS)
def test_hwfit_routes_require_admin(monkeypatch, method, fragment):
    """A logged-in non-admin user must be rejected with 403, not reach detect_system."""
    monkeypatch.setenv("AUTH_ENABLED", "true")
    handler = _get_handler(method, fragment)
    non_admin = _req("bob", is_admin=False)

    with pytest.raises(HTTPException) as exc:
        handler(request=non_admin)
    assert exc.value.status_code == 403


@pytest.mark.parametrize("method,fragment", _ENDPOINTS)
def test_hwfit_routes_reject_option_injecting_host(monkeypatch, method, fragment):
    """Even an admin can't smuggle ssh options through `host` — must be user@host."""
    monkeypatch.setenv("AUTH_ENABLED", "true")
    handler = _get_handler(method, fragment)
    admin = _req("alice", is_admin=True)

    with pytest.raises(HTTPException) as exc:
        handler(request=admin, host="-oProxyCommand=touch /tmp/pwn")
    assert exc.value.status_code == 400


@pytest.mark.parametrize("method,fragment", _ENDPOINTS)
def test_hwfit_routes_reject_malformed_ssh_port(monkeypatch, method, fragment):
    """ssh_port must be a plain numeric port, not another injection vector."""
    monkeypatch.setenv("AUTH_ENABLED", "true")
    handler = _get_handler(method, fragment)
    admin = _req("alice", is_admin=True)

    with pytest.raises(HTTPException) as exc:
        handler(request=admin, host="user@example.com", ssh_port="22 -oProxyCommand=x")
    assert exc.value.status_code == 400

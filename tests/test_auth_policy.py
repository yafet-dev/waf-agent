"""
Auth policy tests for the WAF Agent.

Covers the one rule that decides whether a caller may skip the bearer token and
the payload signature: the request must originate on this same machine.

Run with:
    pip install fastapi httpx cryptography pytest
    pytest tests/ -v

These use FastAPI's TestClient and stub every nginx side effect, so they are
safe to run anywhere -- no root, no nginx, no real config files touched.
"""
import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# ip_block imports fcntl, which is POSIX-only. Stub it when absent (Windows dev
# machines) so the module graph imports; the locking paths are never exercised
# by these tests.
try:  # pragma: no cover - platform dependent
    import fcntl  # noqa: F401
except ImportError:  # pragma: no cover
    _fcntl = types.ModuleType("fcntl")
    _fcntl.flock = lambda *a, **k: None
    _fcntl.LOCK_EX, _fcntl.LOCK_UN, _fcntl.LOCK_SH = 2, 8, 1
    sys.modules["fcntl"] = _fcntl

from fastapi import HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import src.main as main  # noqa: E402
from src.waf_toggle import toggle_waf_for_domain  # noqa: E402

# Peer address the next request should appear to arrive from.
_PEER = {"host": "127.0.0.1"}


@main.app.middleware("http")
async def _spoof_peer(request, call_next):
    """TestClient reports a peer of "testclient"; substitute a real address."""
    request.scope["client"] = (_PEER["host"], 12345)
    return await call_next(request)


client = TestClient(main.app)

TOGGLE_OK = {
    "status": "OK",
    "message": "toggled",
    "domain": "example.com",
    "modsecurity_status": "on",
}

LOOPBACK = ["127.0.0.1", "127.1.2.3", "::1", "::ffff:127.0.0.1"]

# Deliberately includes private/LAN addresses: the agent can disable the
# firewall, so a whole subnet is too wide a blast radius to trust silently.
NON_LOOPBACK = [
    "10.0.0.5",
    "172.16.0.1",
    "192.168.1.50",
    "100.64.0.1",
    "169.254.1.1",
    "196.188.250.141",
    "8.8.8.8",
    "fd00::1",
]


@pytest.fixture(autouse=True)
def _reset_peer(monkeypatch):
    _PEER["host"] = "127.0.0.1"
    monkeypatch.delenv("WAF_AGENT_STRICT_AUTH", raising=False)


def _toggle(**kwargs):
    body = {"domain": "example.com", "enabled": True}
    body.update(kwargs.pop("body", {}))
    return client.post("/waf/toggle", json=body, **kwargs)


@pytest.mark.parametrize("host", LOOPBACK)
def test_loopback_caller_needs_no_credentials(host):
    _PEER["host"] = host
    with patch.object(main, "toggle_waf_for_domain", return_value=TOGGLE_OK) as m:
        assert _toggle().status_code == 200
        assert m.call_args.kwargs["require_signature"] is False


@pytest.mark.parametrize("host", NON_LOOPBACK)
def test_non_loopback_caller_is_rejected_without_credentials(host):
    _PEER["host"] = host
    with patch.object(main, "toggle_waf_for_domain", return_value=TOGGLE_OK):
        assert _toggle().status_code == 403


def test_non_loopback_caller_with_token_still_requires_a_signature():
    _PEER["host"] = "196.188.250.141"
    with patch.object(main, "toggle_waf_for_domain", return_value=TOGGLE_OK) as m:
        response = _toggle(
            body={"signature": "abc"}, headers={"Authorization": "Bearer tok"}
        )
        assert response.status_code == 200
        assert m.call_args.kwargs["require_signature"] is True


@pytest.mark.parametrize(
    "header", ["X-Forwarded-For", "X-Real-IP", "Forwarded", "X-Forwarded-Host"]
)
def test_forwarded_request_is_never_treated_as_local(header):
    """Behind a proxy every request looks like loopback; refuse to trust it."""
    _PEER["host"] = "127.0.0.1"
    with patch.object(main, "toggle_waf_for_domain", return_value=TOGGLE_OK):
        assert _toggle(headers={header: "1.2.3.4"}).status_code == 403


def test_strict_auth_forces_credentials_even_on_loopback(monkeypatch):
    monkeypatch.setenv("WAF_AGENT_STRICT_AUTH", "true")
    _PEER["host"] = "127.0.0.1"
    with patch.object(main, "toggle_waf_for_domain", return_value=TOGGLE_OK):
        assert _toggle().status_code == 403


def test_ban_endpoint_follows_the_same_rule():
    payload = {"ip": "1.2.3.4", "domains": ["a.com"], "action": "ban"}
    with patch.object(main, "ban_unban_ip", return_value={"ok": True, "results": []}):
        _PEER["host"] = "127.0.0.1"
        assert client.post("/ban", json=payload).status_code == 200

        _PEER["host"] = "10.0.0.5"
        assert client.post("/ban", json=payload).status_code == 403


def test_geo_endpoints_follow_the_same_rule():
    with patch.object(main, "set_mode_atomic"), patch.object(
        main, "read_list", return_value={"ET"}
    ):
        _PEER["host"] = "127.0.0.1"
        assert client.post("/v1/geo/mode", json={"mode": "deny_only"}).status_code == 200

        _PEER["host"] = "8.8.8.8"
        assert client.post("/v1/geo/mode", json={"mode": "deny_only"}).status_code == 403


@pytest.mark.parametrize(
    "path", ["/health", "/v1/geo/health", "/status", "/v1/geo/status"]
)
def test_read_only_endpoints_stay_open(path):
    _PEER["host"] = "8.8.8.8"
    with patch.object(main, "get_ip_block_status", return_value={}), patch.object(
        main, "get_current_mode", return_value="deny_only"
    ), patch.object(main, "read_list", return_value=set()):
        assert client.get(path).status_code == 200


def test_a_supplied_signature_is_verified_even_on_loopback():
    """Relaxation tolerates an ABSENT signature, never a WRONG one."""
    with pytest.raises(HTTPException) as excinfo:
        toggle_waf_for_domain(
            "example.com", True, signature="bogus", require_signature=False
        )
    assert excinfo.value.status_code == 401


def test_missing_signature_is_rejected_when_required():
    with pytest.raises(HTTPException) as excinfo:
        toggle_waf_for_domain("example.com", True, signature=None, require_signature=True)
    assert excinfo.value.status_code == 400

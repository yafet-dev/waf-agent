"""
Per-domain geo access control tests.

Verifies the two properties that matter: nothing is hardcoded to a single
domain, and the first request for a domain creates everything nginx needs.

Directories are redirected into a tmp_path and nginx calls are stubbed, so this
touches no real config and needs no root.
"""
import sys
import types
from pathlib import Path
from unittest.mock import patch

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


@pytest.fixture
def geo_dirs(tmp_path, monkeypatch):
    """Redirect every geo path into tmp_path and stub the nginx reload."""
    lists_dir = tmp_path / "geo-lists"
    servers_dir = tmp_path / "geo-servers"
    conf_d = tmp_path / "conf.d"

    monkeypatch.setattr(geo, "GEO_LISTS_DIR", lists_dir)
    monkeypatch.setattr(geo, "GEO_SERVERS_DIR", servers_dir)
    monkeypatch.setattr(geo, "NGINX_CONF_D", conf_d)
    monkeypatch.setattr(geo, "validate_and_reload_nginx", lambda: None)

    return types.SimpleNamespace(
        lists=lists_dir, servers=servers_dir, conf_d=conf_d, root=tmp_path
    )


# ─── domain validation ──────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "raw,expected",
    [
        ("example.com", "example.com"),
        ("EXAMPLE.COM", "example.com"),
        ("  gnzabe.com  ", "gnzabe.com"),
        ("waf.zergaw.et", "waf.zergaw.et"),
        ("example.com.", "example.com"),
        ("my-site.co.uk", "my-site.co.uk"),
    ],
)
def test_valid_domains_are_normalized(raw, expected):
    assert geo.normalize_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "../../etc/passwd",
        "example.com/../../etc/nginx",
        "exa mple.com",
        "example",          # single label, no dot
        "-example.com",
        "example-.com",
        "exa$mple.com",
        "example\n.com",       # embedded newline, not merely trailing
        "example.com\x00.evil",
        "a" * 300 + ".com",
    ],
)
def test_path_traversal_and_junk_domains_are_rejected(raw):
    """The only guard between a request body and a file path."""
    with pytest.raises(HTTPException) as excinfo:
        geo.normalize_domain(raw)
    assert excinfo.value.status_code == 400


def test_surrounding_whitespace_is_stripped_not_rejected():
    """Trailing newlines arrive from config files and env vars routinely."""
    assert geo.normalize_domain("example.com\n") == "example.com"
    assert geo.normalize_domain("\t example.com \n") == "example.com"


# ─── provisioning ───────────────────────────────────────────────────────────

def test_first_request_creates_every_file(geo_dirs):
    domain = "gnzabe.com"
    assert not geo_dirs.lists.exists()

    geo.ensure_domain_files(domain)

    for path in (
        geo.get_allow_list_path(domain),
        geo.get_deny_list_path(domain),
        geo.get_map_config_path(domain),
        geo.get_allow_only_conf_path(domain),
        geo.get_deny_only_conf_path(domain),
        geo.get_active_conf_path(domain),
    ):
        assert path.exists(), f"{path} should have been created"


def test_provisioning_is_idempotent(geo_dirs):
    domain = "gnzabe.com"
    assert geo.ensure_domain_files(domain) is True
    assert geo.ensure_domain_files(domain) is False, "second call should change nothing"


def test_files_are_named_for_the_domain_not_hardcoded(geo_dirs):
    """The original bug: every path was pinned to waf.zergaw.et."""
    for domain in ("gnzabe.com", "waf.zergaw.et", "another-site.org"):
        geo.ensure_domain_files(domain)
        assert geo.get_allow_list_path(domain).name == f"{domain}.allow"
        assert geo.get_deny_list_path(domain).name == f"{domain}.deny"
        assert domain in geo.get_map_config_path(domain).name

    # All three coexist without clobbering each other.
    assert len(list(geo_dirs.lists.glob("*.allow"))) == 3


def test_map_uses_a_domain_scoped_nginx_variable(geo_dirs):
    geo.ensure_domain_files("gnzabe.com")
    content = geo.get_map_config_path("gnzabe.com").read_text()

    assert "$geo_allow_gnzabe_com" in content
    assert "$geo_deny_gnzabe_com" in content
    assert str(geo.get_allow_list_path("gnzabe.com")) in content


def test_two_domains_get_independent_variables(geo_dirs):
    geo.ensure_domain_files("a-site.com")
    geo.ensure_domain_files("b-site.com")

    a = geo.get_map_config_path("a-site.com").read_text()
    b = geo.get_map_config_path("b-site.com").read_text()

    assert "$geo_allow_a_site_com" in a and "$geo_allow_b_site_com" not in a
    assert "$geo_allow_b_site_com" in b and "$geo_allow_a_site_com" not in b


def test_new_domain_defaults_to_blocking_nobody(geo_dirs):
    """A fresh domain must not lock anyone out before rules are set."""
    domain = "gnzabe.com"
    geo.ensure_domain_files(domain)

    assert geo.get_current_mode(domain) == "deny_only"
    assert geo.read_list(geo.get_deny_list_path(domain)) == set()


# ─── lists and modes ────────────────────────────────────────────────────────

def test_country_lists_are_written_per_domain(geo_dirs):
    geo.ensure_domain_files("a-site.com")
    geo.ensure_domain_files("b-site.com")

    geo.write_list_atomic(geo.get_allow_list_path("a-site.com"), {"ET", "KE"})
    geo.write_list_atomic(geo.get_deny_list_path("b-site.com"), {"CN"})

    assert geo.read_list(geo.get_allow_list_path("a-site.com")) == {"ET", "KE"}
    assert geo.read_list(geo.get_allow_list_path("b-site.com")) == set()
    assert geo.read_list(geo.get_deny_list_path("b-site.com")) == {"CN"}


def test_list_file_uses_nginx_map_syntax(geo_dirs):
    geo.ensure_domain_files("gnzabe.com")
    geo.write_list_atomic(geo.get_allow_list_path("gnzabe.com"), {"ET", "KE"})

    assert geo.get_allow_list_path("gnzabe.com").read_text() == "ET 1;\nKE 1;\n"


def test_mode_switching_is_per_domain(geo_dirs):
    geo.ensure_domain_files("a-site.com")
    geo.ensure_domain_files("b-site.com")

    geo.set_mode_atomic("a-site.com", "allow_only")

    assert geo.get_current_mode("a-site.com") == "allow_only"
    assert geo.get_current_mode("b-site.com") == "deny_only"


def test_active_conf_points_at_the_selected_mode(geo_dirs):
    domain = "gnzabe.com"
    geo.set_mode_atomic(domain, "allow_only")
    assert str(geo.get_allow_only_conf_path(domain)) in geo.get_active_conf_path(domain).read_text()

    geo.set_mode_atomic(domain, "deny_only")
    assert str(geo.get_deny_only_conf_path(domain)) in geo.get_active_conf_path(domain).read_text()


def test_set_mode_rejects_an_unknown_mode(geo_dirs):
    with pytest.raises(ValueError):
        geo.set_mode_atomic("gnzabe.com", "sideways")


def test_unconfigured_domain_reports_unknown_without_creating_anything(geo_dirs):
    """Reading status must never provision."""
    status = geo.get_domain_status("never-seen.com")

    assert status == {
        "domain": "never-seen.com",
        "mode": "unknown",
        "allow": [],
        "deny": [],
    }
    assert not geo.get_allow_list_path("never-seen.com").exists()


def test_status_lists_every_configured_domain(geo_dirs):
    geo.ensure_domain_files("a-site.com")
    geo.ensure_domain_files("b-site.com")
    geo.write_list_atomic(geo.get_deny_list_path("a-site.com"), {"CN"})

    status = geo.get_all_status()

    assert status["total_domains"] == 2
    by_domain = {d["domain"]: d for d in status["domains"]}
    assert by_domain["a-site.com"]["deny"] == ["CN"]
    assert by_domain["b-site.com"]["deny"] == []


# ─── rollback ───────────────────────────────────────────────────────────────

def test_a_failed_nginx_reload_restores_the_previous_list(geo_dirs, monkeypatch):
    domain = "gnzabe.com"
    geo.ensure_domain_files(domain)
    allow_path = geo.get_allow_list_path(domain)
    geo.write_list_atomic(allow_path, {"ET"})

    def boom():
        raise HTTPException(status_code=500, detail="nginx -t failed")

    monkeypatch.setattr(geo, "validate_and_reload_nginx", boom)

    with pytest.raises(HTTPException):
        geo.write_list_atomic(allow_path, {"ET", "KE", "US"})

    assert geo.read_list(allow_path) == {"ET"}, "should have rolled back"


def test_a_failed_nginx_reload_restores_the_previous_mode(geo_dirs, monkeypatch):
    domain = "gnzabe.com"
    geo.set_mode_atomic(domain, "allow_only")

    def boom():
        raise HTTPException(status_code=500, detail="nginx -t failed")

    monkeypatch.setattr(geo, "validate_and_reload_nginx", boom)

    with pytest.raises(HTTPException):
        geo.set_mode_atomic(domain, "deny_only")

    assert geo.get_current_mode(domain) == "allow_only", "should have rolled back"


# ─── vhost wiring ───────────────────────────────────────────────────────────

def test_geo_include_is_added_to_the_vhost_after_server_name(geo_dirs, tmp_path):
    domain = "gnzabe.com"
    vhost = tmp_path / f"{domain}.conf"
    vhost.write_text(
        "server {\n"
        "    listen 80;\n"
        f"    server_name {domain};\n"
        "    location / { proxy_pass http://127.0.0.1:3000; }\n"
        "}\n"
    )

    geo.ensure_domain_files(domain)
    with patch.object(geo, "get_nginx_config_path", return_value=vhost):
        changed, _ = geo.ensure_vhost_includes_geo(domain)

    assert changed is True
    lines = vhost.read_text().split("\n")
    server_name_idx = next(i for i, l in enumerate(lines) if "server_name" in l)
    assert str(geo.get_active_conf_path(domain)) in lines[server_name_idx + 1]


def test_geo_include_is_not_added_twice(geo_dirs, tmp_path):
    domain = "gnzabe.com"
    vhost = tmp_path / f"{domain}.conf"
    vhost.write_text(
        f"server {{\n    server_name {domain};\n}}\n"
    )

    geo.ensure_domain_files(domain)
    with patch.object(geo, "get_nginx_config_path", return_value=vhost):
        assert geo.ensure_vhost_includes_geo(domain)[0] is True
        assert geo.ensure_vhost_includes_geo(domain)[0] is False

    assert vhost.read_text().count("active.conf") == 1


def test_a_missing_vhost_is_not_fatal(geo_dirs):
    """Geo files still get written; enforcement starts when the site exists."""
    domain = "not-deployed-yet.com"
    geo.ensure_domain_files(domain)

    def missing(_):
        raise FileNotFoundError("no vhost")

    with patch.object(geo, "get_nginx_config_path", side_effect=missing):
        changed, backup = geo.ensure_vhost_includes_geo(domain)

    assert changed is False and backup is None
    assert geo.get_allow_list_path(domain).exists()


def test_an_unreadable_vhost_path_is_not_fatal(geo_dirs, tmp_path):
    """
    A path that resolves but cannot be read must not 500 the request -- a
    country list should stay editable even when the site is half-deployed.
    """
    domain = "half-deployed.com"
    geo.ensure_domain_files(domain)
    ghost = tmp_path / "sites-available" / domain  # never created

    with patch.object(geo, "get_nginx_config_path", return_value=ghost):
        changed, backup = geo.ensure_vhost_includes_geo(domain)

    assert changed is False and backup is None


def test_list_edits_survive_a_missing_vhost(geo_dirs):
    """The end-to-end shape of the bug: syncing a not-yet-deployed domain."""
    domain = "not-deployed-yet.com"

    def missing(_):
        raise FileNotFoundError("no vhost")

    with patch.object(geo, "get_nginx_config_path", side_effect=missing):
        geo.ensure_domain_ready(domain)
        geo.write_list_atomic(geo.get_deny_list_path(domain), {"US"})
        geo.set_mode_atomic(domain, "deny_only")

    assert geo.get_domain_status(domain) == {
        "domain": domain,
        "mode": "deny_only",
        "allow": [],
        "deny": ["US"],
    }

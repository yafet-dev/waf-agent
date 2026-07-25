"""
Tests for locating the nginx server block that serves a domain.

The production defect this guards against: the agent resolved a vhost purely by
filename, trying gnzabe.com, gnzabe.com.conf, gnzabe_com and gnzabe_com.conf.
A site stored as gnzabe-apis.conf containing

    server_name gnzabe.com www.gnzabe.com;

was therefore never found. Geo and IP rules were written, nginx was reloaded,
HTTP 200 came back, the database was updated -- and nothing was enforced.
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

import src.nginx_utils as nginx_utils  # noqa: E402
from src.nginx_utils import (  # noqa: E402
    find_server_blocks_for_domain,
    insert_include_into_server_blocks,
    server_name_matches,
)


@pytest.fixture
def tree(tmp_path, monkeypatch):
    available = tmp_path / "sites-available"
    enabled = tmp_path / "sites-enabled"
    conf_d = tmp_path / "conf.d"
    for directory in (available, enabled, conf_d):
        directory.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(nginx_utils, "NGINX_SITES_AVAILABLE", available)
    monkeypatch.setattr(nginx_utils, "NGINX_SITES_ENABLED", enabled)
    monkeypatch.setattr(nginx_utils, "NGINX_CONF_D", conf_d)

    def write(filename, body, directory=None):
        path = (directory or available) / filename
        path.write_text(body)
        return path

    return types.SimpleNamespace(
        available=available, enabled=enabled, conf_d=conf_d, write=write
    )


# ─── server_name matching ───────────────────────────────────────────────────

@pytest.mark.parametrize(
    "names,domain,expected",
    [
        (["gnzabe.com"], "gnzabe.com", True),
        (["gnzabe.com", "www.gnzabe.com"], "gnzabe.com", True),
        (["gnzabe.com", "www.gnzabe.com"], "www.gnzabe.com", True),
        (["GNZABE.COM"], "gnzabe.com", True),
        (["gnzabe.com."], "gnzabe.com", True),
        (["*.gnzabe.com"], "api.gnzabe.com", True),
        ([".gnzabe.com"], "gnzabe.com", True),
        ([".gnzabe.com"], "api.gnzabe.com", True),
        # Non-matches
        (["other.com"], "gnzabe.com", False),
        (["notgnzabe.com"], "gnzabe.com", False),
        (["gnzabe.com.evil.net"], "gnzabe.com", False),
        (["api.gnzabe.com"], "gnzabe.com", False),
        ([], "gnzabe.com", False),
        # The catch-all default server is not a claim to serve this domain.
        (["_"], "gnzabe.com", False),
    ],
)
def test_server_name_matching(names, domain, expected):
    assert server_name_matches(names, domain) is expected


# ─── discovery ──────────────────────────────────────────────────────────────

def test_finds_a_vhost_whose_filename_does_not_match(tree):
    """The exact production case."""
    tree.write(
        "gnzabe-apis.conf",
        "server {\n"
        "    listen 80;\n"
        "    server_name gnzabe.com www.gnzabe.com;\n"
        "}\n",
    )

    blocks = find_server_blocks_for_domain("gnzabe.com")

    assert len(blocks) == 1
    assert blocks[0].path.name == "gnzabe-apis.conf"
    assert blocks[0].server_names == ["gnzabe.com", "www.gnzabe.com"]


def test_finds_every_block_for_a_domain(tree):
    tree.write(
        "site.conf",
        "server {\n    listen 80;\n    server_name gnzabe.com;\n}\n"
        "server {\n    listen 443 ssl;\n    server_name gnzabe.com;\n}\n",
    )

    assert len(find_server_blocks_for_domain("gnzabe.com")) == 2


def test_finds_blocks_across_multiple_files(tree):
    tree.write("a.conf", "server {\n    server_name gnzabe.com;\n}\n")
    tree.write("b.conf", "server {\n    server_name gnzabe.com;\n}\n")
    tree.write("c.conf", "server {\n    server_name unrelated.com;\n}\n")

    blocks = find_server_blocks_for_domain("gnzabe.com")
    assert {b.path.name for b in blocks} == {"a.conf", "b.conf"}


def test_ignores_unrelated_domains(tree):
    tree.write("other.conf", "server {\n    server_name unrelated.com;\n}\n")
    assert find_server_blocks_for_domain("gnzabe.com") == []


def test_nested_location_blocks_do_not_break_parsing(tree):
    tree.write(
        "nested.conf",
        "server {\n"
        "    location / {\n"
        "        if ($x) { return 403; }\n"
        "    }\n"
        "    server_name gnzabe.com;\n"
        "}\n"
        "server {\n"
        "    server_name second.com;\n"
        "}\n",
    )

    blocks = find_server_blocks_for_domain("gnzabe.com")
    assert len(blocks) == 1
    assert find_server_blocks_for_domain("second.com") != []


def test_commented_server_name_is_ignored(tree):
    tree.write(
        "commented.conf",
        "server {\n"
        "    # server_name gnzabe.com;\n"
        "    server_name other.com;\n"
        "}\n",
    )
    assert find_server_blocks_for_domain("gnzabe.com") == []


def test_backup_files_are_skipped(tree):
    tree.write("site.conf.bak-20260101_000000", "server {\n server_name gnzabe.com;\n}\n")
    tree.write("site.conf.backup", "server {\n server_name gnzabe.com;\n}\n")
    assert find_server_blocks_for_domain("gnzabe.com") == []


def test_the_same_file_reached_twice_is_only_returned_once(tree):
    real = tree.write("gnzabe-apis.conf", "server {\n    server_name gnzabe.com;\n}\n")
    link = tree.enabled / "gnzabe-apis.conf"
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform/account")

    blocks = find_server_blocks_for_domain("gnzabe.com")
    assert len(blocks) == 1


# ─── insertion ──────────────────────────────────────────────────────────────

def test_include_is_inserted_after_server_name(tree):
    vhost = tree.write(
        "gnzabe-apis.conf",
        "server {\n"
        "    listen 80;\n"
        "    server_name gnzabe.com;\n"
        "    root /var/www;\n"
        "}\n",
    )

    changed = insert_include_into_server_blocks("gnzabe.com", "include /etc/x.conf;")

    assert len(changed) == 1
    lines = vhost.read_text().split("\n")
    name_index = next(i for i, l in enumerate(lines) if "server_name" in l)
    assert lines[name_index + 1].strip() == "include /etc/x.conf;"
    assert lines[name_index + 1].startswith("    "), "indentation should match"


def test_insertion_is_idempotent(tree):
    vhost = tree.write("s.conf", "server {\n    server_name gnzabe.com;\n}\n")

    assert len(insert_include_into_server_blocks("gnzabe.com", "include /etc/x.conf;")) == 1
    assert insert_include_into_server_blocks("gnzabe.com", "include /etc/x.conf;") == []
    assert vhost.read_text().count("include /etc/x.conf;") == 1


def test_insertion_only_touches_matching_blocks(tree):
    vhost = tree.write(
        "multi.conf",
        "server {\n    server_name keepme.com;\n}\n"
        "server {\n    server_name gnzabe.com;\n}\n",
    )

    insert_include_into_server_blocks("gnzabe.com", "include /etc/x.conf;")

    first, second = vhost.read_text().split("server {")[1:3]
    assert "include /etc/x.conf;" not in first
    assert "include /etc/x.conf;" in second


def test_insertion_covers_all_matching_blocks_in_one_file(tree):
    vhost = tree.write(
        "two.conf",
        "server {\n    listen 80;\n    server_name gnzabe.com;\n}\n"
        "server {\n    listen 443;\n    server_name gnzabe.com;\n}\n",
    )

    insert_include_into_server_blocks("gnzabe.com", "include /etc/x.conf;")

    assert vhost.read_text().count("include /etc/x.conf;") == 2


def test_a_backup_is_written_before_editing(tree):
    vhost = tree.write("s.conf", "server {\n    server_name gnzabe.com;\n}\n")
    original = vhost.read_text()

    changed = insert_include_into_server_blocks("gnzabe.com", "include /etc/x.conf;")

    _, backup = changed[0]
    assert backup is not None and backup.exists()
    assert backup.read_text() == original


def test_a_block_without_server_name_still_gets_the_include(tree):
    """Matched by filename fallback elsewhere; insertion must not crash."""
    vhost = tree.write(
        "s.conf",
        "server {\n    server_name gnzabe.com;\n}\n",
    )
    insert_include_into_server_blocks("gnzabe.com", "include /etc/x.conf;")
    assert "include /etc/x.conf;" in vhost.read_text()


def test_no_matching_block_raises(tree):
    tree.write("other.conf", "server {\n    server_name unrelated.com;\n}\n")

    with pytest.raises(FileNotFoundError) as excinfo:
        insert_include_into_server_blocks("gnzabe.com", "include /etc/x.conf;")

    assert "gnzabe.com" in str(excinfo.value)


def test_resulting_config_keeps_balanced_braces(tree):
    vhost = tree.write(
        "s.conf",
        "server {\n"
        "    server_name gnzabe.com;\n"
        "    location / {\n"
        "        proxy_pass http://127.0.0.1:3000;\n"
        "    }\n"
        "}\n",
    )

    insert_include_into_server_blocks("gnzabe.com", "include /etc/x.conf;")

    text = vhost.read_text()
    assert text.count("{") == text.count("}")

"""
Nginx configuration utilities for WAF Agent
"""

import re
import subprocess
import shutil
import logging
from pathlib import Path
from typing import List, NamedTuple, Optional, Tuple
from .config import (
    NGINX_SITES_AVAILABLE,
    NGINX_SITES_ENABLED,
    NGINX_CONF_D,
    NGINX_BINARY,
    SYSTEMCTL_BINARY,
    find_binary,
)

logger = logging.getLogger(__name__)


class ServerBlock(NamedTuple):
    """A `server { ... }` block located inside a config file."""

    path: Path
    """File the block lives in (a real file, symlinks resolved)."""
    start: int
    """Index of the `server` keyword in the file's text."""
    body_start: int
    """Index just after the block's opening brace."""
    body_end: int
    """Index of the block's closing brace."""
    server_names: List[str]
    """Names from the block's server_name directive, lowercased."""


def _strip_comments(content: str) -> str:
    """
    Blank out `#` comments while preserving offsets, so indexes computed on the
    stripped text still address the original. Quoted `#` is left alone.
    """
    out = []
    in_single = in_double = in_comment = False

    for char in content:
        if in_comment:
            # Keep newlines so line structure survives.
            out.append("\n" if char == "\n" else " ")
            if char == "\n":
                in_comment = False
            continue

        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double:
            in_comment = True
            out.append(" ")
            continue

        out.append(char)

    return "".join(out)


def _find_server_blocks(content: str) -> List[Tuple[int, int, int]]:
    """
    Locate top-level `server { ... }` blocks.

    Returns (keyword_index, body_start, body_end) triples. Brace depth is
    tracked so nested blocks such as `location { }` do not end the server
    block early.
    """
    stripped = _strip_comments(content)
    blocks: List[Tuple[int, int, int]] = []

    for match in re.finditer(r'\bserver\b\s*\{', stripped):
        body_start = match.end()
        depth = 1
        index = body_start

        while index < len(stripped) and depth > 0:
            if stripped[index] == "{":
                depth += 1
            elif stripped[index] == "}":
                depth -= 1
            index += 1

        if depth == 0:
            blocks.append((match.start(), body_start, index - 1))
        else:
            logger.warning("Unbalanced braces while scanning a server block")

    return blocks


def _server_names_in(block_text: str) -> List[str]:
    """Extract the names from a block's server_name directive."""
    match = re.search(r'\bserver_name\s+([^;]+);', _strip_comments(block_text))
    if not match:
        return []

    return [
        name.strip().rstrip('.').lower()
        for name in match.group(1).split()
        if name.strip()
    ]


def server_name_matches(server_names: List[str], domain: str) -> bool:
    """
    Decide whether a server_name list serves `domain`.

    Handles the exact name, nginx's leading-dot form (".example.com" means the
    domain and its subdomains), and wildcards ("*.example.com"). The catch-all
    "_" is deliberately NOT treated as a match: it is the default server, not a
    declaration that it serves this domain.
    """
    target = domain.strip().rstrip('.').lower()

    for raw_name in server_names:
        # Normalize here too: this is a public helper, so it must not depend on
        # the caller having canonicalized the names first.
        name = raw_name.strip().rstrip('.').lower()

        if not name:
            continue
        if name == target:
            return True
        if name.startswith('.') and (target == name[1:] or target.endswith(name)):
            return True
        if name.startswith('*.') and target.endswith(name[1:]):
            return True

    return False


def _candidate_config_files() -> List[Path]:
    """
    Every file that could hold a vhost, de-duplicated by real path.

    sites-enabled is listed first because it is what nginx actually loads;
    entries there are usually symlinks into sites-available, and resolving them
    means edits land on the real file.
    """
    seen = set()
    files: List[Path] = []

    for directory in (NGINX_SITES_ENABLED, NGINX_SITES_AVAILABLE, NGINX_CONF_D):
        if not directory.exists():
            continue

        for entry in sorted(directory.iterdir()):
            try:
                if not entry.is_file():
                    continue
                # Skip our own backups and temp files.
                if re.search(r'\.(bak|backup|tmp|dpkg-dist|dpkg-old|save)', entry.name):
                    continue
                if entry.name.endswith("~"):
                    continue

                resolved = entry.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                files.append(resolved)
            except OSError as e:
                logger.warning(f"Skipping unreadable config entry {entry}: {e}")

    return files


def find_server_blocks_for_domain(domain: str) -> List[ServerBlock]:
    """
    Find every server block that actually serves `domain`.

    Matches on the server_name directive rather than the filename. A vhost is
    routinely stored under an unrelated name -- gnzabe-apis.conf holding
    `server_name gnzabe.com www.gnzabe.com;` is the case that motivated this --
    and a filename-only lookup silently finds nothing, so rules get written but
    never enforced.

    A domain commonly appears in more than one block (an :80 redirect plus the
    :443 server); all of them are returned so enforcement covers each.
    """
    matches: List[ServerBlock] = []

    for path in _candidate_config_files():
        try:
            content = path.read_text()
        except (OSError, UnicodeDecodeError) as e:
            logger.warning(f"Skipping unreadable config {path}: {e}")
            continue

        if "server_name" not in content:
            continue

        for keyword_index, body_start, body_end in _find_server_blocks(content):
            names = _server_names_in(content[body_start:body_end])
            if server_name_matches(names, domain):
                matches.append(
                    ServerBlock(
                        path=path,
                        start=keyword_index,
                        body_start=body_start,
                        body_end=body_end,
                        server_names=names,
                    )
                )

    if matches:
        logger.info(
            f"Found {len(matches)} server block(s) for {domain} in: "
            + ", ".join(sorted({str(m.path) for m in matches}))
        )
    else:
        logger.warning(f"No server block declares server_name for {domain}")

    return matches


def get_nginx_config_path(domain: str) -> Path:
    """
    Get the nginx config file for a domain.

    Resolves by server_name first, falling back to filename guesses only when
    no block declares the domain.
    """
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    domain = domain.strip()

    blocks = find_server_blocks_for_domain(domain)
    if blocks:
        return blocks[0].path

    if not NGINX_SITES_AVAILABLE.exists():
        raise FileNotFoundError(
            f"Nginx sites-available directory not found: {NGINX_SITES_AVAILABLE}"
        )

    # Fall back to filename conventions, for a config that has no server_name
    # (rare, but a redirect-only stub may omit it).
    for var in (
        domain,
        f"{domain}.conf",
        domain.replace(".", "_"),
        f"{domain.replace('.', '_')}.conf",
    ):
        potential_file = NGINX_SITES_AVAILABLE / var
        if potential_file.exists():
            logger.info(f"Found config by filename: {potential_file}")
            return potential_file

    available = ", ".join(
        sorted(f.name for f in NGINX_SITES_AVAILABLE.glob("*") if f.is_file())
    )
    raise FileNotFoundError(
        f"No nginx server block declares server_name for '{domain}', and no "
        f"config file is named after it. Searched {NGINX_SITES_ENABLED}, "
        f"{NGINX_SITES_AVAILABLE} and {NGINX_CONF_D}. "
        f"Available in sites-available: {available}"
    )


def insert_include_into_server_blocks(
    domain: str, include_line: str
) -> List[Tuple[Path, Optional[Path]]]:
    """
    Add `include_line` to every server block serving `domain`.

    Returns a list of (changed_file, backup_file) pairs; backup_file is None if
    the backup could not be written. A block that already contains the line is
    left alone, so this is safe to call on every request.

    Raises FileNotFoundError when no block serves the domain. That is a hard
    failure on purpose: writing rule files while silently skipping the include
    leaves the caller believing a security control is active when nginx never
    evaluates it.
    """
    blocks = find_server_blocks_for_domain(domain)

    if not blocks:
        raise FileNotFoundError(
            f"No nginx server block declares server_name for '{domain}'. "
            f"Rules cannot be enforced until one does. Searched "
            f"{NGINX_SITES_ENABLED}, {NGINX_SITES_AVAILABLE} and {NGINX_CONF_D}."
        )

    from datetime import datetime

    changed: List[Tuple[Path, Optional[Path]]] = []

    # Group by file so one file is read, edited and written once even when it
    # holds several matching blocks.
    by_path: dict = {}
    for block in blocks:
        by_path.setdefault(block.path, []).append(block)

    for path, path_blocks in by_path.items():
        content = path.read_text()
        original = content

        # Work from the last block backwards so earlier offsets stay valid.
        for block in sorted(path_blocks, key=lambda b: b.body_start, reverse=True):
            body = content[block.body_start : block.body_end]

            if include_line in body:
                logger.debug(
                    f"{path}: include already present in block for "
                    f"{', '.join(block.server_names) or 'unnamed'}"
                )
                continue

            insert_at, indent = _pick_insert_point(content, block)
            content = (
                content[:insert_at]
                + f"\n{indent}{include_line}"
                + content[insert_at:]
            )

        if content == original:
            continue

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path: Optional[Path] = path.with_suffix(f"{path.suffix}.bak-{timestamp}")
        try:
            shutil.copy2(path, backup_path)
        except OSError as e:
            logger.warning(f"Could not back up {path}: {e}")
            backup_path = None

        path.write_text(content)
        changed.append((path, backup_path))
        logger.info(f"Added '{include_line}' to {path}")

    return changed


def _pick_insert_point(content: str, block: ServerBlock) -> Tuple[int, str]:
    """
    Choose where inside a server block the include should go.

    Prefers the end of the server_name line so the rule sits with the other
    per-site directives; falls back to just after the opening brace.
    Returns (index, indent_string).
    """
    body = content[block.body_start : block.body_end]
    match = re.search(r'\bserver_name\s+[^;]+;', _strip_comments(body))

    if match:
        absolute_end = block.body_start + match.end()
        line_start = content.rfind("\n", 0, block.body_start + match.start()) + 1
        line = content[line_start : block.body_start + match.start()]
        indent = line[: len(line) - len(line.lstrip())] or "    "
        return absolute_end, indent

    # No server_name in this block: put it right after the opening brace,
    # indented one level past the `server` keyword.
    line_start = content.rfind("\n", 0, block.start) + 1
    server_line = content[line_start : block.start]
    base_indent = server_line[: len(server_line) - len(server_line.lstrip())]
    return block.body_start, base_indent + "    "


def read_nginx_config(config_path: Path) -> str:
    """Read nginx configuration file"""
    try:
        with open(config_path, 'r') as f:
            return f.read()
    except Exception as e:
        logger.error(f"Error reading nginx config: {e}")
        raise


def write_nginx_config(config_path: Path, content: str) -> None:
    """Write nginx configuration file"""
    try:
        # Create backup
        backup_path = config_path.with_suffix(f"{config_path.suffix}.backup")
        if config_path.exists():
            shutil.copy2(config_path, backup_path)
            logger.info(f"Created backup: {backup_path}")
        
        # Write new config
        with open(config_path, 'w') as f:
            f.write(content)
        logger.info(f"Updated nginx config: {config_path}")
    except Exception as e:
        logger.error(f"Error writing nginx config: {e}")
        raise


def test_nginx_config() -> tuple[bool, str]:
    """Test nginx configuration"""
    try:
        result = subprocess.run(
            [NGINX_BINARY, '-t'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            logger.info("Nginx configuration test passed")
            return True, "Configuration test passed"
        else:
            error_msg = result.stderr or result.stdout or "Unknown error"
            logger.error(f"Nginx configuration test failed: {error_msg}")
            return False, error_msg
    except FileNotFoundError:
        error_msg = f"Nginx binary not found at {NGINX_BINARY}. Please ensure nginx is installed."
        logger.error(error_msg)
        return False, error_msg
    except subprocess.TimeoutExpired:
        error_msg = "Nginx test command timed out"
        logger.error(error_msg)
        return False, error_msg
    except Exception as e:
        error_msg = f"Error testing nginx config: {str(e)}"
        logger.error(error_msg)
        return False, error_msg


def reload_nginx() -> tuple[bool, str]:
    """Reload nginx configuration"""
    try:
        result = subprocess.run(
            [SYSTEMCTL_BINARY, 'reload', 'nginx'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            logger.info("Nginx reloaded successfully via systemctl")
            return True, "Nginx reloaded successfully"
        else:
            # Try alternative method
            service_binary = find_binary('service', ['/usr/sbin/service', '/sbin/service'])
            result = subprocess.run(
                [service_binary, 'nginx', 'reload'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.info("Nginx reloaded successfully via service")
                return True, "Nginx reloaded successfully"
            error_msg = result.stderr or result.stdout or "Unknown error"
            logger.error(f"Failed to reload nginx: {error_msg}")
            return False, error_msg
    except FileNotFoundError:
        error_msg = f"systemctl binary not found at {SYSTEMCTL_BINARY}. Please ensure systemd is installed."
        logger.error(error_msg)
        return False, error_msg
    except subprocess.TimeoutExpired:
        error_msg = "Nginx reload command timed out"
        logger.error(error_msg)
        return False, error_msg
    except Exception as e:
        error_msg = f"Error reloading nginx: {str(e)}"
        logger.error(error_msg)
        return False, error_msg


def get_modsecurity_status(config_content: str) -> dict:
    """Get current ModSecurity status from nginx config content"""
    pattern = r'modsecurity\s+(on|off)\s*;'
    match = re.search(pattern, config_content, re.IGNORECASE)
    
    if match:
        status = match.group(1).lower()
        return {
            "modsecurity_enabled": status == "on",
            "status": status
        }
    else:
        return {
            "modsecurity_enabled": None,
            "status": "not_configured"
        }

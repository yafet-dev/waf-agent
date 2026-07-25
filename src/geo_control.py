"""
Geo Access Control - per-domain country allow/deny lists and mode switching.

Everything here is keyed by domain. Nothing is hardcoded to a particular site,
and the first request for a domain provisions every file nginx needs, so a new
domain works without any manual setup.

Layout created per domain (paths configurable in config.py):

    /etc/nginx/waf/geo-lists/<domain>.allow          country codes, "ET 1;"
    /etc/nginx/waf/geo-lists/<domain>.deny           country codes, "CN 1;"
    /etc/nginx/conf.d/waf-geo-<domain>.conf          http-context map blocks
    /etc/nginx/waf/geo-servers/<domain>.allow_only.conf
    /etc/nginx/waf/geo-servers/<domain>.deny_only.conf
    /etc/nginx/waf/geo-servers/<domain>.active.conf  includes the active mode

and the domain's vhost gains one line inside its server block:

    include /etc/nginx/waf/geo-servers/<domain>.active.conf;

The map blocks live under conf.d because nginx only accepts `map` in the http
context, and the stock nginx.conf already includes conf.d/*.conf there.

Enforcement depends on the GeoIP2 module populating GEO_COUNTRY_VARIABLE. If
that module or its country database is missing, nginx -t fails and the change
is rolled back rather than silently doing nothing.
"""

import re
import fcntl
import logging
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from fastapi import HTTPException

# Try relative imports first (when run as module), fallback to absolute
try:
    from .config import (
        NGINX_BINARY,
        SYSTEMCTL_BINARY,
        GEO_LISTS_DIR,
        GEO_SERVERS_DIR,
        NGINX_CONF_D,
        GEO_COUNTRY_VARIABLE,
    )
    from .nginx_utils import get_nginx_config_path, read_nginx_config, write_nginx_config
    from .domains import normalize_domain, sanitize_domain_for_variable, safe_domain_path
except ImportError:
    from src.config import (
        NGINX_BINARY,
        SYSTEMCTL_BINARY,
        GEO_LISTS_DIR,
        GEO_SERVERS_DIR,
        NGINX_CONF_D,
        GEO_COUNTRY_VARIABLE,
    )
    from src.nginx_utils import get_nginx_config_path, read_nginx_config, write_nginx_config
    from src.domains import normalize_domain, sanitize_domain_for_variable, safe_domain_path

logger = logging.getLogger(__name__)

# ─── Constants ──────────────────────────────────────────────────────────────
COUNTRY_RE = re.compile(r'^[A-Z]{2}$')
CMD_TIMEOUT = 10  # seconds

VALID_MODES = ("allow_only", "deny_only")


# ─── Per-domain paths ───────────────────────────────────────────────────────
#
# Every builder goes through safe_domain_path(), which validates the domain and
# confirms the finished path sits inside its base directory. Validating here
# rather than only in the request handlers means these are safe no matter which
# module calls them.

def get_allow_list_path(domain: str) -> Path:
    return safe_domain_path(GEO_LISTS_DIR, domain, ".allow")


def get_deny_list_path(domain: str) -> Path:
    return safe_domain_path(GEO_LISTS_DIR, domain, ".deny")


def get_map_config_path(domain: str) -> Path:
    """http-context map block; lives in conf.d so nginx.conf needs no edit."""
    return safe_domain_path(NGINX_CONF_D, domain, ".conf", prefix="waf-geo-")


def get_allow_only_conf_path(domain: str) -> Path:
    return safe_domain_path(GEO_SERVERS_DIR, domain, ".allow_only.conf")


def get_deny_only_conf_path(domain: str) -> Path:
    return safe_domain_path(GEO_SERVERS_DIR, domain, ".deny_only.conf")


def get_active_conf_path(domain: str) -> Path:
    return safe_domain_path(GEO_SERVERS_DIR, domain, ".active.conf")


def ensure_directories() -> None:
    """Create the geo directories if they do not exist yet."""
    for directory in (GEO_LISTS_DIR, GEO_SERVERS_DIR, NGINX_CONF_D):
        directory.mkdir(parents=True, exist_ok=True)
        logger.debug(f"Ensured directory exists: {directory}")


# ─── Atomic file helpers ────────────────────────────────────────────────────

def _write_atomic(path: Path, content: str) -> None:
    """Write via a temp file plus rename, so readers never see a partial file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_file = path.with_suffix(f"{path.suffix}.tmp")

    try:
        with open(temp_file, 'w') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.write(content)
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        temp_file.replace(path)
    except Exception:
        if temp_file.exists():
            try:
                temp_file.unlink()
            except Exception:
                pass
        raise


def _write_if_changed(path: Path, content: str) -> bool:
    """Write only when the content differs. Returns True if it wrote."""
    if path.exists():
        try:
            if path.read_text() == content:
                return False
        except Exception as e:
            logger.warning(f"Could not read {path} for comparison: {e}")

    _write_atomic(path, content)
    logger.info(f"Wrote {path}")
    return True


# ─── Provisioning ───────────────────────────────────────────────────────────

def ensure_domain_files(domain: str) -> bool:
    """
    Create every file the domain needs, if missing. Idempotent.

    Called at the start of each mutating request so a brand-new domain works on
    its first call with no manual setup.

    Returns True if anything was created or changed.
    """
    ensure_directories()

    safe = sanitize_domain_for_variable(domain)
    allow_list = get_allow_list_path(domain)
    deny_list = get_deny_list_path(domain)
    changed = False

    # The list files must exist even when empty: nginx fails to start if a
    # file named by `include` inside a map block is missing.
    for list_path in (allow_list, deny_list):
        if not list_path.exists():
            _write_atomic(list_path, "")
            logger.info(f"Created empty geo list: {list_path}")
            changed = True

    # http-context maps translating the visitor's country into two flags.
    map_content = f"""# Managed by waf-agent. Geo access control for {domain}.
map {GEO_COUNTRY_VARIABLE} $geo_allow_{safe} {{
    default 0;
    include {allow_list};
}}

map {GEO_COUNTRY_VARIABLE} $geo_deny_{safe} {{
    default 0;
    include {deny_list};
}}
"""
    changed |= _write_if_changed(get_map_config_path(domain), map_content)

    # server-context enforcement, one file per mode.
    allow_only = (
        f"# Managed by waf-agent. Allow only listed countries for {domain}.\n"
        f"if ($geo_allow_{safe} = 0) {{ return 403; }}\n"
    )
    deny_only = (
        f"# Managed by waf-agent. Block listed countries for {domain}.\n"
        f"if ($geo_deny_{safe}) {{ return 403; }}\n"
    )
    changed |= _write_if_changed(get_allow_only_conf_path(domain), allow_only)
    changed |= _write_if_changed(get_deny_only_conf_path(domain), deny_only)

    # active.conf must exist before the vhost includes it. Default to
    # deny_only with an empty deny list, which blocks nobody.
    active_conf = get_active_conf_path(domain)
    if not active_conf.exists():
        _write_atomic(
            active_conf,
            f"include {get_deny_only_conf_path(domain)};\n",
        )
        logger.info(f"Initialised {active_conf} to deny_only (empty list, allows all)")
        changed = True

    return changed


def ensure_vhost_includes_geo(domain: str) -> Tuple[bool, Optional[Path]]:
    """
    Add the geo include to the domain's server block, once.

    Returns (was_modified, backup_path). A missing vhost is not fatal: the geo
    files are still written, so enforcement starts as soon as the vhost exists.
    """
    # A missing or unreadable vhost is not fatal. The geo files are still
    # written, so enforcement begins as soon as the site exists -- failing the
    # whole request would mean a country list could not be edited just because
    # the site is not deployed yet.
    try:
        config_path = get_nginx_config_path(domain)
        config_content = read_nginx_config(config_path)
    except (FileNotFoundError, OSError) as e:
        logger.warning(
            f"Could not read a vhost for {domain} ({e}); geo files were written "
            "but nothing enforces them until the site exists."
        )
        return False, None
    include_line = f"include {get_active_conf_path(domain)};"

    if include_line in config_content:
        logger.debug(f"Geo include already present in {config_path}")
        return False, None

    lines = config_content.split('\n')
    inserted = False

    # Preferred anchor: immediately after server_name.
    for i, line in enumerate(lines):
        if re.search(r'server_name\s+', line) and ';' in line:
            indent = len(line) - len(line.lstrip())
            lines.insert(i + 1, ' ' * indent + include_line)
            inserted = True
            logger.info(f"Inserted geo include after server_name in {config_path}")
            break

    # Fallback: just inside the server block.
    if not inserted:
        for i, line in enumerate(lines):
            if line.strip().startswith('server {'):
                indent = len(line) - len(line.lstrip()) + 4
                for j in range(i + 1, min(i + 5, len(lines))):
                    if lines[j].strip():
                        indent = len(lines[j]) - len(lines[j].lstrip())
                        break
                lines.insert(i + 1, ' ' * indent + include_line)
                inserted = True
                logger.info(f"Inserted geo include into server block in {config_path}")
                break

    if not inserted:
        logger.error(f"Could not find a server block in {config_path}")
        raise HTTPException(
            status_code=500,
            detail=f"Could not find a server block in {config_path} to add the geo rule to.",
        )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = config_path.with_suffix(f"{config_path.suffix}.bak-{timestamp}")
    try:
        shutil.copy2(config_path, backup_path)
        logger.info(f"Created backup: {backup_path}")
    except Exception as e:
        logger.warning(f"Failed to create backup of {config_path}: {e}")
        backup_path = None

    write_nginx_config(config_path, '\n'.join(lines))
    return True, backup_path


def ensure_domain_ready(domain: str) -> None:
    """
    Full provisioning for a domain: files plus the vhost include.

    Rolls the vhost back if the resulting config does not pass nginx -t, so a
    failed provision cannot leave nginx unable to start.
    """
    ensure_domain_files(domain)
    vhost_changed, backup_path = ensure_vhost_includes_geo(domain)

    if not vhost_changed:
        return

    try:
        validate_and_reload_nginx()
    except Exception:
        if backup_path and backup_path.exists():
            try:
                shutil.copy2(backup_path, get_nginx_config_path(domain))
                logger.info(f"Rolled back vhost changes for {domain}")
            except Exception as rollback_err:
                logger.error(f"Failed to roll back vhost for {domain}: {rollback_err}")
        raise


# ─── List read/write ────────────────────────────────────────────────────────

def read_list(file_path: Path) -> Set[str]:
    """
    Read a geo-list file and return its country codes.
    File format: one entry per line, "XX 1;".
    """
    codes: Set[str] = set()
    if not file_path.exists():
        return codes

    try:
        with open(file_path, 'r') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            try:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    match = re.match(r'^([A-Z]{2})\s+1;', line)
                    if match:
                        codes.add(match.group(1))
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except Exception as e:
        logger.error(f"Error reading list file {file_path}: {e}")
        raise

    return codes


def write_list_atomic(file_path: Path, codes: Set[str]) -> None:
    """
    Atomically write a geo-list file, validate nginx, and reload.
    Restores the previous contents if nginx -t fails.
    """
    ensure_directories()

    sorted_codes = sorted(codes)
    content = '\n'.join(f"{code} 1;" for code in sorted_codes)
    if content:
        content += '\n'

    existed = file_path.exists()
    backup: Optional[str] = None
    if existed:
        try:
            backup = file_path.read_text()
        except Exception as e:
            logger.warning(f"Could not read backup from {file_path}: {e}")

    try:
        _write_atomic(file_path, content)
        logger.info(f"Wrote {file_path} ({len(codes)} entries)")
        validate_and_reload_nginx()
    except Exception:
        if backup is not None:
            try:
                _write_atomic(file_path, backup)
                logger.info(f"Rolled back {file_path}")
            except Exception as rollback_err:
                logger.error(f"Failed to rollback {file_path}: {rollback_err}")
        elif not existed and file_path.exists():
            try:
                file_path.unlink()
            except Exception:
                pass
        raise


# ─── Mode switching ─────────────────────────────────────────────────────────

def set_mode_atomic(domain: str, mode: str) -> None:
    """
    Switch the domain's active enforcement mode, validate, and reload.
    Restores the previous mode if nginx -t fails.
    """
    if mode not in VALID_MODES:
        raise ValueError(f"Invalid mode: {mode}. Must be one of {VALID_MODES}")

    ensure_domain_files(domain)

    active_conf = get_active_conf_path(domain)
    target = (
        get_allow_only_conf_path(domain) if mode == "allow_only"
        else get_deny_only_conf_path(domain)
    )

    backup: Optional[str] = None
    if active_conf.exists():
        try:
            backup = active_conf.read_text()
        except Exception as e:
            logger.warning(f"Could not read backup from {active_conf}: {e}")

    try:
        _write_atomic(active_conf, f"include {target};\n")
        logger.info(f"Mode for {domain} set to {mode}")
        validate_and_reload_nginx()
    except Exception:
        if backup is not None:
            try:
                _write_atomic(active_conf, backup)
                logger.info(f"Rolled back {active_conf}")
            except Exception as rollback_err:
                logger.error(f"Failed to rollback {active_conf}: {rollback_err}")
        raise


def get_current_mode(domain: str) -> str:
    """Return "allow_only", "deny_only", or "unknown" for a domain."""
    active_conf = get_active_conf_path(domain)
    if not active_conf.exists():
        return "unknown"

    try:
        data = active_conf.read_text()
        if "allow_only.conf" in data:
            return "allow_only"
        if "deny_only.conf" in data:
            return "deny_only"
        return "unknown"
    except Exception as e:
        logger.warning(f"Error reading {active_conf}: {e}")
        return "unknown"


# ─── Status ─────────────────────────────────────────────────────────────────

def get_configured_domains() -> List[str]:
    """Every domain that has geo files, derived from the allow lists."""
    if not GEO_LISTS_DIR.exists():
        return []
    return sorted({p.stem for p in GEO_LISTS_DIR.glob("*.allow")})


def get_domain_status(domain: str) -> Dict:
    """Mode plus allow/deny lists for one domain."""
    return {
        "domain": domain,
        "mode": get_current_mode(domain),
        "allow": sorted(read_list(get_allow_list_path(domain))),
        "deny": sorted(read_list(get_deny_list_path(domain))),
    }


def get_all_status() -> Dict:
    """Status for every configured domain."""
    domains = get_configured_domains()
    return {
        "domains": [get_domain_status(d) for d in domains],
        "total_domains": len(domains),
    }


# ─── nginx ──────────────────────────────────────────────────────────────────

def validate_and_reload_nginx() -> None:
    """Run `nginx -t`, then `systemctl reload nginx`. Raises on failure."""
    try:
        result = subprocess.run(
            [NGINX_BINARY, '-t'],
            capture_output=True,
            text=True,
            timeout=CMD_TIMEOUT
        )

        if result.returncode != 0:
            error_msg = result.stderr or result.stdout or "Unknown error"
            logger.error(f"Nginx config test failed: {error_msg}")

            hint = ""
            if "geoip2" in error_msg.lower() or "unknown" in error_msg.lower():
                hint = (
                    " This usually means the GeoIP2 module or its country "
                    "database is not installed, so "
                    f"{GEO_COUNTRY_VARIABLE} is undefined."
                )

            raise HTTPException(
                status_code=500,
                detail=f"Nginx configuration test failed: {error_msg}{hint}"
            )

        logger.info("Nginx configuration test passed")

        result = subprocess.run(
            [SYSTEMCTL_BINARY, 'reload', 'nginx'],
            capture_output=True,
            text=True,
            timeout=CMD_TIMEOUT
        )

        if result.returncode != 0:
            error_msg = result.stderr or result.stdout or "Unknown error"
            logger.error(f"Failed to reload nginx: {error_msg}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to reload nginx: {error_msg}"
            )

        logger.info("Nginx reloaded successfully")

    except subprocess.TimeoutExpired:
        error_msg = "Command timed out"
        logger.error(error_msg)
        raise HTTPException(status_code=500, detail=error_msg)
    except FileNotFoundError as e:
        error_msg = f"Command not found: {e}"
        logger.error(error_msg)
        raise HTTPException(status_code=500, detail=error_msg)
    except HTTPException:
        raise
    except Exception as e:
        error_msg = f"Error validating/reloading nginx: {str(e)}"
        logger.error(error_msg)
        raise HTTPException(status_code=500, detail=error_msg)


def validate_country_code(country: str) -> bool:
    """Validate country code format (ISO-3166-1 alpha-2, uppercase)."""
    return bool(COUNTRY_RE.match(country))

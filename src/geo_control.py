"""
Geo Access Control functionality - Handles country allow/deny lists and mode switching
"""

import re
import fcntl
import logging
import subprocess
from pathlib import Path
from typing import Set, Optional
from fastapi import HTTPException

# Try relative imports first (when run as module), fallback to absolute (when run directly)
try:
    from .config import NGINX_BINARY, SYSTEMCTL_BINARY
except ImportError:
    from src.config import NGINX_BINARY, SYSTEMCTL_BINARY

logger = logging.getLogger(__name__)

# ─── Paths ──────────────────────────────────────────────────────────────────
GEO_LISTS_DIR = Path("/etc/nginx/waf/geo-lists")
GEO_SERVERS_DIR = Path("/etc/nginx/waf/geo-servers")

ALLOW_LIST_PATH = GEO_LISTS_DIR / "waf.zergaw.et.allow"
DENY_LIST_PATH = GEO_LISTS_DIR / "waf.zergaw.et.deny"
ACTIVE_CONF_PATH = GEO_SERVERS_DIR / "waf.zergaw.et.active.conf"

ALLOW_ONLY_CONF = GEO_SERVERS_DIR / "waf.zergaw.et.allow_only.conf"
DENY_ONLY_CONF = GEO_SERVERS_DIR / "waf.zergaw.et.deny_only.conf"

# ─── Constants ──────────────────────────────────────────────────────────────
COUNTRY_RE = re.compile(r'^[A-Z]{2}$')
CMD_TIMEOUT = 10  # seconds


def ensure_directories() -> None:
    """Ensure all required geo directories exist"""
    for directory in [GEO_LISTS_DIR, GEO_SERVERS_DIR]:
        directory.mkdir(parents=True, exist_ok=True)
        logger.debug(f"Ensured directory exists: {directory}")


def read_list(file_path: Path) -> Set[str]:
    """
    Read a geo-list file and return the set of country codes.
    File format: one entry per line "XX 1;"
    """
    codes = set()
    if not file_path.exists():
        return codes
    
    try:
        with open(file_path, 'r') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)  # Shared lock for reading
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
    Rolls back on nginx -t failure.
    """
    ensure_directories()
    
    # Prepare content
    sorted_codes = sorted(codes)
    content = '\n'.join(f"{code} 1;" for code in sorted_codes)
    if content:
        content += '\n'
    
    # Save original for rollback
    backup: Optional[str] = None
    if file_path.exists():
        try:
            with open(file_path, 'r') as f:
                backup = f.read()
        except Exception as e:
            logger.warning(f"Could not read backup from {file_path}: {e}")
    
    # Write to temp file first
    temp_file = file_path.with_suffix(f"{file_path.suffix}.tmp")
    try:
        with open(temp_file, 'w') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.write(content)
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        
        # Atomic rename
        temp_file.replace(file_path)
        logger.info(f"Wrote {file_path} ({len(codes)} entries)")
        
        # Validate and reload
        validate_and_reload_nginx()
        
    except Exception as e:
        # Rollback on error
        if backup is not None:
            try:
                with open(file_path, 'w') as f:
                    f.write(backup)
                logger.info(f"Rolled back {file_path}")
            except Exception as rollback_err:
                logger.error(f"Failed to rollback {file_path}: {rollback_err}")
        else:
            # If file didn't exist, try to remove it
            try:
                if file_path.exists():
                    file_path.unlink()
            except Exception:
                pass
        
        if temp_file.exists():
            try:
                temp_file.unlink()
            except Exception:
                pass
        
        raise


def set_mode_atomic(mode: str) -> None:
    """
    Atomically switch the active enforcement mode, validate, and reload.
    Rolls back on nginx -t failure.
    """
    if mode not in ["allow_only", "deny_only"]:
        raise ValueError(f"Invalid mode: {mode}. Must be 'allow_only' or 'deny_only'")
    
    ensure_directories()
    
    include_line = (
        f"include {ALLOW_ONLY_CONF};" if mode == "allow_only"
        else f"include {DENY_ONLY_CONF};"
    )
    
    # Save original for rollback
    backup: Optional[str] = None
    if ACTIVE_CONF_PATH.exists():
        try:
            with open(ACTIVE_CONF_PATH, 'r') as f:
                backup = f.read()
        except Exception as e:
            logger.warning(f"Could not read backup from {ACTIVE_CONF_PATH}: {e}")
    
    # Write to temp file first
    temp_file = ACTIVE_CONF_PATH.with_suffix(f"{ACTIVE_CONF_PATH.suffix}.tmp")
    try:
        with open(temp_file, 'w') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.write(include_line + '\n')
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        
        # Atomic rename
        temp_file.replace(ACTIVE_CONF_PATH)
        logger.info(f"Mode set to {mode}")
        
        # Validate and reload
        validate_and_reload_nginx()
        
    except Exception as e:
        # Rollback on error
        if backup is not None:
            try:
                with open(ACTIVE_CONF_PATH, 'w') as f:
                    f.write(backup)
                logger.info(f"Rolled back {ACTIVE_CONF_PATH}")
            except Exception as rollback_err:
                logger.error(f"Failed to rollback {ACTIVE_CONF_PATH}: {rollback_err}")
        
        if temp_file.exists():
            try:
                temp_file.unlink()
            except Exception:
                pass
        
        raise


def validate_and_reload_nginx() -> None:
    """
    Run `nginx -t` then `systemctl reload nginx`.
    Throws on failure.
    """
    try:
        # Test nginx config
        result = subprocess.run(
            [NGINX_BINARY, '-t'],
            capture_output=True,
            text=True,
            timeout=CMD_TIMEOUT
        )
        
        if result.returncode != 0:
            error_msg = result.stderr or result.stdout or "Unknown error"
            logger.error(f"Nginx config test failed: {error_msg}")
            raise HTTPException(
                status_code=500,
                detail=f"Nginx configuration test failed: {error_msg}"
            )
        
        logger.info("Nginx configuration test passed")
        
        # Reload nginx
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


def get_current_mode() -> str:
    """
    Determine current mode by reading active.conf.
    Returns: "allow_only", "deny_only", or "unknown"
    """
    if not ACTIVE_CONF_PATH.exists():
        return "unknown"
    
    try:
        with open(ACTIVE_CONF_PATH, 'r') as f:
            data = f.read()
            if "allow_only.conf" in data:
                return "allow_only"
            if "deny_only.conf" in data:
                return "deny_only"
            return "unknown"
    except Exception as e:
        logger.warning(f"Error reading active conf: {e}")
        return "unknown"


def validate_country_code(country: str) -> bool:
    """Validate country code format"""
    return bool(COUNTRY_RE.match(country))

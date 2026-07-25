"""
IP Blocking functionality - Handles banning/unbanning IPs per domain using Nginx map files
"""

import os
import re
import fcntl
import threading
import logging
import shutil
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from fastapi import HTTPException
from .config import WAF_BLOCKS_DIR, WAF_MAPS_DIR, WAF_SERVERS_DIR, NGINX_SITES_AVAILABLE
from .nginx_utils import test_nginx_config, reload_nginx, read_nginx_config, write_nginx_config, get_nginx_config_path
from .domains import (
    normalize_domain,
    safe_domain_path,
    sanitize_domain_for_variable as _sanitize_domain_for_variable,
)

logger = logging.getLogger(__name__)

# Debounce timer for nginx reload
_reload_timer: Optional[threading.Timer] = None
_reload_lock = threading.Lock()
_RELOAD_DEBOUNCE_SECONDS = 2


# Re-exported for callers that already import it from this module.
sanitize_domain_for_variable = _sanitize_domain_for_variable


def ensure_directories() -> None:
    """Ensure all required WAF directories exist"""
    for directory in [WAF_BLOCKS_DIR, WAF_MAPS_DIR, WAF_SERVERS_DIR]:
        directory.mkdir(parents=True, exist_ok=True)
        logger.debug(f"Ensured directory exists: {directory}")


# Path builders validate the domain and confirm the result stays inside its
# base directory. The agent runs as root, and these names come straight from a
# request body, so an unvalidated join here would let a caller write anywhere
# on the filesystem.

def get_block_file_path(domain: str) -> Path:
    """Get the path to the block map file for a domain"""
    return safe_domain_path(WAF_BLOCKS_DIR, domain, ".map")


def get_map_config_path(domain: str) -> Path:
    """Get the path to the map config file for a domain"""
    return safe_domain_path(WAF_MAPS_DIR, domain, ".conf")


def get_server_rule_path(domain: str) -> Path:
    """Get the path to the server rule file for a domain"""
    return safe_domain_path(WAF_SERVERS_DIR, domain, ".conf")


def update_block_file(domain: str, ip: str, action: str) -> bool:
    """
    Update block file for a domain (ban or unban an IP)
    Uses file locking and atomic writes
    
    Returns:
        bool: True if file was changed, False if no change needed
    """
    block_file = get_block_file_path(domain)
    temp_file = block_file.with_suffix(f"{block_file.suffix}.tmp")
    
    # Ensure directory exists
    block_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Read existing content if file exists
    existing_ips = set()
    if block_file.exists():
        try:
            with open(block_file, 'r') as f:
                # Acquire exclusive lock
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Extract IP from line like "1.2.3.4 1;"
                            match = re.match(r'^([^\s]+)\s+1;', line)
                            if match:
                                existing_ips.add(match.group(1))
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except Exception as e:
            logger.error(f"Error reading block file {block_file}: {e}")
            raise
    
    # Determine if change is needed
    ip_exists = ip in existing_ips
    changed = False
    
    if action == "ban":
        if not ip_exists:
            existing_ips.add(ip)
            changed = True
            logger.info(f"Adding IP {ip} to block list for {domain}")
        else:
            logger.debug(f"IP {ip} already banned for {domain}")
    elif action == "unban":
        if ip_exists:
            existing_ips.remove(ip)
            changed = True
            logger.info(f"Removing IP {ip} from block list for {domain}")
        else:
            logger.debug(f"IP {ip} not in block list for {domain}")
    else:
        raise ValueError(f"Invalid action: {action}. Must be 'ban' or 'unban'")
    
    # Write updated content if changed
    if changed:
        try:
            # Write to temp file first (atomic write)
            with open(temp_file, 'w') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    for blocked_ip in sorted(existing_ips):
                        f.write(f"{blocked_ip} 1;\n")
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            
            # Atomic rename
            temp_file.replace(block_file)
            logger.info(f"Updated block file: {block_file}")
        except Exception as e:
            logger.error(f"Error writing block file {block_file}: {e}")
            if temp_file.exists():
                temp_file.unlink()
            raise
    
    return changed


def ensure_map_config(domain: str) -> None:
    """Ensure map config file exists for a domain"""
    map_file = get_map_config_path(domain)
    safe_domain = sanitize_domain_for_variable(domain)
    block_file = get_block_file_path(domain)
    
    # Check if file exists and content is correct
    content = f"""map $remote_addr $block_{safe_domain} {{
    default 0;
    include {block_file};
}}
"""
    
    needs_update = True
    if map_file.exists():
        try:
            with open(map_file, 'r') as f:
                existing_content = f.read()
                if existing_content.strip() == content.strip():
                    needs_update = False
        except Exception as e:
            logger.warning(f"Error reading map config {map_file}: {e}")
    
    if needs_update:
        temp_file = map_file.with_suffix(f"{map_file.suffix}.tmp")
        try:
            with open(temp_file, 'w') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    f.write(content)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            
            temp_file.replace(map_file)
            logger.info(f"Created/updated map config: {map_file}")
        except Exception as e:
            logger.error(f"Error writing map config {map_file}: {e}")
            if temp_file.exists():
                temp_file.unlink()
            raise


def ensure_server_rule(domain: str) -> None:
    """Ensure server rule file exists for a domain"""
    server_file = get_server_rule_path(domain)
    safe_domain = sanitize_domain_for_variable(domain)
    
    content = f"if ($block_{safe_domain}) {{ return 403; }}\n"
    
    needs_update = True
    if server_file.exists():
        try:
            with open(server_file, 'r') as f:
                existing_content = f.read()
                if existing_content.strip() == content.strip():
                    needs_update = False
        except Exception as e:
            logger.warning(f"Error reading server rule {server_file}: {e}")
    
    if needs_update:
        temp_file = server_file.with_suffix(f"{server_file.suffix}.tmp")
        try:
            with open(temp_file, 'w') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    f.write(content)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            
            temp_file.replace(server_file)
            logger.info(f"Created/updated server rule: {server_file}")
        except Exception as e:
            logger.error(f"Error writing server rule {server_file}: {e}")
            if temp_file.exists():
                temp_file.unlink()
            raise


def ensure_vhost_includes_rule(domain: str) -> Tuple[bool, Optional[Path]]:
    """
    Ensure vhost file includes the server rule (only once)
    Returns:
        Tuple[bool, Optional[Path]]: (was_modified, backup_path)
    """
    try:
        config_path = get_nginx_config_path(domain)
    except FileNotFoundError:
        logger.warning(f"Vhost file not found for domain {domain}, skipping include")
        return False, None
    
    # Create backup
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = config_path.with_suffix(f"{config_path.suffix}.bak-{timestamp}")
    
    try:
        config_content = read_nginx_config(config_path)
    except Exception as e:
        logger.error(f"Error reading vhost config {config_path}: {e}")
        raise
    
    server_rule_path = get_server_rule_path(domain)
    include_line = f"include {server_rule_path};"
    
    # Check if include already exists
    if include_line in config_content:
        logger.debug(f"Server rule already included in {config_path}")
        return False, None
    
    # Find server_name line and insert include after it
    lines = config_content.split('\n')
    modified = False
    server_rule_inserted = False
    
    for i, line in enumerate(lines):
        # Look for server_name directive
        if re.search(r'server_name\s+', line) and not server_rule_inserted:
            # Find the end of this line (after semicolon)
            if ';' in line:
                # Insert include on next line with same indentation
                indent = len(line) - len(line.lstrip())
                lines.insert(i + 1, ' ' * indent + include_line)
                modified = True
                server_rule_inserted = True
                logger.info(f"Inserted server rule include in {config_path}")
                break
    
    if not server_rule_inserted:
        # Fallback: add at the beginning of server block
        for i, line in enumerate(lines):
            if line.strip().startswith('server {'):
                indent = len(line) - len(line.lstrip())
                # Find next non-empty line to match indentation
                for j in range(i + 1, min(i + 5, len(lines))):
                    if lines[j].strip():
                        indent = len(lines[j]) - len(lines[j].lstrip())
                        break
                lines.insert(i + 1, ' ' * indent + include_line)
                modified = True
                server_rule_inserted = True
                logger.info(f"Inserted server rule include in {config_path} (fallback)")
                break
    
    if modified:
        # Create backup before writing
        try:
            shutil.copy2(config_path, backup_path)
            logger.info(f"Created backup: {backup_path}")
        except Exception as e:
            logger.warning(f"Failed to create backup: {e}")
            backup_path = None
        
        # Write updated content
        updated_content = '\n'.join(lines)
        write_nginx_config(config_path, updated_content)
        return True, backup_path
    
    return False, None


def _debounced_reload_nginx() -> None:
    """Internal function to perform nginx reload with debouncing"""
    global _reload_timer
    
    with _reload_lock:
        # Cancel existing timer if any
        if _reload_timer is not None:
            _reload_timer.cancel()
        
        # Create new timer
        _reload_timer = threading.Timer(_RELOAD_DEBOUNCE_SECONDS, _perform_reload)
        _reload_timer.start()
        logger.debug(f"Scheduled nginx reload in {_RELOAD_DEBOUNCE_SECONDS} seconds")


def _perform_reload() -> None:
    """Actually perform the nginx reload (called from background thread)"""
    global _reload_timer
    
    with _reload_lock:
        _reload_timer = None
    
    logger.info("Performing debounced nginx reload...")
    
    # Test nginx config
    test_ok, test_message = test_nginx_config()
    if not test_ok:
        logger.error(f"Nginx config test failed: {test_message}")
        logger.error("Nginx reload was skipped due to configuration test failure")
        return
    
    # Reload nginx
    reload_ok, reload_message = reload_nginx()
    if not reload_ok:
        logger.error(f"Nginx reload failed: {reload_message}")
        return
    
    logger.info("Nginx reloaded successfully")


def ban_unban_ip(ip: str, domains: List[str], action: str) -> Dict:
    """
    Ban or unban an IP for one or more domains
    
    Args:
        ip: IP address to ban/unban
        domains: List of domains (or ["*"] for all known domains)
        action: "ban" or "unban"
    
    Returns:
        dict with ok status and results per domain
    """
    if action not in ["ban", "unban"]:
        raise ValueError(f"Invalid action: {action}. Must be 'ban' or 'unban'")
    
    if not ip or not ip.strip():
        raise ValueError("IP address is required")
    
    # Validate IP format (basic validation)
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if not ip_pattern.match(ip):
        raise ValueError(f"Invalid IP address format: {ip}")
    
    # Resolve "*" to all known domains
    if domains == ["*"]:
        domains = get_known_domains()
        if not domains:
            raise HTTPException(
                status_code=404,
                detail="No domains found. Cannot use '*' when no domains are configured."
            )
    
    if not domains:
        raise ValueError("At least one domain is required")
    
    # Ensure directories exist
    ensure_directories()
    
    results = []
    any_changed = False
    vhost_changes = []  # List of (domain, backup_path) tuples
    
    for raw_domain in domains:
        if not raw_domain or not raw_domain.strip():
            continue

        # Validate before the domain reaches any path builder. Reported per
        # domain rather than raised, so one bad entry does not abort a batch
        # that is otherwise valid.
        try:
            domain = normalize_domain(raw_domain)
        except HTTPException as e:
            logger.warning(f"Rejected invalid domain {raw_domain!r}: {e.detail}")
            results.append({
                "domain": raw_domain,
                "changed": False,
                "message": f"Invalid domain: {e.detail}",
            })
            continue

        try:
            # Update block file
            block_changed = update_block_file(domain, ip, action)
            
            # Ensure map config exists
            ensure_map_config(domain)
            
            # Ensure server rule exists
            ensure_server_rule(domain)
            
            # Ensure vhost includes rule
            vhost_changed_domain, backup_path = ensure_vhost_includes_rule(domain)
            if vhost_changed_domain:
                vhost_changes.append((domain, backup_path))
            
            if block_changed or vhost_changed_domain:
                any_changed = True
                results.append({
                    "domain": domain,
                    "changed": True,
                    "message": f"{action}ed" if action == "ban" else f"{action}ned"
                })
            else:
                results.append({
                    "domain": domain,
                    "changed": False,
                    "message": f"IP already {action}ed" if action == "ban" else f"IP not in block list"
                })
        
        except FileNotFoundError as e:
            logger.error(f"Domain {domain} not found: {e}")
            results.append({
                "domain": domain,
                "changed": False,
                "message": f"Domain config not found: {str(e)}"
            })
        except Exception as e:
            logger.error(f"Error processing domain {domain}: {e}", exc_info=True)
            results.append({
                "domain": domain,
                "changed": False,
                "message": f"Error: {str(e)}"
            })
    
    # If vhost was changed, validate and reload immediately (don't debounce)
    if vhost_changes:
        logger.info("Vhost file(s) changed, validating nginx config immediately...")
        test_ok, test_message = test_nginx_config()
        if not test_ok:
            # Rollback vhost changes
            logger.error(f"Nginx config test failed: {test_message}, rolling back vhost changes...")
            for domain, backup_path in vhost_changes:
                if backup_path and backup_path.exists():
                    try:
                        config_path = get_nginx_config_path(domain)
                        shutil.copy2(backup_path, config_path)
                        logger.info(f"Rolled back vhost changes for {domain}")
                    except Exception as e:
                        logger.error(f"Failed to rollback vhost for {domain}: {e}")
            
            return {
                "ok": False,
                "results": results,
                "error": f"Nginx configuration test failed: {test_message}"
            }
        
        # Reload nginx immediately for vhost changes
        reload_ok, reload_message = reload_nginx()
        if not reload_ok:
            return {
                "ok": False,
                "results": results,
                "error": f"Failed to reload nginx: {reload_message}"
            }
    elif any_changed:
        # Debounce reload for block file changes only
        _debounced_reload_nginx()
    
    return {
        "ok": True,
        "results": results
    }


def get_known_domains() -> List[str]:
    """Get list of known domains from vhost files or existing block files"""
    domains = set()
    
    # From vhost files
    if NGINX_SITES_AVAILABLE.exists():
        for config_file in NGINX_SITES_AVAILABLE.glob("*"):
            if config_file.is_file() and not config_file.name.startswith('.'):
                # Try to extract domain from filename or file content
                domain = config_file.stem
                # Remove common suffixes
                for suffix in ['.conf', '.bak']:
                    if domain.endswith(suffix):
                        domain = domain[:-len(suffix)]
                domains.add(domain)
    
    # From existing block files
    if WAF_BLOCKS_DIR.exists():
        for block_file in WAF_BLOCKS_DIR.glob("*.map"):
            domain = block_file.stem
            domains.add(domain)
    
    return sorted(list(domains))


def get_blocked_ips(domain: str) -> List[str]:
    """Get list of blocked IPs for a domain"""
    block_file = get_block_file_path(domain)
    blocked_ips = []
    
    if not block_file.exists():
        return blocked_ips
    
    try:
        with open(block_file, 'r') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)  # Shared lock for reading
            try:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        match = re.match(r'^([^\s]+)\s+1;', line)
                        if match:
                            blocked_ips.append(match.group(1))
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except Exception as e:
        logger.error(f"Error reading block file {block_file}: {e}")
    
    return sorted(blocked_ips)


def get_ip_block_status() -> Dict:
    """Get status of all domains and their blocked IPs"""
    domains = get_known_domains()
    
    status = {
        "domains": [],
        "total_blocked_ips": 0
    }
    
    for domain in domains:
        blocked_ips = get_blocked_ips(domain)
        status["domains"].append({
            "domain": domain,
            "blocked_ips": blocked_ips,
            "blocked_count": len(blocked_ips)
        })
        status["total_blocked_ips"] += len(blocked_ips)
    
    return status

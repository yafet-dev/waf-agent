"""
WAF Toggle functionality - Handles turning ModSecurity on/off for domains
"""

import re
import logging
import shutil
from pathlib import Path
from fastapi import HTTPException
from .nginx_utils import (
    get_nginx_config_path,
    read_nginx_config,
    write_nginx_config,
    test_nginx_config,
    reload_nginx,
    get_modsecurity_status
)
from .security import verify_signature

logger = logging.getLogger(__name__)


def update_modsecurity_status(config_content: str, enabled: bool) -> str:
    """Update modsecurity on/off status in nginx config"""
    target_status = "on" if enabled else "off"
    
    logger.info(f"Updating modsecurity to: {target_status}")
    logger.debug(f"Config content before update:\n{config_content}")
    
    # Simple pattern: match "modsecurity on;" or "modsecurity off;" (case insensitive)
    # This handles: "modsecurity on;", "modsecurity off;", "modsecurity  on ;", etc.
    pattern = r'modsecurity\s+(on|off)\s*;'
    
    # Check if modsecurity directive exists
    match = re.search(pattern, config_content, re.IGNORECASE)
    
    if match:
        # Replace existing modsecurity directive
        # Simple replacement: replace the entire matched string
        updated_content = re.sub(
            pattern,
            f'modsecurity {target_status};',
            config_content,
            flags=re.IGNORECASE
        )
        logger.info(f"Updated modsecurity from '{match.group(1)}' to '{target_status}'")
        logger.debug(f"Config content after update:\n{updated_content}")
    else:
        # Add modsecurity directive if not present
        # Try to add before modsecurity_rules_file if it exists
        if 'modsecurity_rules_file' in config_content:
            # Add before modsecurity_rules_file line (preserve indentation)
            lines = config_content.split('\n')
            for i, line in enumerate(lines):
                if 'modsecurity_rules_file' in line:
                    # Get indentation from the modsecurity_rules_file line
                    indent = len(line) - len(line.lstrip())
                    lines.insert(i, ' ' * indent + f'modsecurity {target_status};')
                    updated_content = '\n'.join(lines)
                    logger.info(f"Added modsecurity directive before modsecurity_rules_file: {target_status}")
                    break
            else:
                # Fallback if loop didn't break
                updated_content = config_content.replace(
                    'modsecurity_rules_file',
                    f'modsecurity {target_status};\n  modsecurity_rules_file',
                    1
                )
                logger.info(f"Added modsecurity directive (fallback): {target_status}")
        else:
            # Add after server_name line
            updated_content = re.sub(
                r'(server_name\s+[^;]+;)',
                f'\\1\n  modsecurity {target_status};',
                config_content,
                count=1
            )
            logger.info(f"Added modsecurity directive after server_name: {target_status}")
    
    return updated_content


def toggle_waf_for_domain(
    domain: str,
    enabled: bool,
    signature: str = None,
    require_signature: bool = True
) -> dict:
    """
    Toggle ModSecurity on/off for a domain

    Args:
        domain: Domain name
        enabled: Whether to enable (True) or disable (False) ModSecurity
        signature: Base64 encoded signature for verification
        require_signature: When False, an absent signature is accepted. The
            caller sets this only for loopback requests, which never cross a
            network. A signature that IS supplied is always verified, even
            locally, so a misconfigured key is never silently ignored.

    Returns:
        dict with status information

    Raises:
        HTTPException: For various error conditions
    """
    # Validate input
    if not domain or not domain.strip():
        raise HTTPException(status_code=400, detail="Domain is required")

    has_signature = bool(signature and signature.strip())

    if not has_signature:
        if require_signature:
            raise HTTPException(status_code=400, detail="Signature is required")
        logger.info(
            f"Local request for domain {domain}: no signature supplied, "
            "skipping verification"
        )

    # Prepare data for signature verification
    # Signature should be of: domain|enabled (as string, lowercase boolean)
    # Convert boolean to lowercase string to match signing format
    enabled_str = str(enabled).lower()  # "true" or "false"

    logger.info(f"Received request - Domain: {domain}, Enabled: {enabled} (type: {type(enabled)})")

    if has_signature:
        data_to_verify = f"{domain}|{enabled_str}".encode('utf-8')
        logger.info(f"Data to verify: '{data_to_verify.decode('utf-8')}' (length: {len(data_to_verify)} bytes)")
        logger.info(f"Signature (first 50 chars): {signature[:50]}...")

        # Verify signature
        if not verify_signature(data_to_verify, signature):
            logger.error(f"Signature verification failed for domain: {domain}")
            logger.error(f"Expected data format: '{domain}|{enabled_str}'")
            raise HTTPException(
                status_code=401,
                detail="Invalid signature. Please check that the correct private key is being used."
            )

    logger.info(f"Processing WAF toggle: domain={domain}, enabled={enabled}")
    
    # Get nginx config path
    config_path = get_nginx_config_path(domain)
    logger.info(f"Using nginx config: {config_path}")
    
    # Read current config
    config_content = read_nginx_config(config_path)
    
    # Update modsecurity status
    updated_content = update_modsecurity_status(config_content, enabled)
    
    # Write updated config
    write_nginx_config(config_path, updated_content)
    
    # Test nginx configuration
    test_ok, test_message = test_nginx_config()
    if not test_ok:
        logger.error(f"Nginx config test failed: {test_message}")
        # Restore backup if test fails
        backup_path = config_path.with_suffix(f"{config_path.suffix}.backup")
        if backup_path.exists():
            shutil.copy2(backup_path, config_path)
            logger.info("Restored backup due to config test failure")
        raise HTTPException(
            status_code=500,
            detail=f"Nginx configuration test failed: {test_message}"
        )
    
    # Reload nginx
    reload_ok, reload_message = reload_nginx()
    if not reload_ok:
        logger.error(f"Nginx reload failed: {reload_message}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to reload nginx: {reload_message}"
        )
    
    logger.info(f"Successfully toggled WAF for {domain}: {'on' if enabled else 'off'}")
    
    return {
        "status": "OK",
        "message": "WAF status updated successfully",
        "domain": domain,
        "modsecurity_status": "on" if enabled else "off"
    }


def get_waf_status_for_domain(domain: str) -> dict:
    """
    Get current ModSecurity status for a domain
    
    Args:
        domain: Domain name
    
    Returns:
        dict with status information
    
    Raises:
        HTTPException: For various error conditions
    """
    config_path = get_nginx_config_path(domain)
    config_content = read_nginx_config(config_path)
    
    status_info = get_modsecurity_status(config_content)
    
    return {
        "domain": domain,
        **status_info
    }

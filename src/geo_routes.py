"""
Geo Access Control endpoints, as a router shared by both agent apps.

Mounted by main.py (the combined agent on :8080) and by geo_main.py (the
standalone geo service on :8081) so the two can never drift apart.

Every endpoint is scoped to a domain in the path. The first request for a
domain provisions its geo files and adds the include to its nginx server
block, so a new site needs no manual setup.
"""

import logging
import traceback
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

try:
    from .auth import require_auth
    from .geo_control import (
        read_list,
        write_list_atomic,
        set_mode_atomic,
        get_current_mode,
        validate_country_code,
        normalize_domain,
        ensure_domain_ready,
        get_allow_list_path,
        get_deny_list_path,
        get_domain_status,
        get_all_status,
    )
except ImportError:
    from src.auth import require_auth
    from src.geo_control import (
        read_list,
        write_list_atomic,
        set_mode_atomic,
        get_current_mode,
        validate_country_code,
        normalize_domain,
        ensure_domain_ready,
        get_allow_list_path,
        get_deny_list_path,
        get_domain_status,
        get_all_status,
    )

logger = logging.getLogger(__name__)

router = APIRouter()


class GeoModeRequest(BaseModel):
    mode: str  # "allow_only" or "deny_only"
    force: Optional[bool] = False


class GeoCountryRequest(BaseModel):
    country: str


@router.get("/v1/geo/health")
async def geo_health_check():
    """Geo service health check endpoint"""
    from datetime import datetime
    return {
        "status": "healthy",
        "service": "geo-agent",
        "timestamp": datetime.now().isoformat(),
    }



@router.post("/v1/geo/{domain}/mode")
async def set_geo_mode(
    domain: str,
    request: GeoModeRequest,
    _auth: bool = Depends(require_auth)
):
    """
    Switch a domain between allow_only and deny_only modes

    Body:
    {
        "mode": "allow_only" | "deny_only",
        "force": false  # optional, set to true to override safety checks
    }
    """
    try:
        domain = normalize_domain(domain)

        if request.mode not in ["allow_only", "deny_only"]:
            raise HTTPException(
                status_code=400,
                detail='mode must be "allow_only" or "deny_only"'
            )

        ensure_domain_ready(domain)

        # Safety: allow_only with an empty allow list blocks everyone.
        if request.mode == "allow_only":
            allow = read_list(get_allow_list_path(domain))
            if len(allow) == 0 and not request.force:
                raise HTTPException(
                    status_code=400,
                    detail="Allow list is empty. This would block all traffic. Send force=true to override."
                )

        set_mode_atomic(domain, request.mode)
        return {"ok": True, "domain": domain, "mode": request.mode}

    except HTTPException:
        raise
    except Exception as e:
        error_trace = traceback.format_exc()
        error_msg = str(e) if str(e) else f"{type(e).__name__}"
        logger.error(f"Unexpected error setting geo mode for {domain}: {error_msg}\n{error_trace}")
        raise HTTPException(status_code=500, detail=f"Internal error: {error_msg}")


@router.post("/v1/geo/{domain}/allow")
async def add_allow_country(
    domain: str,
    request: GeoCountryRequest,
    _auth: bool = Depends(require_auth)
):
    """
    Add a country to a domain's allow list

    Body:
    {
        "country": "ET"  # ISO-3166-1 alpha-2 uppercase
    }
    """
    try:
        domain = normalize_domain(domain)

        if not validate_country_code(request.country):
            raise HTTPException(
                status_code=400,
                detail='Invalid country code. Must be uppercase ISO-3166-1 alpha-2 (e.g. "ET").'
            )

        ensure_domain_ready(domain)

        allow_path = get_allow_list_path(domain)
        codes = read_list(allow_path)
        if request.country in codes:
            return {"ok": True, "domain": domain, "message": "Already in allow list"}

        codes.add(request.country)
        write_list_atomic(allow_path, codes)
        return {"ok": True, "domain": domain, "added": request.country}

    except HTTPException:
        raise
    except Exception as e:
        error_trace = traceback.format_exc()
        error_msg = str(e) if str(e) else f"{type(e).__name__}"
        logger.error(f"Unexpected error adding allow country for {domain}: {error_msg}\n{error_trace}")
        raise HTTPException(status_code=500, detail=f"Internal error: {error_msg}")


@router.delete("/v1/geo/{domain}/allow/{country}")
async def remove_allow_country(
    domain: str,
    country: str,
    force: bool = False,
    _auth: bool = Depends(require_auth)
):
    """
    Remove a country from a domain's allow list

    Query params:
    - force: bool (default: false) - set to true to override safety checks
    """
    try:
        domain = normalize_domain(domain)

        if not validate_country_code(country):
            raise HTTPException(status_code=400, detail="Invalid country code.")

        allow_path = get_allow_list_path(domain)
        codes = read_list(allow_path)
        if country not in codes:
            return {"ok": True, "domain": domain, "message": "Not in allow list"}

        # Safety: removing the last entry while in allow_only mode blocks everyone.
        if len(codes) == 1 and get_current_mode(domain) == "allow_only" and not force:
            raise HTTPException(
                status_code=400,
                detail="Removing the last country from the allow list in allow_only mode would block all traffic. Add ?force=true to override."
            )

        codes.remove(country)
        write_list_atomic(allow_path, codes)
        return {"ok": True, "domain": domain, "removed": country}

    except HTTPException:
        raise
    except Exception as e:
        error_trace = traceback.format_exc()
        error_msg = str(e) if str(e) else f"{type(e).__name__}"
        logger.error(f"Unexpected error removing allow country for {domain}: {error_msg}\n{error_trace}")
        raise HTTPException(status_code=500, detail=f"Internal error: {error_msg}")


@router.post("/v1/geo/{domain}/deny")
async def add_deny_country(
    domain: str,
    request: GeoCountryRequest,
    _auth: bool = Depends(require_auth)
):
    """
    Add a country to a domain's deny list

    Body:
    {
        "country": "CN"  # ISO-3166-1 alpha-2 uppercase
    }
    """
    try:
        domain = normalize_domain(domain)

        if not validate_country_code(request.country):
            raise HTTPException(
                status_code=400,
                detail='Invalid country code. Must be uppercase ISO-3166-1 alpha-2 (e.g. "CN").'
            )

        ensure_domain_ready(domain)

        deny_path = get_deny_list_path(domain)
        codes = read_list(deny_path)
        if request.country in codes:
            return {"ok": True, "domain": domain, "message": "Already in deny list"}

        codes.add(request.country)
        write_list_atomic(deny_path, codes)
        return {"ok": True, "domain": domain, "added": request.country}

    except HTTPException:
        raise
    except Exception as e:
        error_trace = traceback.format_exc()
        error_msg = str(e) if str(e) else f"{type(e).__name__}"
        logger.error(f"Unexpected error adding deny country for {domain}: {error_msg}\n{error_trace}")
        raise HTTPException(status_code=500, detail=f"Internal error: {error_msg}")


@router.delete("/v1/geo/{domain}/deny/{country}")
async def remove_deny_country(
    domain: str,
    country: str,
    _auth: bool = Depends(require_auth)
):
    """Remove a country from a domain's deny list"""
    try:
        domain = normalize_domain(domain)

        if not validate_country_code(country):
            raise HTTPException(status_code=400, detail="Invalid country code.")

        deny_path = get_deny_list_path(domain)
        codes = read_list(deny_path)
        if country not in codes:
            return {"ok": True, "domain": domain, "message": "Not in deny list"}

        codes.remove(country)
        write_list_atomic(deny_path, codes)
        return {"ok": True, "domain": domain, "removed": country}

    except HTTPException:
        raise
    except Exception as e:
        error_trace = traceback.format_exc()
        error_msg = str(e) if str(e) else f"{type(e).__name__}"
        logger.error(f"Unexpected error removing deny country for {domain}: {error_msg}\n{error_trace}")
        raise HTTPException(status_code=500, detail=f"Internal error: {error_msg}")


@router.get("/v1/geo/{domain}/status")
async def get_geo_domain_status(domain: str):
    """
    Geo access control status for one domain

    Returns:
    {
        "domain": "example.com",
        "mode": "allow_only" | "deny_only" | "unknown",
        "allow": ["ET", "KE"],
        "deny": ["CN"]
    }

    A domain with no geo configuration yet reports mode "unknown" with empty
    lists rather than 404 -- reading status must never provision anything.
    """
    try:
        return get_domain_status(normalize_domain(domain))
    except HTTPException:
        raise
    except Exception as e:
        error_trace = traceback.format_exc()
        error_msg = str(e) if str(e) else f"{type(e).__name__}"
        logger.error(f"Unexpected error getting geo status for {domain}: {error_msg}\n{error_trace}")
        raise HTTPException(status_code=500, detail=f"Internal error: {error_msg}")


@router.get("/v1/geo/status")
async def get_geo_status():
    """
    Geo access control status for every configured domain

    Returns:
    {
        "domains": [{"domain": ..., "mode": ..., "allow": [...], "deny": [...]}],
        "total_domains": 2
    }
    """
    try:
        return get_all_status()
    except Exception as e:
        error_trace = traceback.format_exc()
        error_msg = str(e) if str(e) else f"{type(e).__name__}"
        logger.error(f"Unexpected error getting geo status: {error_msg}\n{error_trace}")
        raise HTTPException(status_code=500, detail=f"Internal error: {error_msg}")


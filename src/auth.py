"""
Shared authentication dependency for the WAF Agent's FastAPI apps.

Lives in its own module so both main.py and geo_main.py enforce the identical
policy rather than each carrying its own copy.
"""

import logging
from typing import Optional

from fastapi import HTTPException, Request, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

try:
    from .security import is_trusted_local_request, verify_auth_token
except ImportError:
    from src.security import is_trusted_local_request, verify_auth_token

logger = logging.getLogger(__name__)

# auto_error=False so a missing Authorization header reaches require_auth()
# instead of being rejected by FastAPI first; require_auth decides whether the
# omission is acceptable.
security = HTTPBearer(auto_error=False)


def require_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security),
) -> bool:
    """
    Enforce the bearer token, except for requests originating on this machine.

    A backend running on the same host reaches the agent over loopback, where
    the request never touches a network, so requiring a shared token there is
    setup friction with no security benefit. Every other caller must present
    one.

    Returns True when the caller was treated as local, so an endpoint can apply
    the same relaxation to a payload signature.
    """
    if is_trusted_local_request(request):
        return True

    presented = (credentials.credentials or "") if credentials else ""

    if not presented.strip():
        raise HTTPException(
            status_code=403,
            detail=(
                "Not authenticated. A bearer token is required for non-local "
                "requests. Only callers on this machine (loopback) may omit it."
            ),
        )

    if not verify_auth_token(presented):
        logger.warning(
            "Rejected request from %s: bearer token does not match "
            "WAF_AGENT_AUTH_TOKEN",
            request.client.host if request.client else "unknown",
        )
        raise HTTPException(status_code=403, detail="Invalid bearer token.")

    return False

"""
Security and authentication utilities for WAF Agent
"""

import base64
import ipaddress
import logging
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from .config import PRIVATE_KEY_PATH

logger = logging.getLogger(__name__)


# Headers a reverse proxy adds when it forwards a request. If any are present,
# request.client.host is the proxy's address rather than the real caller's, so
# a loopback check would wrongly trust every remote client.
_FORWARDING_HEADERS = (
    "x-forwarded-for",
    "x-real-ip",
    "forwarded",
    "x-forwarded-host",
)


def _is_loopback(host: str) -> bool:
    """True when the address refers to this machine."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False

    # ::ffff:127.0.0.1 is an IPv4 address wearing an IPv6 costume; unwrap it
    # because IPv6Address.is_loopback is only true for ::1.
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped

    return address.is_loopback


def is_trusted_local_request(request) -> bool:
    """
    Decide whether a request may skip the bearer token and signature.

    Only requests originating on this same machine qualify. The backend applies
    the mirror-image rule: it omits credentials only when WAF_AGENT_URL is a
    loopback address, so the two sides agree on exactly one trusted case.

    Returns False — meaning full credentials are required — whenever we cannot
    be certain, specifically:

    * WAF_AGENT_STRICT_AUTH is set, which forces credentials unconditionally.
    * The request carries reverse-proxy forwarding headers. Behind a proxy on
      localhost every request looks like loopback, so trusting the peer address
      would hand an auth bypass to the whole internet.
    * The peer address is missing or is anything other than loopback.
    """
    if os.getenv("WAF_AGENT_STRICT_AUTH", "").strip().lower() in ("1", "true", "yes"):
        return False

    for header in _FORWARDING_HEADERS:
        if request.headers.get(header):
            logger.warning(
                "Refusing to treat request as local: %s header present, so the "
                "peer address is a proxy rather than the real client.",
                header,
            )
            return False

    client = request.client
    if client is None or not client.host:
        return False

    return _is_loopback(client.host)


def load_private_key() -> rsa.RSAPrivateKey:
    """Load the private key for decryption/verification"""
    try:
        with open(PRIVATE_KEY_PATH, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        return private_key
    except FileNotFoundError:
        logger.error(f"Private key not found at {PRIVATE_KEY_PATH}")
        raise
    except Exception as e:
        logger.error(f"Error loading private key: {e}")
        raise


def verify_signature(data: bytes, signature: str) -> bool:
    """Verify the signature of the request"""
    if not signature or not signature.strip():
        logger.error("Signature is empty")
        return False
    
    if not data:
        logger.error("Data to verify is empty")
        return False
    
    try:
        # Validate private key exists
        if not PRIVATE_KEY_PATH.exists():
            logger.error(f"Private key not found at {PRIVATE_KEY_PATH}")
            return False
        
        private_key = load_private_key()
        public_key = private_key.public_key()
        
        # Decode base64 signature
        try:
            signature_bytes = base64.b64decode(signature)
        except Exception as e:
            logger.error(f"Failed to decode base64 signature: {e}")
            return False
        
        if len(signature_bytes) == 0:
            logger.error("Decoded signature is empty")
            return False
        
        data_str = data.decode('utf-8')
        logger.info(f"Verifying signature for data: '{data_str}'")
        logger.info(f"Data bytes (hex): {data.hex()}")
        logger.info(f"Signature length: {len(signature_bytes)} bytes")
        
        # Verify signature
        try:
            public_key.verify(
                signature_bytes,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            logger.info("Signature verification successful")
            return True
        except Exception as verify_error:
            logger.error(f"Signature verification failed: {verify_error}")
            logger.error(f"Data being verified: '{data_str}'")
            logger.error(f"Data bytes (hex): {data.hex()}")
            logger.error(f"Signature (first 50 chars): {signature[:50]}...")
            logger.error(f"Signature length: {len(signature_bytes)} bytes")
            logger.error(f"Private key path: {PRIVATE_KEY_PATH}")
            logger.error(f"Private key exists: {PRIVATE_KEY_PATH.exists()}")
            return False
    except FileNotFoundError as e:
        logger.error(f"Private key file not found: {e}")
        return False
    except Exception as e:
        logger.error(f"Signature verification error: {e}", exc_info=True)
        return False

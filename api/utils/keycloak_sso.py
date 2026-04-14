"""
Keycloak SSO JWT Authentication Module for RAGFlow

This module provides Keycloak OIDC JWT token verification for RAGFlow.
It allows users authenticated via Keycloak SSO to access RAGFlow API seamlessly.

Architecture:
- When KEYCLOAK_SSO_ENABLED is True, _load_user() will try Keycloak JWT
  verification before falling back to RAGFlow's native itsdangerous token.
- JWT tokens are verified using Keycloak's JWKS public keys.
- Verified users are matched to RAGFlow users by email.
- If auto-create is enabled, new users are created automatically.
"""

import logging
import os
import threading
import time
from typing import Any

import jwt
import requests

from common.constants import StatusEnum
from api.db.services import UserService

logger = logging.getLogger(__name__)

# JWKS cache
_jwks_cache: dict[str, dict[str, Any]] = {}
_jwks_cache_lock = threading.Lock()
_JWKS_CACHE_TTL = 3600  # 1 hour


def _get_config(key: str, default: str = "") -> str:
    """Get configuration from environment variables.

    NOTE: RAGFlow does not have a unified config framework like Dify's dify_config,
    so we read directly from os.environ. All KEYCLOAK_SSO_* env vars are documented
    in docs/role-extraction.md and must be set consistently across all services.
    """
    return os.environ.get(key, default)


def is_keycloak_enabled() -> bool:
    """Check if Keycloak authentication is enabled."""
    return _get_config("KEYCLOAK_SSO_ENABLED", "false").lower() in ("true", "1", "yes")


def _fetch_jwks(jwks_uri: str) -> list[dict[str, Any]]:
    """Fetch JWKS keys from Keycloak with caching.

    Thread-safe: uses a lock to prevent concurrent JWKS fetches for the same URI.
    """
    now = time.time()

    # Fast path: check cache without lock
    cached = _jwks_cache.get(jwks_uri)
    if cached and (now - cached["fetched_at"]) < _JWKS_CACHE_TTL:
        return cached["keys"]

    # Slow path: acquire lock and double-check
    with _jwks_cache_lock:
        cached = _jwks_cache.get(jwks_uri)
        if cached and (now - cached["fetched_at"]) < _JWKS_CACHE_TTL:
            return cached["keys"]

        try:
            response = requests.get(jwks_uri, timeout=10)
            response.raise_for_status()
            jwks_data = response.json()
            keys = jwks_data.get("keys", [])

            _jwks_cache[jwks_uri] = {
                "keys": keys,
                "fetched_at": time.time(),
            }

            logger.info("Keycloak SSO: Fetched %d JWKS keys from %s", len(keys), jwks_uri)
            return keys
        except Exception as e:
            logger.error("Keycloak SSO: Failed to fetch JWKS from %s: %s", jwks_uri, e)
            if cached:
                logger.warning("Keycloak SSO: Using expired cached JWKS keys")
                return cached["keys"]
            raise


def verify_keycloak_token(token: str) -> dict[str, Any] | None:
    """Verify a Keycloak JWT access token.

    Args:
        token: The raw JWT token string (without "Bearer " prefix)

    Returns:
        Decoded token payload dict if valid, None if invalid
    """
    if not is_keycloak_enabled():
        return None

    jwks_uri = _get_config("KEYCLOAK_SSO_JWKS_URI")
    issuer = _get_config("KEYCLOAK_SSO_ISSUER")
    client_id = _get_config("KEYCLOAK_SSO_CLIENT_ID", "ragflow-console")

    if not jwks_uri or not issuer:
        logger.debug("Keycloak SSO: JWKS URI or Issuer not configured, skipping")
        return None

    try:
        # Decode header without verification to get kid
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")

        if not kid:
            logger.debug("Keycloak SSO: No kid in JWT header, not a Keycloak token")
            return None

        # Fetch JWKS keys
        keys = _fetch_jwks(jwks_uri)

        # Find matching key
        matching_key = None
        for key in keys:
            if key.get("kid") == kid:
                matching_key = key
                break

        if not matching_key:
            logger.warning("Keycloak SSO: No matching key found for kid=%s", kid)
            return None

        # Construct public key from JWK
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(matching_key)

        # Verify token
        decoded = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=client_id,
            issuer=issuer,
        )

        logger.info(
            "Keycloak SSO: Successfully verified token for user %s (email=%s)",
            decoded.get("sub"),
            decoded.get("email", "N/A"),
        )
        return decoded

    except jwt.ExpiredSignatureError:
        logger.debug("Keycloak SSO: Token has expired")
        return None
    except jwt.InvalidAudienceError:
        logger.debug("Keycloak SSO: Invalid audience")
        return None
    except jwt.InvalidIssuerError:
        logger.debug("Keycloak SSO: Invalid issuer")
        return None
    except jwt.DecodeError as e:
        logger.debug("Keycloak SSO: Token decode error: %s", e)
        return None
    except Exception as e:
        logger.warning("Keycloak SSO: Unexpected error during token verification: %s", e)
        return None


def extract_keycloak_roles(decoded_token: dict[str, Any]) -> list[str]:
    """Extract roles from Keycloak token.

    Keycloak realm roles are in: realm_access.roles
    Keycloak client roles are in: resource_access.<client_id>.roles

    Args:
        decoded_token: The verified JWT payload

    Returns:
        List of role strings
    """
    roles: list[str] = []

    # Extract realm roles
    realm_access = decoded_token.get("realm_access", {})
    if isinstance(realm_access, dict):
        realm_roles = realm_access.get("roles", [])
        if isinstance(realm_roles, list):
            roles.extend(realm_roles)

    return roles


def get_platform_role(roles: list[str]) -> str:
    """Determine the platform role from Keycloak roles.

    Priority: super_admin > admin > teacher > student

    Args:
        roles: List of Keycloak realm roles

    Returns:
        The highest-priority role string
    """
    role_priority = ["super_admin", "admin", "teacher", "student"]
    for role in role_priority:
        if role in roles:
            return role
    return "student"  # Default role


def get_or_create_user_from_sso(decoded_token: dict[str, Any]):
    """Get or create a RAGFlow user from a verified Keycloak token.

    Args:
        decoded_token: The verified Keycloak JWT payload

    Returns:
        User object if found/created, None otherwise
    """
    email = decoded_token.get("email")
    if not email:
        logger.warning("Keycloak SSO: No email in token, cannot match user")
        return None

    name = decoded_token.get("name") or decoded_token.get("preferred_username") or email.split("@")[0]

    # Try to find existing user by email
    users = UserService.query_user_by_email(email)
    if users:
        user = users[0]
        # Check if user is active
        if hasattr(user, 'status') and user.status == StatusEnum.VALID.value:
            logger.info("Keycloak SSO: Found existing user for %s", email)
            return user
        else:
            logger.warning("Keycloak SSO: User %s exists but status is not VALID", email)
            return None

    # Auto-create user if enabled
    auto_create = _get_config("KEYCLOAK_SSO_AUTO_CREATE_ACCOUNT", "true").lower() in ("true", "1", "yes")
    if not auto_create:
        logger.warning(
            "Keycloak SSO: No user found for %s and auto-create is disabled",
            email,
        )
        return None

    try:
        from common.misc_utils import get_uuid
        import hashlib

        # Create user with a random access token
        access_token = get_uuid()
        user_id = get_uuid()

        UserService.save(
            id=user_id,
            email=email,
            nickname=name,
            access_token=access_token,
            status=StatusEnum.VALID.value,
        )

        # Query the newly created user
        user = UserService.filter_by_id(user_id)
        if user:
            logger.info("Keycloak SSO: Auto-created user for %s", email)
            return user

        logger.error("Keycloak SSO: Failed to query newly created user for %s", email)
        return None

    except Exception as e:
        logger.error("Keycloak SSO: Failed to create user for %s: %s", email, e)
        return None

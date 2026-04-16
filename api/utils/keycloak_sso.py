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
from urllib.parse import urljoin

import jwt
import requests

from api.db import UserTenantRole
from api.db.services.file_service import FileService
from api.db.services.llm_service import get_init_tenant_llm
from api.db.services.tenant_llm_service import TenantLLMService
from api.db.services.user_service import UserService, TenantService, UserTenantService
from common import settings
from common.constants import StatusEnum
from common.misc_utils import get_uuid

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


def _get_oauth_config() -> dict[str, Any]:
    oauth_config = getattr(settings, "OAUTH_CONFIG", {}) or {}
    keycloak_config = oauth_config.get("keycloak", {})
    return keycloak_config if isinstance(keycloak_config, dict) else {}


def _get_keycloak_token_url() -> str:
    oauth_config = _get_oauth_config()
    token_url = oauth_config.get("token_url")
    if token_url:
        return token_url

    issuer = _get_config("KEYCLOAK_SSO_ISSUER")
    if issuer:
        normalized_issuer = issuer.rstrip("/") + "/"
        return urljoin(normalized_issuer, "protocol/openid-connect/token")

    return ""


def _get_keycloak_client_credentials() -> tuple[str, str]:
    oauth_config = _get_oauth_config()
    client_id = oauth_config.get("client_id") or "ragflow-console"
    client_secret = oauth_config.get("client_secret") or ""
    return client_id, client_secret


def _get_allowed_client_ids() -> list[str]:
    """Return the allowed Keycloak client ids for SmartAA SSO tokens.

    The env keeps backward compatibility with the original single-client setup,
    but now supports a comma-separated allowlist so tokens issued for the admin
    console can also open the embedded RAGFlow workspace without a second login.
    """
    raw_value = _get_config("KEYCLOAK_SSO_CLIENT_ID", "ragflow-console")
    return [item.strip() for item in raw_value.split(",") if item.strip()]


def _is_client_allowed(decoded: dict[str, Any], allowed_client_ids: list[str]) -> bool:
    """Accept tokens whose audience or azp matches one of the allowed clients."""
    if not allowed_client_ids:
        return True

    audience = decoded.get("aud")
    audiences = audience if isinstance(audience, list) else [audience] if audience else []
    azp = decoded.get("azp")

    return bool(set(audiences).intersection(allowed_client_ids)) or azp in allowed_client_ids


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
    allowed_client_ids = _get_allowed_client_ids()

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
            issuer=issuer,
            options={"verify_aud": False},
        )

        if not _is_client_allowed(decoded, allowed_client_ids):
            logger.debug(
                "Keycloak SSO: Token client is not allowed. aud=%s azp=%s allowed=%s",
                decoded.get("aud"),
                decoded.get("azp"),
                allowed_client_ids,
            )
            return None

        logger.info(
            "Keycloak SSO: Successfully verified token for user %s (email=%s)",
            decoded.get("sub"),
            decoded.get("email", "N/A"),
        )
        return decoded

    except jwt.ExpiredSignatureError:
        logger.debug("Keycloak SSO: Token has expired")
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


def authenticate_keycloak_user(username: str, password: str) -> dict[str, Any] | None:
    """Authenticate a user against Keycloak using username/password."""
    if not is_keycloak_enabled():
        return None

    token_url = _get_keycloak_token_url()
    client_id, client_secret = _get_keycloak_client_credentials()

    if not token_url or not client_id:
        logger.warning("Keycloak SSO: token endpoint or client id is not configured")
        return None

    try:
        payload = {
            "grant_type": "password",
            "client_id": client_id,
            "username": username,
            "password": password,
            "scope": "openid email profile",
        }
        if client_secret:
            payload["client_secret"] = client_secret

        response = requests.post(token_url, data=payload, timeout=10)
        if response.status_code != 200:
            logger.info(
                "Keycloak SSO: Password authentication failed for %s with status %s",
                username,
                response.status_code,
            )
            return None

        token_payload = response.json()
        access_token = token_payload.get("access_token")
        if not access_token:
            logger.warning("Keycloak SSO: Keycloak token response for %s has no access_token", username)
            return None

        decoded_token = verify_keycloak_token(access_token)
        if not decoded_token:
            logger.warning("Keycloak SSO: access_token verification failed for %s", username)
            return None

        token_payload["decoded_access_token"] = decoded_token
        return token_payload
    except Exception as e:
        logger.warning("Keycloak SSO: password authentication error for %s: %s", username, e)
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


def _ensure_user_bootstrap(user: Any) -> bool:
    """Ensure SSO users always have a usable tenant workspace."""
    user_id = getattr(user, "id", None)
    if not user_id:
        return False

    nickname = getattr(user, "nickname", None) or "User"
    tenant_exists = TenantService.get_or_none(id=user_id) is not None
    user_tenant_exists = UserTenantService.filter_by_tenant_and_user_id(user_id, user_id) is not None

    try:
        if not tenant_exists:
            TenantService.insert(
                id=user_id,
                name=f"{nickname}‘s Kingdom",
                llm_id=settings.CHAT_MDL,
                embd_id=settings.EMBEDDING_MDL,
                asr_id=settings.ASR_MDL,
                parser_ids=settings.PARSERS,
                img2txt_id=settings.IMAGE2TEXT_MDL,
                rerank_id=settings.RERANK_MDL,
            )

        if not user_tenant_exists:
            UserTenantService.insert(
                tenant_id=user_id,
                user_id=user_id,
                invited_by=user_id,
                role=UserTenantRole.OWNER,
            )

        if not TenantLLMService.query(tenant_id=user_id):
            tenant_llm = get_init_tenant_llm(user_id)
            if tenant_llm:
                TenantLLMService.insert_many(tenant_llm)

        # Ensure root folder exists for this tenant.
        FileService.get_root_folder(user_id)
        return True
    except Exception as e:
        logger.error("Keycloak SSO: Failed to bootstrap tenant for user %s: %s", user_id, e)
        return False


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
            _ensure_user_bootstrap(user)
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
            _ensure_user_bootstrap(user)
            logger.info("Keycloak SSO: Auto-created user for %s", email)
            return user

        logger.error("Keycloak SSO: Failed to query newly created user for %s", email)
        return None

    except Exception as e:
        logger.error("Keycloak SSO: Failed to create user for %s: %s", email, e)
        return None

import logging
from typing import Optional, Dict, Any
from fastapi import Header, HTTPException, status
from app.config import settings

logger = logging.getLogger("netscope.supabase")

_supabase_client = None


def get_supabase_client():
    global _supabase_client
    if _supabase_client is not None:
        return _supabase_client

    if not settings.has_supabase:
        return None

    try:
        from supabase import create_client, Client
        key = settings.SUPABASE_SERVICE_KEY or settings.SUPABASE_KEY
        _supabase_client = create_client(settings.SUPABASE_URL, key)
        logger.info(f"Supabase client initialized for {settings.SUPABASE_URL}")
        return _supabase_client
    except Exception as e:
        logger.error(f"Failed to initialize Supabase client: {e}")
        return None


async def get_current_user(authorization: Optional[str] = Header(None)) -> Optional[Dict[str, Any]]:
    """
    FastAPI dependency to extract and verify Supabase JWT token.
    If Supabase is configured, verifies Bearer token via supabase.auth.get_user(jwt).
    If authorization header is missing and Supabase is configured, returns None (or can raise 401).
    """
    if not settings.has_supabase:
        # Supabase not configured: local standalone mode
        return None

    if not authorization or not authorization.startswith("Bearer "):
        return None

    token = authorization.split(" ", 1)[1].strip()
    if not token:
        return None

    client = get_supabase_client()
    if not client:
        return None

    try:
        # Verify with Supabase Auth API
        user_res = client.auth.get_user(token)
        if user_res and user_res.user:
            return {
                "id": user_res.user.id,
                "email": user_res.user.email,
                "role": user_res.user.role,
                "metadata": user_res.user.user_metadata or {}
            }
    except Exception as ex:
        logger.warning(f"Failed to verify Supabase JWT: {ex}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired Supabase authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return None


async def require_auth_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """Strict dependency for endpoints that require an authenticated Supabase user."""
    user = await get_current_user(authorization)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please sign in via Supabase.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

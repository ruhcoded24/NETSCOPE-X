import asyncio
import pytest
from unittest.mock import patch, MagicMock
from fastapi import HTTPException
from app.database.supabase_client import get_current_user, require_auth_user, get_supabase_client
from app.config import settings


def test_get_current_user_no_token():
    """Without authorization header, returns None in standalone mode."""
    async def run():
        user = await get_current_user(None)
        assert user is None
    asyncio.run(run())


def test_require_auth_user_raises_without_token():
    """Protected endpoints require valid auth."""
    async def run():
        with patch.object(settings, "SUPABASE_URL", "https://mock.supabase.co"), \
             patch.object(settings, "SUPABASE_KEY", "mock_key"):
            with pytest.raises(HTTPException) as exc_info:
                await require_auth_user(None)
            assert exc_info.value.status_code == 401
    asyncio.run(run())


def test_valid_supabase_token():
    """Valid Bearer token resolves user ID and email."""
    async def run():
        mock_user_obj = MagicMock()
        mock_user_obj.id = "user_uuid_1234"
        mock_user_obj.email = "analyst@netscope.internal"
        mock_user_obj.role = "authenticated"
        mock_user_obj.user_metadata = {"full_name": "Senior SOC Analyst"}

        mock_res = MagicMock()
        mock_res.user = mock_user_obj

        mock_client = MagicMock()
        mock_client.auth.get_user.return_value = mock_res

        with patch("app.database.supabase_client.get_supabase_client", return_value=mock_client), \
             patch.object(settings, "SUPABASE_URL", "https://mock.supabase.co"), \
             patch.object(settings, "SUPABASE_KEY", "mock_key"):
            
            user = await get_current_user("Bearer test_valid_token_xyz")
            assert user is not None
            assert user["id"] == "user_uuid_1234"
            assert user["email"] == "analyst@netscope.internal"
    asyncio.run(run())


def test_supabase_config_properties():
    """Verify has_supabase flag responds accurately."""
    with patch.object(settings, "SUPABASE_URL", ""), patch.object(settings, "SUPABASE_KEY", ""):
        assert settings.has_supabase is False

    with patch.object(settings, "SUPABASE_URL", "https://proj.supabase.co"), \
         patch.object(settings, "SUPABASE_KEY", "key"):
        assert settings.has_supabase is True

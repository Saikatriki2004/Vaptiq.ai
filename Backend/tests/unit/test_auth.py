"""
Unit tests for auth.py

Tests cover:
- JWT token validation
- Token expiration handling
- Invalid token handling
- Role-based access control
- Audit logging integration
"""

import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
import jwt


class TestGetCurrentUser:
    """Tests for JWT authentication function."""
    
    @pytest.fixture
    def mock_credentials(self):
        """Create mock HTTP credentials."""
        creds = MagicMock(spec=HTTPAuthorizationCredentials)
        creds.credentials = "valid.jwt.token"
        return creds
    
    @pytest.fixture
    def mock_request(self):
        """Create mock request with client IP."""
        request = MagicMock()
        request.client.host = "192.0.2.1"
        return request
    
    @pytest.fixture
    def mock_user(self):
        """Create mock user object."""
        user = MagicMock()
        user.id = "user-123"
        user.role = "USER"
        user.credits = 100
        return user
    
    @pytest.mark.asyncio
    async def test_valid_jwt_returns_user(self, mock_credentials, mock_request, mock_user):
        """Should decode valid JWT and return user."""
        with patch('auth.jwt.decode') as mock_decode:
            with patch('auth.db.user.find_unique', new_callable=AsyncMock) as mock_find:
                with patch('auth.audit_logger') as mock_logger:
                    mock_decode.return_value = {"sub": "user-123"}
                    mock_find.return_value = mock_user
                    
                    # Import here to avoid module-level SUPABASE_JWT_SECRET check
                    with patch.dict('os.environ', {'SUPABASE_JWT_SECRET': 'a' * 32}):
                        from auth import get_current_user
                        result = await get_current_user(mock_credentials, mock_request)
                    
                    assert result.id == "user-123"
                    mock_logger.log_auth_success.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_expired_jwt_raises_401(self, mock_credentials, mock_request):
        """Should reject expired JWT with 401."""
        with patch('auth.jwt.decode') as mock_decode:
            with patch('auth.audit_logger') as mock_logger:
                mock_decode.side_effect = jwt.ExpiredSignatureError()
                
                with patch.dict('os.environ', {'SUPABASE_JWT_SECRET': 'a' * 32}):
                    from auth import get_current_user
                    
                    with pytest.raises(HTTPException) as exc_info:
                        await get_current_user(mock_credentials, mock_request)
                    
                    assert exc_info.value.status_code == 401
                    assert "expired" in exc_info.value.detail.lower()
                    mock_logger.log_auth_failure.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_invalid_signature_raises_401(self, mock_credentials, mock_request):
        """Should reject invalid JWT signature with 401."""
        with patch('auth.jwt.decode') as mock_decode:
            with patch('auth.audit_logger') as mock_logger:
                mock_decode.side_effect = jwt.InvalidSignatureError()
                
                with patch.dict('os.environ', {'SUPABASE_JWT_SECRET': 'a' * 32}):
                    from auth import get_current_user
                    
                    with pytest.raises(HTTPException) as exc_info:
                        await get_current_user(mock_credentials, mock_request)
                    
                    assert exc_info.value.status_code == 401
                    assert "invalid" in exc_info.value.detail.lower()
    
    @pytest.mark.asyncio
    async def test_missing_sub_claim_raises_401(self, mock_credentials, mock_request):
        """Should reject missing 'sub' claim with 401."""
        with patch('auth.jwt.decode') as mock_decode:
            with patch('auth.audit_logger') as mock_logger:
                mock_decode.return_value = {"iss": "supabase"}  # No 'sub' claim
                
                with patch.dict('os.environ', {'SUPABASE_JWT_SECRET': 'a' * 32}):
                    from auth import get_current_user
                    
                    with pytest.raises(HTTPException) as exc_info:
                        await get_current_user(mock_credentials, mock_request)
                    
                    assert exc_info.value.status_code == 401
                    assert "invalid" in exc_info.value.detail.lower()
    
    @pytest.mark.asyncio
    async def test_user_not_found_raises_401(self, mock_credentials, mock_request):
        """Should return 401 when user not in database."""
        with patch('auth.jwt.decode') as mock_decode:
            with patch('auth.db.user.find_unique', new_callable=AsyncMock) as mock_find:
                with patch('auth.audit_logger') as mock_logger:
                    mock_decode.return_value = {"sub": "user-not-exists"}
                    mock_find.return_value = None
                    
                    with patch.dict('os.environ', {'SUPABASE_JWT_SECRET': 'a' * 32}):
                        from auth import get_current_user
                        
                        with pytest.raises(HTTPException) as exc_info:
                            await get_current_user(mock_credentials, mock_request)
                        
                        assert exc_info.value.status_code == 401
                        assert "not found" in exc_info.value.detail.lower()


class TestGetCurrentUserOptional:
    """Tests for optional authentication."""
    
    @pytest.mark.asyncio
    async def test_no_credentials_returns_none(self):
        """Should return None when no credentials provided."""
        with patch.dict('os.environ', {'SUPABASE_JWT_SECRET': 'a' * 32}):
            from auth import get_current_user_optional
            result = await get_current_user_optional(None, None)
            assert result is None
    
    @pytest.mark.asyncio
    async def test_with_credentials_calls_get_current_user(self):
        """Should call get_current_user when credentials provided."""
        mock_creds = MagicMock(spec=HTTPAuthorizationCredentials)
        mock_creds.credentials = "test.token"
        mock_user = MagicMock()
        mock_user.id = "user-123"
        
        with patch.dict('os.environ', {'SUPABASE_JWT_SECRET': 'a' * 32}):
            with patch('auth.get_current_user', new_callable=AsyncMock) as mock_get_user:
                mock_get_user.return_value = mock_user
                
                from auth import get_current_user_optional
                result = await get_current_user_optional(mock_creds, None)
                
                mock_get_user.assert_called_once()
                assert result.id == "user-123"


class TestRequireRole:
    """Tests for role-based access control."""
    
    @pytest.mark.asyncio
    async def test_admin_role_allows_admin(self):
        """Should allow admin user on admin-only endpoint."""
        mock_user = MagicMock()
        mock_user.id = "admin-123"
        mock_user.role = "ADMIN"
        mock_request = MagicMock()
        mock_request.client.host = "192.0.2.1"
        mock_request.url.path = "/admin/users"
        
        with patch.dict('os.environ', {'SUPABASE_JWT_SECRET': 'a' * 32}):
            with patch('auth.get_current_user', new_callable=AsyncMock) as mock_get_user:
                mock_get_user.return_value = mock_user
                
                from auth import require_role, UserRole
                check_role_func = require_role([UserRole.ADMIN])
                
                # This should not raise
                result = await check_role_func(mock_user, mock_request)
                assert result.id == "admin-123"
    
    @pytest.mark.asyncio
    async def test_user_role_denied_on_admin_endpoint(self):
        """Should deny regular user on admin-only endpoint."""
        mock_user = MagicMock()
        mock_user.id = "user-123"
        mock_user.role = "USER"
        mock_request = MagicMock()
        mock_request.client.host = "192.0.2.1"
        mock_request.url.path = "/admin/users"
        
        with patch.dict('os.environ', {'SUPABASE_JWT_SECRET': 'a' * 32}):
            with patch('auth.audit_logger') as mock_logger:
                from auth import require_role, UserRole
                check_role_func = require_role([UserRole.ADMIN])
                
                with pytest.raises(HTTPException) as exc_info:
                    await check_role_func(mock_user, mock_request)
                
                assert exc_info.value.status_code == 403
                assert "permission" in exc_info.value.detail.lower()
                mock_logger.log_access_denied.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_multiple_roles_allowed(self):
        """Should allow access when user has any of the allowed roles."""
        mock_user = MagicMock()
        mock_user.id = "auditor-123"
        mock_user.role = "AUDITOR"
        mock_request = MagicMock()
        mock_request.client.host = "192.0.2.1"
        
        with patch.dict('os.environ', {'SUPABASE_JWT_SECRET': 'a' * 32}):
            from auth import require_role, UserRole
            check_role_func = require_role([UserRole.ADMIN, UserRole.AUDITOR])
            
            # This should not raise
            result = await check_role_func(mock_user, mock_request)
            assert result.role == "AUDITOR"


class TestUserRole:
    """Tests for UserRole enum."""
    
    def test_role_values(self):
        """Should have correct role values."""
        with patch.dict('os.environ', {'SUPABASE_JWT_SECRET': 'a' * 32}):
            from auth import UserRole
            assert UserRole.ADMIN.value == "ADMIN"
            assert UserRole.USER.value == "USER"
            assert UserRole.AUDITOR.value == "AUDITOR"
    
    def test_role_is_string_enum(self):
        """Should be a string enum."""
        with patch.dict('os.environ', {'SUPABASE_JWT_SECRET': 'a' * 32}):
            from auth import UserRole
            assert isinstance(UserRole.ADMIN.value, str)

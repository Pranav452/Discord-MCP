"""
Unit tests for the authentication module.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
import sys
from pathlib import Path

# Add the app directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "app"))

from app.auth import AuthManager, Permission, AuthResult, APIKeyInfo


class TestAuthManager:
    """Test cases for the AuthManager class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.api_keys = ["test-key-1", "test-key-2"]
        self.admin_key = "admin-test-key"
        self.auth_manager = AuthManager(self.api_keys, self.admin_key)

    def test_init(self):
        """Test AuthManager initialization."""
        assert len(self.auth_manager.api_keys_info) == 3  # 2 regular + 1 admin
        assert self.admin_key in self.auth_manager.api_keys_info
        assert self.auth_manager.api_keys_info[self.admin_key].is_admin

    @pytest.mark.asyncio
    async def test_authenticate_valid_key(self):
        """Test authentication with valid API key."""
        result = await self.auth_manager.authenticate("test-key-1")
        
        assert result.is_valid
        assert result.api_key == "test-key-1"
        assert Permission.SEND_MESSAGE in result.permissions
        assert Permission.READ_MESSAGES in result.permissions

    @pytest.mark.asyncio
    async def test_authenticate_invalid_key(self):
        """Test authentication with invalid API key."""
        result = await self.auth_manager.authenticate("invalid-key")
        
        assert not result.is_valid
        assert result.error == "Invalid API key"

    @pytest.mark.asyncio
    async def test_authenticate_empty_key(self):
        """Test authentication with empty API key."""
        result = await self.auth_manager.authenticate("")
        
        assert not result.is_valid
        assert result.error == "No API key provided"

    @pytest.mark.asyncio
    async def test_authenticate_admin_key(self):
        """Test authentication with admin API key."""
        result = await self.auth_manager.authenticate(self.admin_key)
        
        assert result.is_valid
        assert result.api_key == self.admin_key
        assert Permission.ADMIN in result.permissions
        assert Permission.MODERATE_CONTENT in result.permissions

    @pytest.mark.asyncio
    async def test_check_permission_valid(self):
        """Test permission checking with valid key and permission."""
        has_permission = await self.auth_manager.check_permission(
            "test-key-1", Permission.SEND_MESSAGE
        )
        assert has_permission

    @pytest.mark.asyncio
    async def test_check_permission_invalid_key(self):
        """Test permission checking with invalid key."""
        has_permission = await self.auth_manager.check_permission(
            "invalid-key", Permission.SEND_MESSAGE
        )
        assert not has_permission

    @pytest.mark.asyncio
    async def test_check_permission_insufficient(self):
        """Test permission checking with insufficient permissions."""
        has_permission = await self.auth_manager.check_permission(
            "test-key-1", Permission.MODERATE_CONTENT
        )
        assert not has_permission

    @pytest.mark.asyncio
    async def test_is_admin_regular_key(self):
        """Test admin check with regular key."""
        is_admin = await self.auth_manager.is_admin("test-key-1")
        assert not is_admin

    @pytest.mark.asyncio
    async def test_is_admin_admin_key(self):
        """Test admin check with admin key."""
        is_admin = await self.auth_manager.is_admin(self.admin_key)
        assert is_admin

    @pytest.mark.asyncio
    async def test_is_admin_invalid_key(self):
        """Test admin check with invalid key."""
        is_admin = await self.auth_manager.is_admin("invalid-key")
        assert not is_admin

    def test_add_api_key(self):
        """Test adding new API key."""
        new_key = "new-test-key"
        permissions = {Permission.SEND_MESSAGE, Permission.READ_MESSAGES}
        
        result = self.auth_manager.add_api_key(new_key, permissions)
        assert result
        assert new_key in self.auth_manager.api_keys_info
        assert self.auth_manager.api_keys_info[new_key].permissions == permissions

    def test_add_existing_key(self):
        """Test adding existing API key."""
        permissions = {Permission.SEND_MESSAGE}
        
        result = self.auth_manager.add_api_key("test-key-1", permissions)
        assert not result

    def test_remove_api_key(self):
        """Test removing API key."""
        result = self.auth_manager.remove_api_key("test-key-1")
        assert result
        assert "test-key-1" not in self.auth_manager.api_keys_info

    def test_remove_nonexistent_key(self):
        """Test removing non-existent API key."""
        result = self.auth_manager.remove_api_key("nonexistent-key")
        assert not result

    def test_update_permissions(self):
        """Test updating API key permissions."""
        new_permissions = {Permission.SEND_MESSAGE, Permission.MODERATE_CONTENT}
        
        result = self.auth_manager.update_permissions("test-key-1", new_permissions)
        assert result
        assert self.auth_manager.api_keys_info["test-key-1"].permissions == new_permissions

    def test_update_permissions_nonexistent_key(self):
        """Test updating permissions for non-existent key."""
        new_permissions = {Permission.SEND_MESSAGE}
        
        result = self.auth_manager.update_permissions("nonexistent-key", new_permissions)
        assert not result

    def test_validate_key_format_valid(self):
        """Test key format validation with valid key."""
        valid_keys = [
            "test-key-123456789012345",
            "valid.key.with.dots",
            "valid_key_with_underscores",
            "ValidKeyWithMixedCase123"
        ]
        
        for key in valid_keys:
            assert self.auth_manager.validate_key_format(key)

    def test_validate_key_format_invalid(self):
        """Test key format validation with invalid keys."""
        invalid_keys = [
            "",
            "short",
            "key with spaces",
            "key@with#symbols",
            None,
            123
        ]
        
        for key in invalid_keys:
            assert not self.auth_manager.validate_key_format(key)

    def test_generate_api_key(self):
        """Test API key generation."""
        key = self.auth_manager.generate_api_key()
        assert key.startswith("discord-mcp-")
        assert len(key) > 32
        assert self.auth_manager.validate_key_format(key)

    def test_generate_api_key_custom_prefix(self):
        """Test API key generation with custom prefix."""
        key = self.auth_manager.generate_api_key("custom-prefix")
        assert key.startswith("custom-prefix-")
        assert len(key) > 32

    def test_get_key_info(self):
        """Test getting API key information."""
        info = self.auth_manager.get_key_info("test-key-1")
        assert info is not None
        assert info.key == "test-key-1"
        assert not info.is_admin

    def test_get_key_info_nonexistent(self):
        """Test getting information for non-existent key."""
        info = self.auth_manager.get_key_info("nonexistent-key")
        assert info is None

    def test_get_all_keys_info(self):
        """Test getting all API keys information."""
        all_info = self.auth_manager.get_all_keys_info()
        assert len(all_info) == 3
        
        # Check that keys are hashed in the output
        for key_hash, info in all_info.items():
            assert len(key_hash) == 16  # SHA256 hash truncated to 16 chars
            assert "permissions" in info
            assert "is_admin" in info

    def test_get_usage_stats(self):
        """Test getting usage statistics."""
        stats = self.auth_manager.get_usage_stats()
        assert stats["total_keys"] == 3
        assert stats["admin_keys"] == 1
        assert stats["regular_keys"] == 2
        assert stats["total_usage"] == 0  # No usage yet
        assert stats["average_usage"] == 0


class TestAuthResult:
    """Test cases for the AuthResult class."""

    def test_init_valid_result(self):
        """Test AuthResult initialization with valid result."""
        permissions = {Permission.SEND_MESSAGE, Permission.READ_MESSAGES}
        result = AuthResult(
            is_valid=True,
            api_key="test-key",
            permissions=permissions
        )
        
        assert result.is_valid
        assert result.api_key == "test-key"
        assert result.permissions == permissions

    def test_init_invalid_result(self):
        """Test AuthResult initialization with invalid result."""
        result = AuthResult(
            is_valid=False,
            error="Invalid API key"
        )
        
        assert not result.is_valid
        assert result.error == "Invalid API key"
        assert result.permissions == set()

    def test_post_init_none_permissions(self):
        """Test AuthResult post_init with None permissions."""
        result = AuthResult(is_valid=True, permissions=None)
        assert result.permissions == set()


class TestAPIKeyInfo:
    """Test cases for the APIKeyInfo class."""

    def test_init_basic(self):
        """Test APIKeyInfo initialization."""
        permissions = {Permission.SEND_MESSAGE}
        info = APIKeyInfo(key="test-key", permissions=permissions)
        
        assert info.key == "test-key"
        assert info.permissions == permissions
        assert not info.is_admin
        assert info.usage_count == 0
        assert info.created_at is not None

    def test_init_admin(self):
        """Test APIKeyInfo initialization with admin flag."""
        permissions = {Permission.ADMIN}
        info = APIKeyInfo(
            key="admin-key",
            permissions=permissions,
            is_admin=True
        )
        
        assert info.key == "admin-key"
        assert info.is_admin
        assert info.permissions == permissions


class TestPermission:
    """Test cases for the Permission enum."""

    def test_permission_values(self):
        """Test Permission enum values."""
        assert Permission.SEND_MESSAGE.value == "send_message"
        assert Permission.READ_MESSAGES.value == "read_messages"
        assert Permission.SEARCH_MESSAGES.value == "search_messages"
        assert Permission.MODERATE_CONTENT.value == "moderate_content"
        assert Permission.ADMIN.value == "admin"

    def test_permission_enum_length(self):
        """Test number of permissions defined."""
        assert len(Permission) == 5 
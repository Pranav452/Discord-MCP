"""
Authentication module for Discord MCP Server.

This module provides API key authentication, permission management,
and multi-tenancy support for the MCP server.
"""

import hashlib
import hmac
import time
from typing import List, Optional, Dict, Any, Set
from dataclasses import dataclass
from enum import Enum
import structlog

logger = structlog.get_logger(__name__)


class Permission(Enum):
    """Available permissions for API keys."""
    
    SEND_MESSAGE = "send_message"
    READ_MESSAGES = "read_messages"
    SEARCH_MESSAGES = "search_messages"
    MODERATE_CONTENT = "moderate_content"
    ADMIN = "admin"


@dataclass
class AuthResult:
    """Result of authentication attempt."""
    
    is_valid: bool
    api_key: Optional[str] = None
    permissions: Optional[Set[Permission]] = None
    error: Optional[str] = None
    
    def __post_init__(self):
        if self.permissions is None:
            self.permissions = set()


@dataclass
class APIKeyInfo:
    """Information about an API key."""
    
    key: str
    permissions: Set[Permission]
    is_admin: bool = False
    created_at: Optional[float] = None
    last_used: Optional[float] = None
    usage_count: int = 0
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = time.time()


class AuthManager:
    """
    Authentication manager for API key validation and permission management.
    
    This class handles API key authentication, permission checking,
    and usage tracking for the MCP server.
    """

    def __init__(self, api_keys: List[str], admin_api_key: str):
        """
        Initialize the authentication manager.
        
        Args:
            api_keys: List of valid API keys
            admin_api_key: Admin API key with full permissions
        """
        self.api_keys_info: Dict[str, APIKeyInfo] = {}
        self._setup_api_keys(api_keys, admin_api_key)
        
    def _setup_api_keys(self, api_keys: List[str], admin_api_key: str):
        """Set up API key information."""
        
        # Set up regular API keys with basic permissions
        basic_permissions = {
            Permission.SEND_MESSAGE,
            Permission.READ_MESSAGES,
            Permission.SEARCH_MESSAGES
        }
        
        for key in api_keys:
            if key and key != admin_api_key:
                self.api_keys_info[key] = APIKeyInfo(
                    key=key,
                    permissions=basic_permissions.copy(),
                    is_admin=False
                )
        
        # Set up admin API key with all permissions
        if admin_api_key:
            admin_permissions = {perm for perm in Permission}
            self.api_keys_info[admin_api_key] = APIKeyInfo(
                key=admin_api_key,
                permissions=admin_permissions,
                is_admin=True
            )
        
        logger.info(
            "API keys initialized",
            total_keys=len(self.api_keys_info),
            admin_key_present=bool(admin_api_key),
            auth_bypassed=len(self.api_keys_info) == 0
        )

    async def authenticate(self, token: str) -> AuthResult:
        """
        Authenticate a token (API key or session token).
        
        Args:
            token: API key or session token to authenticate
            
        Returns:
            AuthResult containing authentication status and permissions
        """
        if not token:
            return AuthResult(
                is_valid=False,
                error="No token provided"
            )
        
        # First, try to authenticate as API key
        key_info = self.api_keys_info.get(token)
        if key_info:
            # Update usage statistics for API key
            key_info.last_used = time.time()
            key_info.usage_count += 1
            
            logger.info(
                "API key authenticated",
                key_hash=self._hash_key(token),
                is_admin=key_info.is_admin,
                usage_count=key_info.usage_count
            )
            
            return AuthResult(
                is_valid=True,
                api_key=token,
                permissions=key_info.permissions.copy()
            )
        
        # If not an API key, try to authenticate as session token
        if self._validate_session_token(token):
            logger.info(
                "Session token authenticated",
                token_hash=self._hash_key(token)
            )
            
            # Grant basic permissions for session tokens
            basic_permissions = {
                Permission.SEND_MESSAGE,
                Permission.READ_MESSAGES,
                Permission.SEARCH_MESSAGES
            }
            
            return AuthResult(
                is_valid=True,
                api_key=token,
                permissions=basic_permissions
            )
        
        logger.warning("Invalid token used", token_hash=self._hash_key(token))
        return AuthResult(
            is_valid=False,
            error="Invalid token"
        )
    
    def _validate_session_token(self, token: str) -> bool:
        """
        Validate session token format and basic requirements.
        
        Args:
            token: Session token to validate
            
        Returns:
            True if token appears to be a valid session token
        """
        # Basic validation for session tokens
        # In production, you'd want more sophisticated validation
        if not token:
            return False
        
        # Check if it's a hex string of reasonable length (32+ characters)
        if len(token) >= 32 and all(c in '0123456789abcdefABCDEF' for c in token):
            return True
        
        # Check if it's a base64-like string of reasonable length
        if len(token) >= 32 and all(c.isalnum() or c in '+/=' for c in token):
            return True
        
        return False

    async def check_permission(self, api_key: str, permission: Permission) -> bool:
        """
        Check if an API key has a specific permission.
        
        Args:
            api_key: API key to check
            permission: Permission to check for
            
        Returns:
            True if the API key has the permission, False otherwise
        """
        key_info = self.api_keys_info.get(api_key)
        if not key_info:
            return False
        
        has_permission = permission in key_info.permissions
        
        logger.debug(
            "Permission check",
            key_hash=self._hash_key(api_key),
            permission=permission.value,
            has_permission=has_permission
        )
        
        return has_permission

    async def is_admin(self, api_key: str) -> bool:
        """
        Check if an API key has admin privileges.
        
        Args:
            api_key: API key to check
            
        Returns:
            True if the API key is an admin key, False otherwise
        """
        key_info = self.api_keys_info.get(api_key)
        if not key_info:
            return False
        
        return key_info.is_admin

    def get_key_info(self, api_key: str) -> Optional[APIKeyInfo]:
        """
        Get information about an API key.
        
        Args:
            api_key: API key to get information for
            
        Returns:
            APIKeyInfo if the key exists, None otherwise
        """
        return self.api_keys_info.get(api_key)

    def get_all_keys_info(self) -> Dict[str, Dict[str, Any]]:
        """
        Get information about all API keys (for admin use).
        
        Returns:
            Dictionary containing information about all API keys
        """
        return {
            self._hash_key(key): {
                "is_admin": info.is_admin,
                "permissions": [perm.value for perm in info.permissions],
                "created_at": info.created_at,
                "last_used": info.last_used,
                "usage_count": info.usage_count
            }
            for key, info in self.api_keys_info.items()
        }

    def add_api_key(self, api_key: str, permissions: Set[Permission], is_admin: bool = False) -> bool:
        """
        Add a new API key.
        
        Args:
            api_key: New API key to add
            permissions: Set of permissions for the key
            is_admin: Whether the key should have admin privileges
            
        Returns:
            True if the key was added successfully, False if it already exists
        """
        if api_key in self.api_keys_info:
            return False
        
        self.api_keys_info[api_key] = APIKeyInfo(
            key=api_key,
            permissions=permissions,
            is_admin=is_admin
        )
        
        logger.info(
            "API key added",
            key_hash=self._hash_key(api_key),
            is_admin=is_admin,
            permissions=[perm.value for perm in permissions]
        )
        
        return True

    def remove_api_key(self, api_key: str) -> bool:
        """
        Remove an API key.
        
        Args:
            api_key: API key to remove
            
        Returns:
            True if the key was removed successfully, False if it didn't exist
        """
        if api_key not in self.api_keys_info:
            return False
        
        del self.api_keys_info[api_key]
        
        logger.info(
            "API key removed",
            key_hash=self._hash_key(api_key)
        )
        
        return True

    def update_permissions(self, api_key: str, permissions: Set[Permission]) -> bool:
        """
        Update permissions for an API key.
        
        Args:
            api_key: API key to update
            permissions: New set of permissions
            
        Returns:
            True if the permissions were updated successfully, False if the key doesn't exist
        """
        key_info = self.api_keys_info.get(api_key)
        if not key_info:
            return False
        
        old_permissions = key_info.permissions.copy()
        key_info.permissions = permissions
        
        logger.info(
            "API key permissions updated",
            key_hash=self._hash_key(api_key),
            old_permissions=[perm.value for perm in old_permissions],
            new_permissions=[perm.value for perm in permissions]
        )
        
        return True

    def _hash_key(self, api_key: str) -> str:
        """
        Create a hash of an API key for logging purposes.
        
        Args:
            api_key: API key to hash
            
        Returns:
            Hashed version of the API key
        """
        return hashlib.sha256(api_key.encode()).hexdigest()[:16]

    def validate_key_format(self, api_key: str) -> bool:
        """
        Validate the format of an API key.
        
        Args:
            api_key: API key to validate
            
        Returns:
            True if the key format is valid, False otherwise
        """
        if not api_key or not isinstance(api_key, str):
            return False
        
        # Basic validation - key should be at least 16 characters
        if len(api_key) < 16:
            return False
        
        # Key should contain only alphanumeric characters and common symbols
        allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
        if not all(c in allowed_chars for c in api_key):
            return False
        
        return True

    def generate_api_key(self, prefix: str = "discord-mcp") -> str:
        """
        Generate a new API key.
        
        Args:
            prefix: Prefix for the API key
            
        Returns:
            Generated API key
        """
        import secrets
        import string
        
        # Generate a random suffix
        alphabet = string.ascii_letters + string.digits
        suffix = ''.join(secrets.choice(alphabet) for _ in range(32))
        
        return f"{prefix}-{suffix}"

    def get_usage_stats(self) -> Dict[str, Any]:
        """
        Get usage statistics for all API keys.
        
        Returns:
            Dictionary containing usage statistics
        """
        total_keys = len(self.api_keys_info)
        admin_keys = sum(1 for info in self.api_keys_info.values() if info.is_admin)
        total_usage = sum(info.usage_count for info in self.api_keys_info.values())
        
        return {
            "total_keys": total_keys,
            "admin_keys": admin_keys,
            "regular_keys": total_keys - admin_keys,
            "total_usage": total_usage,
            "average_usage": total_usage / total_keys if total_keys > 0 else 0
        } 
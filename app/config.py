"""
Configuration module for Discord MCP Server.

This module handles loading configuration from environment variables
and provides default values for all settings.
"""

import os
from typing import List, Optional
from dataclasses import dataclass, field
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


@dataclass
class Config:
    """Configuration settings for the Discord MCP Server."""
    
    # Discord Configuration
    discord_bot_token: str = field(
        default_factory=lambda: os.getenv("DISCORD_BOT_TOKEN", "")
    )
    discord_guild_id: Optional[str] = field(
        default_factory=lambda: os.getenv("DISCORD_GUILD_ID")
    )
    
    # MCP Server Configuration
    mcp_server_name: str = field(
        default_factory=lambda: os.getenv("MCP_SERVER_NAME", "discord-mcp-server")
    )
    mcp_server_version: str = field(
        default_factory=lambda: os.getenv("MCP_SERVER_VERSION", "1.0.0")
    )
    mcp_server_port: int = field(
        default_factory=lambda: int(os.getenv("MCP_SERVER_PORT", "8080"))
    )
    
    # Authentication Configuration
    api_keys: List[str] = field(
        default_factory=lambda: [
            key.strip() for key in os.getenv("API_KEYS", "").split(",")
            if key.strip()
        ]
    )
    admin_api_key: str = field(
        default_factory=lambda: os.getenv("ADMIN_API_KEY", "")
    )
    
    # MCP Inspector compatibility - allows bypassing auth for testing
    dangerously_omit_auth: bool = field(
        default_factory=lambda: os.getenv("DANGEROUSLY_OMIT_AUTH", "false").lower() == "true"
    )
    
    # Logging Configuration
    log_level: str = field(
        default_factory=lambda: os.getenv("LOG_LEVEL", "INFO")
    )
    log_to_file: bool = field(
        default_factory=lambda: os.getenv("LOG_TO_FILE", "true").lower() == "true"
    )
    audit_log_file: str = field(
        default_factory=lambda: os.getenv("AUDIT_LOG_FILE", "logs.md")
    )
    
    # Rate Limiting Configuration
    rate_limit_enabled: bool = field(
        default_factory=lambda: os.getenv("RATE_LIMIT_ENABLED", "false").lower() == "true"
    )
    rate_limit_requests_per_minute: int = field(
        default_factory=lambda: int(os.getenv("RATE_LIMIT_REQUESTS_PER_MINUTE", "60"))
    )
    
    # Security Configuration
    secret_key: str = field(
        default_factory=lambda: os.getenv("SECRET_KEY", "your-secret-key-here")
    )
    algorithm: str = field(
        default_factory=lambda: os.getenv("ALGORITHM", "HS256")
    )
    access_token_expire_minutes: int = field(
        default_factory=lambda: int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    )
    
    # Environment Configuration
    environment: str = field(
        default_factory=lambda: os.getenv("ENVIRONMENT", "development")
    )
    debug: bool = field(
        default_factory=lambda: os.getenv("DEBUG", "true").lower() == "true"
    )
    
    def __post_init__(self):
        """Validate configuration after initialization."""
        if not self.discord_bot_token:
            raise ValueError("DISCORD_BOT_TOKEN is required")
        
        # Only require API keys if authentication is not bypassed
        if not self.dangerously_omit_auth:
            if not self.api_keys:
                raise ValueError("At least one API key must be provided in API_KEYS")
            
            if not self.admin_api_key:
                raise ValueError("ADMIN_API_KEY is required")
        else:
            # Warn about bypassed authentication
            import warnings
            warnings.warn(
                "Authentication is bypassed (DANGEROUSLY_OMIT_AUTH=true). "
                "This should only be used for testing with MCP Inspector.",
                UserWarning
            )
    
    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment.lower() == "production"
    
    @property
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.environment.lower() == "development" 
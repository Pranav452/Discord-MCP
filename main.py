#!/usr/bin/env python3
"""
Main entry point for the Discord MCP Server.

This script starts the Discord MCP Server with proper configuration
and error handling.
"""

import asyncio
import logging
import sys
from pathlib import Path

# Add the app directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "app"))

try:
    from app.mcp_server import SimpleMCPServer
    from app.config import Config
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Please ensure all dependencies are installed: pip install -r requirements.txt")
    sys.exit(1)


def setup_logging():
    """Set up basic logging configuration."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('discord-mcp-server.log')
        ]
    )


def validate_environment():
    """Validate that required environment variables are set."""
    try:
        config = Config()
        if not config.discord_bot_token:
            print("Error: DISCORD_BOT_TOKEN environment variable is required")
            return False
        if not config.api_keys:
            print("Error: API_KEYS environment variable is required")
            return False
        if not config.admin_api_key:
            print("Error: ADMIN_API_KEY environment variable is required")
            return False
        return True
    except Exception as e:
        print(f"Error validating configuration: {e}")
        return False


async def run_server():
    """Run the Discord MCP Server."""
    print("Starting Discord MCP Server...")
    
    # Validate environment
    if not validate_environment():
        sys.exit(1)
    
    # Set up logging
    setup_logging()
    
    try:
        # Create and run the MCP server
        config = Config()
        server = SimpleMCPServer(config)
        await server.run()
    except KeyboardInterrupt:
        print("\nShutting down Discord MCP Server...")
    except Exception as e:
        print(f"Fatal error: {e}")
        logging.exception("Fatal error occurred")
        sys.exit(1)


if __name__ == "__main__":
    print("Discord MCP Server")
    print("=" * 50)
    print("A Model Context Protocol server for Discord integration")
    print("GitHub: https://github.com/modelcontextprotocol/inspector")
    print("=" * 50)
    
    try:
        asyncio.run(run_server())
    except Exception as e:
        print(f"Failed to start server: {e}")
        sys.exit(1) 
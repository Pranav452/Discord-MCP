#!/usr/bin/env python3
"""
Quick setup script for Discord MCP Server.
This script helps generate API keys and create the .env file.
"""

import os
import secrets
import string
from pathlib import Path


def generate_api_key(length=32):
    """Generate a secure API key."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def create_env_file():
    """Create a .env file with generated API keys."""
    env_path = Path('.env')
    
    print("🚀 Discord MCP Server Setup")
    print("=" * 40)
    
    # Get Discord bot token
    discord_token = input("Enter your Discord bot token: ").strip()
    
    if not discord_token:
        print("❌ Discord bot token is required!")
        return False
    
    # Generate API keys
    print("\n🔑 Generating API keys...")
    api_keys = [generate_api_key() for _ in range(3)]
    admin_key = generate_api_key()
    
    # Create .env content
    env_content = f"""# Discord Bot Configuration
DISCORD_BOT_TOKEN={discord_token}

# API Keys (comma-separated)
API_KEYS={','.join(api_keys)}

# Admin API Key
ADMIN_API_KEY={admin_key}

# Server Configuration
MCP_SERVER_PORT=8080
MCP_SERVER_NAME=Discord MCP Server
MCP_SERVER_VERSION=1.0.0

# Logging
AUDIT_LOG_FILE=audit.md
LOG_LEVEL=INFO
"""
    
    # Write .env file
    try:
        with open(env_path, 'w') as f:
            f.write(env_content)
        
        print(f"✅ Created .env file at {env_path.absolute()}")
        print("\n🔑 Generated API Keys:")
        print(f"   Regular API Keys: {', '.join(api_keys)}")
        print(f"   Admin API Key: {admin_key}")
        print("\n⚠️  Keep these keys secure and never share them publicly!")
        
        return True
        
    except Exception as e:
        print(f"❌ Error creating .env file: {e}")
        return False


def main():
    """Main setup function."""
    if Path('.env').exists():
        overwrite = input(".env file already exists. Overwrite? (y/N): ").strip().lower()
        if overwrite != 'y':
            print("Setup cancelled.")
            return
    
    if create_env_file():
        print("\n🎉 Setup complete!")
        print("\nNext steps:")
        print("1. Make sure your Discord bot is added to your server")
        print("2. Run: python main.py")
        print("3. Your MCP server will be available at http://localhost:8080")
        print("4. Use the MCP Inspector to test: https://github.com/modelcontextprotocol/inspector")
    else:
        print("\n❌ Setup failed. Please check the errors above.")


if __name__ == "__main__":
    main() 
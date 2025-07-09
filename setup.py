#!/usr/bin/env python3
"""
Setup script for Discord MCP Server.

This script helps with initial setup and configuration of the Discord MCP Server.
"""

import os
import secrets
import string
import subprocess
import sys
from pathlib import Path


def generate_api_key(prefix="discord-mcp"):
    """Generate a secure API key."""
    alphabet = string.ascii_letters + string.digits
    suffix = ''.join(secrets.choice(alphabet) for _ in range(32))
    return f"{prefix}-{suffix}"


def create_env_file():
    """Create .env file with generated API keys."""
    env_content = f"""# Discord Bot Configuration
DISCORD_BOT_TOKEN=your_discord_bot_token_here
DISCORD_GUILD_ID=your_guild_id_here

# MCP Server Configuration
MCP_SERVER_NAME=discord-mcp-server
MCP_SERVER_VERSION=1.0.0
MCP_SERVER_PORT=8000

# API Key Authentication (comma-separated)
API_KEYS={generate_api_key("regular")},{generate_api_key("regular")},{generate_api_key("regular")}
ADMIN_API_KEY={generate_api_key("admin")}

# Logging Configuration
LOG_LEVEL=INFO
LOG_TO_FILE=true
AUDIT_LOG_FILE=logs.md

# Rate Limiting (optional)
RATE_LIMIT_ENABLED=false
RATE_LIMIT_REQUESTS_PER_MINUTE=60

# Security
SECRET_KEY={secrets.token_urlsafe(32)}
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Environment
ENVIRONMENT=development
DEBUG=true
"""
    
    with open('.env', 'w') as f:
        f.write(env_content)
    
    print("✅ Created .env file with generated API keys")
    print("⚠️  Please update DISCORD_BOT_TOKEN with your actual Discord bot token")


def install_dependencies():
    """Install Python dependencies."""
    print("📦 Installing Python dependencies...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], 
                      check=True, capture_output=True, text=True)
        print("✅ Dependencies installed successfully")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False
    return True


def setup_directories():
    """Create necessary directories."""
    directories = ["logs", "tests"]
    for dir_name in directories:
        Path(dir_name).mkdir(exist_ok=True)
    print("✅ Created necessary directories")


def setup_mcp_inspector():
    """Set up MCP Inspector configuration."""
    print("\n🔍 Setting up MCP Inspector...")
    
    # Check if npm is available
    try:
        subprocess.run(["npm", "--version"], check=True, capture_output=True)
        print("✅ npm is available")
        
        # Install MCP Inspector
        try:
            subprocess.run(["npm", "install", "-g", "@modelcontextprotocol/inspector"], 
                          check=True, capture_output=True)
            print("✅ MCP Inspector installed globally")
        except subprocess.CalledProcessError:
            print("⚠️  Failed to install MCP Inspector globally. You may need to run:")
            print("   npm install -g @modelcontextprotocol/inspector")
            
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("⚠️  npm not found. Please install Node.js and npm to use MCP Inspector")
        print("   Visit: https://nodejs.org/")
    
    print("✅ MCP Inspector configuration file already created (mcp_server_config.json)")


def validate_setup():
    """Validate the setup."""
    print("\n🔍 Validating setup...")
    
    # Check if .env file exists
    if not Path('.env').exists():
        print("❌ .env file not found")
        return False
    
    # Check if requirements.txt exists
    if not Path('requirements.txt').exists():
        print("❌ requirements.txt not found")
        return False
    
    # Check if main.py exists
    if not Path('main.py').exists():
        print("❌ main.py not found")
        return False
    
    # Check if app directory exists
    if not Path('app').exists():
        print("❌ app directory not found")
        return False
    
    print("✅ Setup validation passed")
    return True


def print_next_steps():
    """Print next steps for the user."""
    print("\n" + "="*50)
    print("🎉 Discord MCP Server Setup Complete!")
    print("="*50)
    print()
    print("📋 Next Steps:")
    print("1. Edit the .env file and add your Discord bot token:")
    print("   DISCORD_BOT_TOKEN=your_actual_bot_token_here")
    print()
    print("2. Create a Discord bot at https://discord.com/developers/applications")
    print("3. Invite the bot to your Discord server")
    print("4. Run the server:")
    print("   python main.py")
    print()
    print("5. (Optional) Use MCP Inspector for debugging:")
    print("   mcp-inspector")
    print("   Then open http://localhost:3000")
    print()
    print("📖 For detailed instructions, see README.md")
    print("🐛 For issues, check the troubleshooting section in README.md")
    print()
    print("API Keys generated (also in .env file):")
    
    # Read and display API keys
    if Path('.env').exists():
        with open('.env', 'r') as f:
            content = f.read()
            for line in content.split('\n'):
                if line.startswith('API_KEYS='):
                    print(f"  Regular API Keys: {line.split('=')[1]}")
                elif line.startswith('ADMIN_API_KEY='):
                    print(f"  Admin API Key: {line.split('=')[1]}")


def main():
    """Main setup function."""
    print("🚀 Discord MCP Server Setup")
    print("="*50)
    
    # Check if already set up
    if Path('.env').exists():
        response = input("⚠️  .env file already exists. Overwrite? (y/N): ").lower()
        if response != 'y':
            print("Setup cancelled.")
            return
    
    # Create directories
    setup_directories()
    
    # Install dependencies
    if not install_dependencies():
        print("❌ Setup failed at dependency installation")
        return
    
    # Create .env file
    create_env_file()
    
    # Set up MCP Inspector
    setup_mcp_inspector()
    
    # Validate setup
    if not validate_setup():
        print("❌ Setup validation failed")
        return
    
    # Print next steps
    print_next_steps()


if __name__ == "__main__":
    main() 
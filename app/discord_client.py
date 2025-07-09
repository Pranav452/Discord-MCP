"""
Discord Client module for the MCP Server.

This module provides Discord API integration using discord.py,
implementing all required Discord operations for the MCP server.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timezone, timedelta
import re

import discord
from discord.ext import commands
import structlog

logger = structlog.get_logger(__name__)


class DiscordClient:
    """
    Discord client that handles all Discord API operations.
    
    This class provides methods for sending messages, retrieving message history,
    getting channel information, searching messages, and moderating content.
    """

    def __init__(self, bot_token: str):
        """Initialize the Discord client."""
        self.bot_token = bot_token
        self.client = None
        self._ready = False
        
        # Configure Discord client with intents
        intents = discord.Intents.default()
        intents.message_content = True
        intents.guilds = True
        intents.members = True
        
        # Create Discord client
        self.client = discord.Client(intents=intents)
        
        # Set up event handlers
        self._setup_event_handlers()

    def _setup_event_handlers(self):
        """Set up Discord client event handlers."""
        
        @self.client.event
        async def on_ready():
            """Handle client ready event."""
            logger.info(
                "Discord client ready",
                user=self.client.user.name,
                guild_count=len(self.client.guilds)
            )
            self._ready = True
            
        @self.client.event
        async def on_error(event, *args, **kwargs):
            """Handle Discord client errors."""
            logger.error("Discord client error", event=event, args=args, kwargs=kwargs)

    async def initialize(self):
        """Initialize the Discord client connection."""
        if not self.client:
            raise ValueError("Discord client not configured")
        
        logger.info("Initializing Discord client")
        
        # Start the client in a background task
        asyncio.create_task(self.client.start(self.bot_token))
        
        # Wait for client to be ready
        timeout = 30
        while not self._ready and timeout > 0:
            await asyncio.sleep(1)
            timeout -= 1
        
        if not self._ready:
            raise ConnectionError("Discord client failed to initialize within timeout")
        
        logger.info("Discord client initialized successfully")

    async def send_message(self, channel_id: str, content: str) -> discord.Message:
        """
        Send a message to a Discord channel.
        
        Args:
            channel_id: Discord channel ID
            content: Message content to send
            
        Returns:
            Discord message object
        """
        if not self._ready:
            raise ConnectionError("Discord client not ready")
        
        try:
            channel = self.client.get_channel(int(channel_id))
            if not channel:
                raise ValueError(f"Channel {channel_id} not found")
            
            message = await channel.send(content)
            
            logger.info(
                "Message sent",
                channel_id=channel_id,
                message_id=message.id,
                content_length=len(content)
            )
            
            return message
            
        except discord.Forbidden:
            raise PermissionError(f"No permission to send messages in channel {channel_id}")
        except discord.HTTPException as e:
            raise RuntimeError(f"Failed to send message: {str(e)}")

    async def get_messages(
        self, 
        channel_id: str, 
        limit: int = 10, 
        before: Optional[str] = None,
        after: Optional[str] = None
    ) -> List[discord.Message]:
        """
        Retrieve message history from a Discord channel.
        
        Args:
            channel_id: Discord channel ID
            limit: Maximum number of messages to retrieve
            before: Message ID to get messages before
            after: Message ID to get messages after
            
        Returns:
            List of Discord message objects
        """
        if not self._ready:
            raise ConnectionError("Discord client not ready")
        
        try:
            channel = self.client.get_channel(int(channel_id))
            if not channel:
                raise ValueError(f"Channel {channel_id} not found")
            
            # Convert string IDs to discord.Object if provided
            before_obj = discord.Object(id=int(before)) if before else None
            after_obj = discord.Object(id=int(after)) if after else None
            
            messages = []
            async for message in channel.history(
                limit=limit, 
                before=before_obj, 
                after=after_obj
            ):
                messages.append(message)
            
            logger.info(
                "Messages retrieved",
                channel_id=channel_id,
                count=len(messages),
                limit=limit
            )
            
            return messages
            
        except discord.Forbidden:
            raise PermissionError(f"No permission to read messages in channel {channel_id}")
        except discord.HTTPException as e:
            raise RuntimeError(f"Failed to retrieve messages: {str(e)}")

    async def get_channel_info(self, channel_id: str) -> Dict[str, Any]:
        """
        Get information about a Discord channel.
        
        Args:
            channel_id: Discord channel ID
            
        Returns:
            Dictionary containing channel information
        """
        if not self._ready:
            raise ConnectionError("Discord client not ready")
        
        try:
            channel = self.client.get_channel(int(channel_id))
            if not channel:
                raise ValueError(f"Channel {channel_id} not found")
            
            channel_info = {
                "id": str(channel.id),
                "name": channel.name,
                "type": str(channel.type),
                "guild_id": str(channel.guild.id) if channel.guild else None,
                "guild_name": channel.guild.name if channel.guild else None,
                "created_at": channel.created_at.isoformat(),
                "nsfw": getattr(channel, 'nsfw', False),
                "category": channel.category.name if getattr(channel, 'category', None) else None,
                "position": getattr(channel, 'position', None),
                "topic": getattr(channel, 'topic', None),
                "member_count": len(channel.members) if hasattr(channel, 'members') else None
            }
            
            logger.info("Channel info retrieved", channel_id=channel_id, name=channel.name)
            
            return channel_info
            
        except discord.Forbidden:
            raise PermissionError(f"No permission to access channel {channel_id}")
        except discord.HTTPException as e:
            raise RuntimeError(f"Failed to get channel info: {str(e)}")

    async def search_messages(
        self, 
        channel_id: str, 
        query: str, 
        limit: int = 10,
        author_id: Optional[str] = None
    ) -> List[discord.Message]:
        """
        Search for messages in a Discord channel.
        
        Args:
            channel_id: Discord channel ID
            query: Search query
            limit: Maximum number of results
            author_id: Filter by author ID (optional)
            
        Returns:
            List of Discord message objects matching the search
        """
        if not self._ready:
            raise ConnectionError("Discord client not ready")
        
        try:
            channel = self.client.get_channel(int(channel_id))
            if not channel:
                raise ValueError(f"Channel {channel_id} not found")
            
            # Simple text search implementation
            matching_messages = []
            search_limit = min(limit * 10, 1000)  # Search more messages to find matches
            
            async for message in channel.history(limit=search_limit):
                # Check author filter
                if author_id and str(message.author.id) != author_id:
                    continue
                
                # Check if message content contains query (case-insensitive)
                if query.lower() in message.content.lower():
                    matching_messages.append(message)
                    
                    # Stop when we have enough matches
                    if len(matching_messages) >= limit:
                        break
            
            logger.info(
                "Messages searched",
                channel_id=channel_id,
                query=query,
                matches=len(matching_messages),
                limit=limit
            )
            
            return matching_messages
            
        except discord.Forbidden:
            raise PermissionError(f"No permission to search messages in channel {channel_id}")
        except discord.HTTPException as e:
            raise RuntimeError(f"Failed to search messages: {str(e)}")

    async def moderate_content(
        self,
        action: str,
        channel_id: str,
        message_id: Optional[str] = None,
        user_id: Optional[str] = None,
        reason: str = "No reason provided",
        duration: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Moderate content in a Discord channel.
        
        Args:
            action: Moderation action to perform
            channel_id: Discord channel ID
            message_id: Message ID (for delete_message)
            user_id: User ID (for user actions)
            reason: Reason for moderation action
            duration: Duration in seconds (for timeout_user)
            
        Returns:
            Dictionary containing moderation result
        """
        if not self._ready:
            raise ConnectionError("Discord client not ready")
        
        try:
            channel = self.client.get_channel(int(channel_id))
            if not channel:
                raise ValueError(f"Channel {channel_id} not found")
            
            guild = channel.guild
            if not guild:
                raise ValueError("Channel is not in a guild")
            
            result = {"action": action, "success": False}
            
            if action == "delete_message":
                if not message_id:
                    raise ValueError("Message ID is required for delete_message action")
                
                message = await channel.fetch_message(int(message_id))
                await message.delete()
                result.update({
                    "success": True,
                    "message_id": message_id,
                    "deleted_at": datetime.now(timezone.utc).isoformat()
                })
                
            elif action == "kick_user":
                if not user_id:
                    raise ValueError("User ID is required for kick_user action")
                
                member = guild.get_member(int(user_id))
                if not member:
                    raise ValueError(f"User {user_id} not found in guild")
                
                await member.kick(reason=reason)
                result.update({
                    "success": True,
                    "user_id": user_id,
                    "reason": reason,
                    "kicked_at": datetime.now(timezone.utc).isoformat()
                })
                
            elif action == "ban_user":
                if not user_id:
                    raise ValueError("User ID is required for ban_user action")
                
                member = guild.get_member(int(user_id))
                if not member:
                    # Try to ban by user ID even if not in guild
                    user = await self.client.fetch_user(int(user_id))
                    await guild.ban(user, reason=reason)
                else:
                    await member.ban(reason=reason)
                
                result.update({
                    "success": True,
                    "user_id": user_id,
                    "reason": reason,
                    "banned_at": datetime.now(timezone.utc).isoformat()
                })
                
            elif action == "timeout_user":
                if not user_id:
                    raise ValueError("User ID is required for timeout_user action")
                if not duration:
                    raise ValueError("Duration is required for timeout_user action")
                
                member = guild.get_member(int(user_id))
                if not member:
                    raise ValueError(f"User {user_id} not found in guild")
                
                timeout_until = datetime.now(timezone.utc) + timedelta(seconds=duration)
                await member.timeout(timeout_until, reason=reason)
                
                result.update({
                    "success": True,
                    "user_id": user_id,
                    "reason": reason,
                    "duration": duration,
                    "timeout_until": timeout_until.isoformat(),
                    "timed_out_at": datetime.now(timezone.utc).isoformat()
                })
                
            else:
                raise ValueError(f"Unknown moderation action: {action}")
            
            logger.info(
                "Moderation action performed",
                action=action,
                channel_id=channel_id,
                user_id=user_id,
                message_id=message_id,
                reason=reason
            )
            
            return result
            
        except discord.Forbidden:
            raise PermissionError(f"No permission to perform {action} in channel {channel_id}")
        except discord.HTTPException as e:
            raise RuntimeError(f"Failed to perform moderation action: {str(e)}")

    async def close(self):
        """Close the Discord client connection."""
        if self.client and not self.client.is_closed():
            await self.client.close()
            logger.info("Discord client closed")

    def is_ready(self) -> bool:
        """Check if the Discord client is ready."""
        return self._ready and self.client and not self.client.is_closed() 
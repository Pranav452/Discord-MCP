"""
Discord MCP Server Implementation

This module implements a basic Model Context Protocol (MCP) server that provides
Discord integration capabilities to AI models.
"""

import asyncio
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional, Union
from datetime import datetime
import uuid

import structlog
from .discord_client import DiscordClient
from .auth import AuthManager
from .audit_logger import AuditLogger
from .config import Config

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)


class SimpleMCPServer:
    """
    Simple MCP Server implementation for Discord integration.
    
    This server implements basic MCP protocol functionality
    without relying on external MCP packages.
    """

    def __init__(self, config: Config):
        """Initialize the Discord MCP Server."""
        self.config = config
        self.discord_client = DiscordClient(config.discord_bot_token)
        
        # Initialize AuthManager with proper handling of bypassed authentication
        if config.dangerously_omit_auth:
            # Provide minimal auth setup when authentication is bypassed
            self.auth_manager = AuthManager([], "")
        else:
            self.auth_manager = AuthManager(config.api_keys, config.admin_api_key)
        
        self.audit_logger = AuditLogger(config.audit_log_file)
        self.tools = self._get_available_tools()

    def _get_available_tools(self) -> List[Dict[str, Any]]:
        """Get list of available Discord tools."""
        return [
            {
                "name": "send_message",
                "description": "Send a message to a Discord channel",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "channel_id": {
                            "type": "string",
                            "description": "Discord channel ID"
                        },
                        "content": {
                            "type": "string",
                            "description": "Message content to send"
                        }
                    },
                    "required": ["channel_id", "content"]
                }
            },
            {
                "name": "get_messages",
                "description": "Retrieve message history from a Discord channel",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "channel_id": {
                            "type": "string",
                            "description": "Discord channel ID"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Number of messages to retrieve (default: 10)",
                            "default": 10
                        },
                        "before": {
                            "type": "string",
                            "description": "Message ID to get messages before"
                        },
                        "after": {
                            "type": "string",
                            "description": "Message ID to get messages after"
                        }
                    },
                    "required": ["channel_id"]
                }
            },
            {
                "name": "get_channel_info",
                "description": "Get information about a Discord channel",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "channel_id": {
                            "type": "string",
                            "description": "Discord channel ID"
                        }
                    },
                    "required": ["channel_id"]
                }
            },
            {
                "name": "search_messages",
                "description": "Search for messages in a Discord channel",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "channel_id": {
                            "type": "string",
                            "description": "Discord channel ID"
                        },
                        "query": {
                            "type": "string",
                            "description": "Search query"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of results (default: 10)",
                            "default": 10
                        },
                        "author_id": {
                            "type": "string",
                            "description": "Filter by author ID (optional)"
                        }
                    },
                    "required": ["channel_id", "query"]
                }
            },
            {
                "name": "moderate_content",
                "description": "Moderate content in a Discord channel",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["delete_message", "kick_user", "ban_user", "timeout_user"],
                            "description": "Moderation action to perform"
                        },
                        "channel_id": {
                            "type": "string",
                            "description": "Discord channel ID"
                        },
                        "message_id": {
                            "type": "string",
                            "description": "Message ID (for delete_message)"
                        },
                        "user_id": {
                            "type": "string",
                            "description": "User ID (for user actions)"
                        },
                        "reason": {
                            "type": "string",
                            "description": "Reason for moderation action"
                        },
                        "duration": {
                            "type": "integer",
                            "description": "Duration in seconds (for timeout_user)"
                        }
                    },
                    "required": ["action", "channel_id"]
                }
            }
        ]

    async def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle incoming MCP requests."""
        method = request.get("method", "")
        params = request.get("params", {})
        request_id = request.get("id", str(uuid.uuid4()))

        logger.info("Handling MCP request", method=method, request_id=request_id)

        try:
            if method == "initialize":
                # Handle MCP initialization
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "tools": {}
                        },
                        "serverInfo": {
                            "name": self.config.mcp_server_name,
                            "version": self.config.mcp_server_version
                        }
                    }
                }
            
            elif method == "notifications/initialized":
                # Handle initialization complete notification
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {}
                }
            
            elif method == "tools/list":
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "tools": self.tools
                    }
                }
            
            elif method == "tools/call":
                tool_name = params.get("name")
                arguments = params.get("arguments", {})
                
                result = await self.call_tool(tool_name, arguments)
                
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": result
                }
            
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: {method}"
                    }
                }
        
        except Exception as e:
            logger.error("Error handling request", error=str(e), request_id=request_id)
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32603,
                    "message": f"Internal error: {str(e)}"
                }
            }

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call a Discord tool."""
        request_id = str(uuid.uuid4())
        
        # Log the incoming request
        await self.audit_logger.log_request(
            request_id=request_id,
            method="call_tool",
            tool_name=tool_name,
            arguments=arguments,
            timestamp=datetime.utcnow()
        )
        
        start_time = datetime.utcnow()
        
        try:
            # Authenticate the request
            session_token = arguments.get("session_token")
            
            # Check if authentication is disabled for testing
            if self.config.dangerously_omit_auth:
                logger.info("Authentication bypassed - DANGEROUSLY_OMIT_AUTH is enabled")
                # Remove session token from arguments before processing
                clean_arguments = {k: v for k, v in arguments.items() if k != "session_token"}
            else:
                if not session_token:
                    raise ValueError("Session token is required")
                
                auth_result = await self.auth_manager.authenticate(session_token)
                if not auth_result.is_valid:
                    raise ValueError("Invalid session token")
                
                # Remove session token from arguments before processing
                clean_arguments = {k: v for k, v in arguments.items() if k != "session_token"}
            
            # Route to appropriate handler
            if tool_name == "send_message":
                result = await self._handle_send_message(clean_arguments)
            elif tool_name == "get_messages":
                result = await self._handle_get_messages(clean_arguments)
            elif tool_name == "get_channel_info":
                result = await self._handle_get_channel_info(clean_arguments)
            elif tool_name == "search_messages":
                result = await self._handle_search_messages(clean_arguments)
            elif tool_name == "moderate_content":
                result = await self._handle_moderate_content(clean_arguments)
            else:
                raise ValueError(f"Unknown tool: {tool_name}")
            
            # Calculate processing time
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            
            # Log successful response
            await self.audit_logger.log_response(
                request_id=request_id,
                status="success",
                result=result,
                processing_time=processing_time,
                timestamp=datetime.utcnow()
            )
            
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(result, indent=2)
                    }
                ]
            }
            
        except Exception as e:
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            logger.error("Tool call failed", tool=tool_name, error=str(e), request_id=request_id)
            
            # Log error response
            await self.audit_logger.log_response(
                request_id=request_id,
                status="error",
                error=str(e),
                processing_time=processing_time,
                timestamp=datetime.utcnow()
            )
            
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"Error: {str(e)}"
                    }
                ]
            }

    async def _handle_send_message(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle send_message tool."""
        channel_id = arguments["channel_id"]
        content = arguments["content"]
        
        message = await self.discord_client.send_message(channel_id, content)
        
        return {
            "success": True,
            "message_id": str(message.id),
            "channel_id": str(message.channel.id),
            "content": message.content,
            "timestamp": message.created_at.isoformat()
        }

    async def _handle_get_messages(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle get_messages tool."""
        channel_id = arguments["channel_id"]
        limit = arguments.get("limit", 10)
        before = arguments.get("before")
        after = arguments.get("after")
        
        messages = await self.discord_client.get_messages(
            channel_id, limit=limit, before=before, after=after
        )
        
        return {
            "success": True,
            "messages": [
                {
                    "id": str(msg.id),
                    "content": msg.content,
                    "author": {
                        "id": str(msg.author.id),
                        "name": msg.author.name,
                        "display_name": msg.author.display_name
                    },
                    "timestamp": msg.created_at.isoformat(),
                    "edited_timestamp": msg.edited_at.isoformat() if msg.edited_at else None
                }
                for msg in messages
            ]
        }

    async def _handle_get_channel_info(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle get_channel_info tool."""
        channel_id = arguments["channel_id"]
        
        channel_info = await self.discord_client.get_channel_info(channel_id)
        
        return {
            "success": True,
            "channel": channel_info
        }

    async def _handle_search_messages(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle search_messages tool."""
        channel_id = arguments["channel_id"]
        query = arguments["query"]
        limit = arguments.get("limit", 10)
        author_id = arguments.get("author_id")
        
        messages = await self.discord_client.search_messages(
            channel_id, query, limit=limit, author_id=author_id
        )
        
        return {
            "success": True,
            "messages": [
                {
                    "id": str(msg.id),
                    "content": msg.content,
                    "author": {
                        "id": str(msg.author.id),
                        "name": msg.author.name,
                        "display_name": msg.author.display_name
                    },
                    "timestamp": msg.created_at.isoformat(),
                    "relevance_score": getattr(msg, 'relevance_score', 1.0)
                }
                for msg in messages
            ]
        }

    async def _handle_moderate_content(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle moderate_content tool."""
        action = arguments["action"]
        channel_id = arguments["channel_id"]
        message_id = arguments.get("message_id")
        user_id = arguments.get("user_id")
        reason = arguments.get("reason", "No reason provided")
        duration = arguments.get("duration")
        
        result = await self.discord_client.moderate_content(
            action=action,
            channel_id=channel_id,
            message_id=message_id,
            user_id=user_id,
            reason=reason,
            duration=duration
        )
        
        return {
            "success": True,
            "action": action,
            "result": result
        }

    async def run_http_server(self):
        """Run HTTP server for MCP Inspector integration with proper authentication and CORS."""
        from http.server import HTTPServer, BaseHTTPRequestHandler
        import threading
        import urllib.parse
        
        # Store reference to MCP server and main event loop
        mcp_server_ref = self
        main_loop = asyncio.get_event_loop()
        
        class MCPHandler(BaseHTTPRequestHandler):
            def _set_cors_headers(self):
                """Set CORS headers for MCP Inspector compatibility."""
                # Allow requests from Inspector origins
                inspector_origins = [
                    "http://127.0.0.1:6274",
                    "http://localhost:6274",
                    "http://127.0.0.1:6275",
                    "http://localhost:6275"
                ]
                
                origin = self.headers.get('Origin')
                if origin in inspector_origins:
                    self.send_header('Access-Control-Allow-Origin', origin)
                else:
                    self.send_header('Access-Control-Allow-Origin', '*')
                
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
                self.send_header('Access-Control-Allow-Credentials', 'true')
                self.send_header('Access-Control-Max-Age', '86400')
            
            def _extract_session_token(self):
                """Extract session token from Authorization header or query params."""
                # Check Authorization header first
                auth_header = self.headers.get('Authorization', '')
                if auth_header.startswith('Bearer '):
                    return auth_header[7:]  # Remove 'Bearer ' prefix
                
                # Check query parameters
                parsed_url = urllib.parse.urlparse(self.path)
                query_params = urllib.parse.parse_qs(parsed_url.query)
                if 'token' in query_params:
                    return query_params['token'][0]
                
                return None
            
            def _authenticate_request(self):
                """Authenticate request using session token."""
                # Check if authentication is disabled for testing
                if mcp_server_ref.config.dangerously_omit_auth:
                    return True, "auth_disabled"
                
                session_token = self._extract_session_token()
                if not session_token:
                    return False, "No session token provided"
                
                # For MCP Inspector, we'll use a simple token validation
                # In production, you'd want more sophisticated token validation
                if len(session_token) >= 32:  # Basic length check
                    return True, session_token
                
                return False, "Invalid session token"
            
            def do_GET(self):
                """Handle GET requests including SSE and OAuth metadata."""
                try:
                    parsed_url = urllib.parse.urlparse(self.path)
                    path = parsed_url.path
                    
                    if path == '/':
                        # Handle root endpoint - return server info
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/json')
                        self._set_cors_headers()
                        self.end_headers()
                        
                        info = {
                            "name": "Discord MCP Server",
                            "version": "1.0.0",
                            "transport": "http",
                            "capabilities": {
                                "tools": {},
                                "resources": {}
                            },
                            "endpoints": {
                                "http": f"http://localhost:{mcp_server_ref.config.mcp_server_port}/",
                                "sse": f"http://localhost:{mcp_server_ref.config.mcp_server_port}/sse"
                            }
                        }
                        self.wfile.write(json.dumps(info).encode('utf-8'))
                    
                    elif path.startswith('/sse'):
                        # Handle SSE endpoint
                        auth_valid, token_or_error = self._authenticate_request()
                        if not auth_valid:
                            self.send_response(401)
                            self.send_header('Content-Type', 'application/json')
                            self._set_cors_headers()
                            self.end_headers()
                            self.wfile.write(json.dumps({"error": token_or_error}).encode('utf-8'))
                            return
                        
                        self.send_response(200)
                        self.send_header('Content-Type', 'text/event-stream')
                        self.send_header('Cache-Control', 'no-cache')
                        self.send_header('Connection', 'keep-alive')
                        self._set_cors_headers()
                        self.end_headers()
                        
                        # Send initial connection message
                        self.wfile.write(b'data: {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}\n\n')
                        self.wfile.flush()
                        
                        # Keep connection alive
                        try:
                            while True:
                                import time
                                time.sleep(30)  # Send keepalive every 30 seconds
                                self.wfile.write(b'data: {"jsonrpc": "2.0", "method": "ping"}\n\n')
                                self.wfile.flush()
                        except Exception:
                            pass
                    
                    elif path == '/.well-known/oauth-authorization-server':
                        # OAuth metadata endpoint (for Inspector compatibility)
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/json')
                        self._set_cors_headers()
                        self.end_headers()
                        
                        # Return minimal OAuth metadata to satisfy Inspector
                        oauth_metadata = {
                            "issuer": f"http://localhost:{mcp_server_ref.config.mcp_server_port}",
                            "authorization_endpoint": f"http://localhost:{mcp_server_ref.config.mcp_server_port}/auth",
                            "token_endpoint": f"http://localhost:{mcp_server_ref.config.mcp_server_port}/token",
                            "response_types_supported": ["code"],
                            "grant_types_supported": ["authorization_code"],
                            "code_challenge_methods_supported": ["S256"]
                        }
                        self.wfile.write(json.dumps(oauth_metadata).encode('utf-8'))
                    
                    else:
                        # Handle 404 for unknown paths
                        self.send_response(404)
                        self.send_header('Content-Type', 'application/json')
                        self._set_cors_headers()
                        self.end_headers()
                        self.wfile.write(json.dumps({"error": "Not found"}).encode('utf-8'))
                        
                except Exception as e:
                    logger.error(f"Error handling GET request: {e}")
                    self.send_response(500)
                    self.send_header('Content-Type', 'application/json')
                    self._set_cors_headers()
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": f"Internal server error: {str(e)}"}).encode('utf-8'))
            
            def do_POST(self):
                """Handle POST requests with proper authentication and error handling."""
                try:
                    content_length = int(self.headers.get('Content-Length', 0))
                    if content_length == 0:
                        self.send_response(400)
                        self.send_header('Content-Type', 'application/json')
                        self._set_cors_headers()
                        self.end_headers()
                        self.wfile.write(json.dumps({"error": "Empty request body"}).encode('utf-8'))
                        return
                    
                    post_data = self.rfile.read(content_length)
                    
                    # Parse JSON request
                    try:
                        request = json.loads(post_data.decode('utf-8'))
                    except json.JSONDecodeError as e:
                        self.send_response(400)
                        self.send_header('Content-Type', 'application/json')
                        self._set_cors_headers()
                        self.end_headers()
                        error_response = {
                            "jsonrpc": "2.0",
                            "id": None,
                            "error": {
                                "code": -32700,
                                "message": f"Parse error: {str(e)}"
                            }
                        }
                        self.wfile.write(json.dumps(error_response).encode('utf-8'))
                        return
                    
                    # For tool calls, authenticate using session token instead of API key
                    method = request.get("method", "")
                    if method == "tools/call":
                        auth_valid, token_or_error = self._authenticate_request()
                        if not auth_valid:
                            self.send_response(401)
                            self.send_header('Content-Type', 'application/json')
                            self._set_cors_headers()
                            self.end_headers()
                            error_response = {
                                "jsonrpc": "2.0",
                                "id": request.get("id"),
                                "error": {
                                    "code": -32001,
                                    "message": f"Authentication failed: {token_or_error}"
                                }
                            }
                            self.wfile.write(json.dumps(error_response).encode('utf-8'))
                            return
                        
                        # Add session token to request params for internal processing
                        if "params" not in request:
                            request["params"] = {}
                        if "arguments" not in request["params"]:
                            request["params"]["arguments"] = {}
                        request["params"]["arguments"]["session_token"] = token_or_error
                    
                    # Handle the request asynchronously using the main event loop
                    future = asyncio.run_coroutine_threadsafe(
                        mcp_server_ref.handle_request(request), 
                        main_loop
                    )
                    
                    # Wait for the result with a timeout
                    try:
                        response = future.result(timeout=30)  # 30 second timeout
                    except asyncio.TimeoutError:
                        self.send_response(408)
                        self.send_header('Content-Type', 'application/json')
                        self._set_cors_headers()
                        self.end_headers()
                        error_response = {
                            "jsonrpc": "2.0",
                            "id": request.get("id"),
                            "error": {
                                "code": -32603,
                                "message": "Request timeout"
                            }
                        }
                        self.wfile.write(json.dumps(error_response).encode('utf-8'))
                        return
                    
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self._set_cors_headers()
                    self.end_headers()
                    
                    self.wfile.write(json.dumps(response).encode('utf-8'))
                    
                except Exception as e:
                    logger.error(f"Error handling POST request: {e}")
                    self.send_response(500)
                    self.send_header('Content-Type', 'application/json')
                    self._set_cors_headers()
                    self.end_headers()
                    
                    error_response = {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {
                            "code": -32603,
                            "message": f"Internal error: {str(e)}"
                        }
                    }
                    self.wfile.write(json.dumps(error_response).encode('utf-8'))
            
            def do_OPTIONS(self):
                """Handle OPTIONS requests for CORS preflight."""
                self.send_response(200)
                self._set_cors_headers()
                self.end_headers()
            
            def log_message(self, format, *args):
                """Override to use structured logging."""
                logger.info(f"HTTP {format % args}")
        
        # Start HTTP server in a separate thread
        server = HTTPServer(('localhost', self.config.mcp_server_port), MCPHandler)
        
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        
        logger.info(f"MCP HTTP server started on http://localhost:{self.config.mcp_server_port}")
        logger.info(f"SSE endpoint available at http://localhost:{self.config.mcp_server_port}/sse")
        logger.info(f"OAuth metadata endpoint: http://localhost:{self.config.mcp_server_port}/.well-known/oauth-authorization-server")
        return server

    async def run(self):
        """Run the MCP server."""
        logger.info("Starting Discord MCP Server", version=self.config.mcp_server_version)
        
        # Initialize Discord client
        await self.discord_client.initialize()
        
        # Start HTTP server for MCP Inspector
        http_server = await self.run_http_server()
        
        logger.info("Discord MCP Server is running...")
        logger.info(f"HTTP Server: http://localhost:{self.config.mcp_server_port}")
        logger.info("Press Ctrl+C to stop")
        
        try:
            # Keep the server running
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            await self.discord_client.close()


async def main():
    """Main entry point for the Discord MCP Server."""
    config = Config()
    server = SimpleMCPServer(config)
    await server.run()


if __name__ == "__main__":
    asyncio.run(main()) 
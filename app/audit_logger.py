"""
Audit Logger module for Discord MCP Server.

This module provides audit logging capabilities, storing all API requests
and responses in markdown format for easy review and debugging.
"""

import json
import os
import asyncio
from datetime import datetime
from typing import Any, Dict, Optional, List
from dataclasses import dataclass, asdict
from pathlib import Path
import structlog
import aiofiles

logger = structlog.get_logger(__name__)


@dataclass
class AuditLogEntry:
    """Single audit log entry."""
    
    timestamp: datetime
    request_id: str
    method: str
    status: str
    tool_name: Optional[str] = None
    arguments: Optional[Dict[str, Any]] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    processing_time: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data


class AuditLogger:
    """
    Audit logger that stores all API operations in markdown format.
    
    This class provides methods for logging requests, responses, and errors
    in a structured markdown format for easy review.
    """

    def __init__(self, log_file: str = "logs.md"):
        """
        Initialize the audit logger.
        
        Args:
            log_file: Path to the markdown log file
        """
        self.log_file = Path(log_file)
        self.log_entries: List[AuditLogEntry] = []
        self._lock = asyncio.Lock()
        self._ensure_log_file()

    def _ensure_log_file(self):
        """Ensure the log file exists and has proper headers."""
        if not self.log_file.exists():
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            self._write_header()

    def _write_header(self):
        """Write the markdown header to the log file."""
        header = f"""# Discord MCP Server Audit Log

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

This file contains audit logs for all API operations performed by the Discord MCP Server.

## Log Format

Each entry contains:
- **Timestamp**: When the operation occurred
- **Request ID**: Unique identifier for the request
- **Method**: API method called
- **Tool**: Discord tool used (if applicable)
- **Status**: Success or error status
- **Arguments**: Input parameters
- **Result**: Output or error message
- **Processing Time**: Time taken to process the request

---

"""
        try:
            with open(self.log_file, 'w', encoding='utf-8') as f:
                f.write(header)
        except Exception as e:
            logger.error("Failed to write log header", error=str(e))

    async def log_request(
        self,
        request_id: str,
        method: str,
        tool_name: Optional[str] = None,
        arguments: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None
    ):
        """
        Log an incoming request.
        
        Args:
            request_id: Unique identifier for the request
            method: API method being called
            tool_name: Name of the Discord tool (if applicable)
            arguments: Request arguments
            timestamp: Request timestamp (defaults to now)
        """
        if timestamp is None:
            timestamp = datetime.now()

        entry = AuditLogEntry(
            timestamp=timestamp,
            request_id=request_id,
            method=method,
            tool_name=tool_name,
            arguments=arguments,
            status="processing"
        )

        async with self._lock:
            self.log_entries.append(entry)
            await self._write_entry(entry, is_request=True)

        logger.info(
            "Request logged",
            request_id=request_id,
            method=method,
            tool_name=tool_name
        )

    async def log_response(
        self,
        request_id: str,
        status: str,
        result: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
        processing_time: Optional[float] = None,
        timestamp: Optional[datetime] = None
    ):
        """
        Log a response for a request.
        
        Args:
            request_id: Unique identifier for the request
            status: Response status (success/error)
            result: Response result (if successful)
            error: Error message (if failed)
            processing_time: Time taken to process the request
            timestamp: Response timestamp (defaults to now)
        """
        if timestamp is None:
            timestamp = datetime.now()

        async with self._lock:
            # Find the matching request entry
            entry = None
            for log_entry in self.log_entries:
                if log_entry.request_id == request_id:
                    entry = log_entry
                    break

            if entry:
                # Update existing entry
                entry.status = status
                entry.result = result
                entry.error = error
                entry.processing_time = processing_time
            else:
                # Create new entry for orphaned response
                entry = AuditLogEntry(
                    timestamp=timestamp,
                    request_id=request_id,
                    method="unknown",
                    status=status,
                    result=result,
                    error=error,
                    processing_time=processing_time
                )
                self.log_entries.append(entry)

            await self._write_entry(entry, is_request=False)

        logger.info(
            "Response logged",
            request_id=request_id,
            status=status,
            processing_time=processing_time
        )

    async def _write_entry(self, entry: AuditLogEntry, is_request: bool = False):
        """
        Write a log entry to the markdown file.
        
        Args:
            entry: Log entry to write
            is_request: Whether this is a request (True) or response (False)
        """
        try:
            async with aiofiles.open(self.log_file, 'a', encoding='utf-8') as f:
                if is_request:
                    await f.write(self._format_request_entry(entry))
                else:
                    await f.write(self._format_response_entry(entry))
        except Exception as e:
            logger.error("Failed to write log entry", error=str(e), request_id=entry.request_id)

    def _format_request_entry(self, entry: AuditLogEntry) -> str:
        """Format a request entry as markdown."""
        md = f"""
## Request: {entry.request_id}

**Timestamp**: {entry.timestamp.strftime('%Y-%m-%d %H:%M:%S')}  
**Method**: `{entry.method}`  
**Tool**: `{entry.tool_name or 'N/A'}`  
**Status**: `{entry.status}`  

"""
        
        if entry.arguments:
            md += "**Arguments**:\n```json\n"
            md += json.dumps(entry.arguments, indent=2, default=str)
            md += "\n```\n\n"
        
        return md

    def _format_response_entry(self, entry: AuditLogEntry) -> str:
        """Format a response entry as markdown."""
        md = f"""**Final Status**: `{entry.status}`  
"""
        
        if entry.processing_time:
            md += f"**Processing Time**: {entry.processing_time:.3f}s  \n"
        
        if entry.result:
            md += "**Result**:\n```json\n"
            md += json.dumps(entry.result, indent=2, default=str)
            md += "\n```\n\n"
        
        if entry.error:
            md += f"**Error**: `{entry.error}`\n\n"
        
        md += "---\n\n"
        
        return md

    async def get_recent_logs(self, count: int = 10) -> List[AuditLogEntry]:
        """
        Get recent log entries.
        
        Args:
            count: Number of recent entries to return
            
        Returns:
            List of recent audit log entries
        """
        async with self._lock:
            return self.log_entries[-count:] if self.log_entries else []

    async def get_logs_by_request_id(self, request_id: str) -> Optional[AuditLogEntry]:
        """
        Get log entry by request ID.
        
        Args:
            request_id: Request ID to search for
            
        Returns:
            Matching log entry or None
        """
        async with self._lock:
            for entry in self.log_entries:
                if entry.request_id == request_id:
                    return entry
            return None

    async def get_error_logs(self, count: int = 10) -> List[AuditLogEntry]:
        """
        Get recent error log entries.
        
        Args:
            count: Number of error entries to return
            
        Returns:
            List of error audit log entries
        """
        async with self._lock:
            error_entries = [entry for entry in self.log_entries if entry.status == "error"]
            return error_entries[-count:] if error_entries else []

    async def get_stats(self) -> Dict[str, Any]:
        """
        Get audit log statistics.
        
        Returns:
            Dictionary containing log statistics
        """
        async with self._lock:
            total_entries = len(self.log_entries)
            success_count = sum(1 for entry in self.log_entries if entry.status == "success")
            error_count = sum(1 for entry in self.log_entries if entry.status == "error")
            
            # Calculate average processing time
            processing_times = [
                entry.processing_time for entry in self.log_entries 
                if entry.processing_time is not None
            ]
            avg_processing_time = sum(processing_times) / len(processing_times) if processing_times else 0
            
            # Get tool usage statistics
            tool_usage = {}
            for entry in self.log_entries:
                if entry.tool_name:
                    tool_usage[entry.tool_name] = tool_usage.get(entry.tool_name, 0) + 1
            
            return {
                "total_entries": total_entries,
                "success_count": success_count,
                "error_count": error_count,
                "success_rate": success_count / total_entries if total_entries > 0 else 0,
                "average_processing_time": avg_processing_time,
                "tool_usage": tool_usage
            }

    async def clear_logs(self):
        """Clear all log entries and reset the log file."""
        async with self._lock:
            self.log_entries.clear()
            self._write_header()
        
        logger.info("Audit logs cleared")

    async def export_logs(self, format: str = "json") -> str:
        """
        Export logs in specified format.
        
        Args:
            format: Export format ('json' or 'csv')
            
        Returns:
            Exported logs as string
        """
        async with self._lock:
            if format.lower() == "json":
                return json.dumps(
                    [entry.to_dict() for entry in self.log_entries], 
                    indent=2, 
                    default=str
                )
            elif format.lower() == "csv":
                import csv
                import io
                
                output = io.StringIO()
                writer = csv.DictWriter(
                    output, 
                    fieldnames=['timestamp', 'request_id', 'method', 'tool_name', 'status', 'error']
                )
                writer.writeheader()
                
                for entry in self.log_entries:
                    writer.writerow({
                        'timestamp': entry.timestamp.isoformat(),
                        'request_id': entry.request_id,
                        'method': entry.method,
                        'tool_name': entry.tool_name or '',
                        'status': entry.status,
                        'error': entry.error or ''
                    })
                
                return output.getvalue()
            else:
                raise ValueError(f"Unsupported export format: {format}")

    def get_log_file_path(self) -> Path:
        """Get the path to the log file."""
        return self.log_file

    def get_log_file_size(self) -> int:
        """Get the size of the log file in bytes."""
        try:
            return self.log_file.stat().st_size
        except FileNotFoundError:
            return 0 
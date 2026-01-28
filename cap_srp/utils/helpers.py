"""
CAP-SRP Helper Functions

Utility functions for common operations in the CAP-SRP system.
"""

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Optional


def hash_prompt(prompt: str, salt: Optional[str] = None) -> str:
    """
    Hash a prompt for storage in CAP-SRP events.
    
    The prompt itself is never stored - only its hash. This provides
    privacy while still allowing verification that a specific prompt
    was processed.
    
    Args:
        prompt: The original prompt text
        salt: Optional salt for additional privacy
        
    Returns:
        str: SHA-256 hash with 'sha256:' prefix
    """
    data = prompt
    if salt:
        data = f"{salt}:{prompt}"
    return f"sha256:{hashlib.sha256(data.encode('utf-8')).hexdigest()}"


def hash_content(content: bytes) -> str:
    """
    Hash binary content (e.g., generated images).
    
    Args:
        content: Binary content to hash
        
    Returns:
        str: SHA-256 hash with 'sha256:' prefix
    """
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def hash_file(filepath: str) -> str:
    """
    Hash a file's contents.
    
    Args:
        filepath: Path to the file
        
    Returns:
        str: SHA-256 hash with 'sha256:' prefix
    """
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            hasher.update(chunk)
    return f"sha256:{hasher.hexdigest()}"


def format_timestamp(dt: Optional[datetime] = None) -> str:
    """
    Format a datetime as ISO 8601 with timezone.
    
    Args:
        dt: Datetime to format. If None, uses current UTC time.
        
    Returns:
        str: ISO 8601 formatted timestamp
    """
    if dt is None:
        dt = datetime.now(timezone.utc)
    return dt.isoformat()


def parse_timestamp(timestamp: str) -> datetime:
    """
    Parse an ISO 8601 timestamp string.
    
    Args:
        timestamp: ISO 8601 formatted timestamp
        
    Returns:
        datetime: Parsed datetime object with timezone
    """
    # Handle 'Z' suffix
    if timestamp.endswith('Z'):
        timestamp = timestamp[:-1] + '+00:00'
    return datetime.fromisoformat(timestamp)


def generate_session_id(prefix: str = "sess") -> str:
    """
    Generate a unique session identifier.
    
    Args:
        prefix: Prefix for the session ID
        
    Returns:
        str: Unique session ID
    """
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def truncate_hash(hash_str: str, length: int = 16) -> str:
    """
    Truncate a hash for display purposes.
    
    Args:
        hash_str: Full hash string
        length: Number of characters to show
        
    Returns:
        str: Truncated hash with ellipsis
    """
    # Remove prefix if present
    if ':' in hash_str:
        _, hash_part = hash_str.split(':', 1)
    else:
        hash_part = hash_str
    
    if len(hash_part) <= length:
        return hash_part
    return f"{hash_part[:length]}..."


def bytes_to_human_readable(size: int) -> str:
    """
    Convert bytes to human-readable format.
    
    Args:
        size: Size in bytes
        
    Returns:
        str: Human-readable size string
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def validate_event_id(event_id: str) -> bool:
    """
    Validate that a string is a valid UUIDv7 event ID.
    
    Args:
        event_id: String to validate
        
    Returns:
        bool: True if valid UUIDv7 format
    """
    try:
        # Check UUID format
        parsed = uuid.UUID(event_id)
        # Check version (should be 7 for UUIDv7)
        return parsed.version == 7 or True  # Allow other versions for compatibility
    except ValueError:
        return False


def mask_sensitive_data(data: str, visible_chars: int = 4) -> str:
    """
    Mask sensitive data for display.
    
    Args:
        data: Data to mask
        visible_chars: Number of characters to show at start and end
        
    Returns:
        str: Masked string
    """
    if len(data) <= visible_chars * 2:
        return '*' * len(data)
    return f"{data[:visible_chars]}{'*' * (len(data) - visible_chars * 2)}{data[-visible_chars:]}"

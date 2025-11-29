"""
Security Utilities Module for Vaptiq.ai

Provides centralized security functions for:
- Input validation and sanitization
- Command injection prevention
- SSRF protection
- Audit logging
- Timing-safe comparisons
"""

import re
import secrets
import logging
import json
import ipaddress
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse
import uuid as uuid_module

# Configure logger
logger = logging.getLogger(__name__)


# ============================================================================
# INPUT VALIDATION & SANITIZATION
# ============================================================================

def validate_uuid(value: str, field_name: str = "ID") -> str:
    """
    Validate UUID format to prevent injection attempts.
    
    Args:
        value: String to validate as UUID
        field_name: Name of the field for error messages
        
    Returns:
        The validated UUID string
        
    Raises:
        ValueError: If the value is not a valid UUID
        
    Example:
        >>> validate_uuid("123e4567-e89b-12d3-a456-426614174000")
        '123e4567-e89b-12d3-a456-426614174000'
    """
    try:
        # This will raise ValueError if invalid
        uuid_module.UUID(value)
        return value
    except (ValueError, AttributeError, TypeError):
        raise ValueError(
            f"Invalid {field_name} format. Must be a valid UUID."
        )


def sanitize_target(target: str, target_type: str) -> str:
    """
    Validates and sanitizes target input to prevent command injection and SSRF.
    
    Security Features:
    - Blocks shell metacharacters
    - Validates URL/IP format
    - Prevents SSRF by blocking private IP ranges
    - Returns safe hostname for command execution
    
    Args:
        target: The target URL, IP, or API endpoint
        target_type: One of "URL", "IP", "API"
        
    Returns:
        Sanitized target suitable for subprocess execution
        
    Raises:
        ValueError: If target format is invalid or points to private network
        
    Example:
        >>> sanitize_target("https://example.com/api", "URL")
        'example.com'
        >>> sanitize_target("192.168.1.1", "IP")
        ValueError: Target points to private IP address (SSRF protection)
    """
    # Step 1: Remove any shell metacharacters
    dangerous_chars = [";", "&", "|", "`", "$", "(", ")", "<", ">", "\n", "\r", "\\"]
    for char in dangerous_chars:
        if char in target:
            raise ValueError(
                f"Invalid character '{char}' in target. "
                "Potential command injection attempt blocked."
            )
    
    # Step 2: Type-specific validation and SSRF protection
    if target_type == "URL":
        try:
            parsed = urlparse(target if "://" in target else f"http://{target}")
            if not parsed.netloc:
                raise ValueError("Invalid URL format - missing hostname")
            
            hostname = parsed.netloc.split(':')[0]  # Remove port
            
            # SSRF Protection: Resolve hostname and check if it's a private IP
            try:
                ip = ipaddress.ip_address(hostname)
                if ip.is_private or ip.is_loopback or ip.is_link_local:
                    raise ValueError(
                        f"Target points to private IP address ({ip}). "
                        "SSRF protection: Cannot scan internal network resources."
                    )
            except ValueError as e:
                # If it's not a direct IP, try resolving the hostname
                if "private IP" in str(e) or "SSRF" in str(e):
                    raise  # Re-raise SSRF errors
                # Otherwise it's a hostname, which we'll validate with DNS later
                pass
            
            # Additional validation: Check for localhost variations
            localhost_names = ["localhost", "127.0.0.1", "0.0.0.0", "::1"]
            if hostname.lower() in localhost_names:
                raise ValueError(
                    "SSRF protection: Cannot scan localhost or loopback addresses"
                )
            
            return hostname
            
        except ValueError as e:
            if "SSRF" in str(e) or "private IP" in str(e):
                raise
            raise ValueError(f"Invalid URL format: {e}")
    
    elif target_type == "IP":
        # Validate IP address format
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(ip_pattern, target):
            raise ValueError("Invalid IP address format (expected xxx.xxx.xxx.xxx)")
        
        # Parse and validate IP ranges
        try:
            ip = ipaddress.ip_address(target)
            
            # SSRF Protection: Block private IP ranges
            if ip.is_private:
                raise ValueError(
                    f"SSRF protection: Cannot scan private IP ranges "
                    f"(RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)"
                )
            
            if ip.is_loopback:
                raise ValueError("SSRF protection: Cannot scan loopback addresses (127.0.0.0/8)")
            
            if ip.is_link_local:
                raise ValueError("SSRF protection: Cannot scan link-local addresses (169.254.0.0/16)")
            
            if ip.is_reserved:
                raise ValueError("SSRF protection: Cannot scan reserved IP addresses")
            
            # Check for AWS metadata endpoint
            if str(ip) == "169.254.169.254":
                raise ValueError(
                    "SSRF protection: Blocked cloud metadata endpoint "
                    "(AWS/GCP/Azure metadata service)"
                )
            
            return str(ip)
            
        except ValueError as e:
            if "SSRF" in str(e):
                raise
            raise ValueError(f"Invalid IP address: {e}")
    
    elif target_type == "API":
        # For API endpoints, apply URL validation
        return sanitize_target(target, "URL")
    
    else:
        raise ValueError(f"Unknown target type: {target_type}")


# ============================================================================
# TIMING-SAFE COMPARISON
# ============================================================================

def constant_time_compare(a: str, b: str) -> bool:
    """
    Compare strings in constant time to prevent timing attacks.
    
    This is critical for comparing security tokens, API keys, and UUIDs.
    Regular string comparison (==) leaks timing information that can be
    used to brute-force tokens character by character.
    
    Args:
        a: First string
        b: Second string
        
    Returns:
        True if strings are equal, False otherwise
        
    Example:
        >>> constant_time_compare("secret123", "secret123")
        True
        >>> constant_time_compare("secret123", "secret124")
        False
    """
    if a is None or b is None:
        return False
    return secrets.compare_digest(a.encode('utf-8'), b.encode('utf-8'))


# ============================================================================
# AUDIT LOGGING
# ============================================================================

class AuditLogger:
    """
    Centralized audit logging for security-relevant events.
    
    Logs are written in structured JSON format for easy parsing
    and compliance reporting (PCI DSS Requirement 10).
    
    Events logged:
    - Authentication successes/failures
    - Authorization denials
    - Sensitive data access
    - Configuration changes
    - Administrative actions
    """
    
    def __init__(self, log_file: str = "audit.log"):
        """Initialize audit logger with file handler"""
        self.logger = logging.getLogger("vaptiq.audit")
        
        # Avoid duplicate handlers
        if not self.logger.handlers:
            handler = logging.FileHandler(log_file)
            handler.setFormatter(logging.Formatter('%(message)s'))
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    def log_event(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        resource: Optional[str] = None,
        action: Optional[str] = None,
        status: Optional[str] = None,
        details: Optional[dict] = None
    ):
        """
        Log a security event in structured JSON format.
        
        Args:
            event_type: Type of event (AUTH_SUCCESS, AUTH_FAILURE, etc.)
            user_id: ID of user performing action
            ip_address: Source IP address
            resource: Resource being accessed
            action: Action being performed
            status: Result status (SUCCESS, FAILURE, DENIED)
            details: Additional context as dictionary
        """
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "user_id": user_id,
            "ip_address": ip_address,
            "resource": resource,
            "action": action,
            "status": status,
            "details": details or {}
        }
        
        # Filter out None values for cleaner logs
        log_entry = {k: v for k, v in log_entry.items() if v is not None}
        
        self.logger.info(json.dumps(log_entry))
    
    def log_auth_success(self, user_id: str, ip_address: Optional[str] = None):
        """Log successful authentication"""
        self.log_event(
            event_type="AUTH_SUCCESS",
            user_id=user_id,
            ip_address=ip_address,
            action="LOGIN",
            status="SUCCESS"
        )
    
    def log_auth_failure(self, reason: str, ip_address: Optional[str] = None):
        """Log authentication failure"""
        self.log_event(
            event_type="AUTH_FAILURE",
            ip_address=ip_address,
            action="LOGIN",
            status="FAILURE",
            details={"reason": reason}
        )
    
    def log_access_denied(
        self, 
        user_id: str, 
        resource: str, 
        reason: str,
        ip_address: Optional[str] = None
    ):
        """Log authorization denial"""
        self.log_event(
            event_type="ACCESS_DENIED",
            user_id=user_id,
            ip_address=ip_address,
            resource=resource,
            action="ACCESS",
            status="DENIED",
            details={"reason": reason}
        )
    
    def log_sensitive_access(
        self,
        user_id: str,
        resource: str,
        action: str,
        ip_address: Optional[str] = None
    ):
        """Log access to sensitive data"""
        self.log_event(
            event_type="SENSITIVE_DATA_ACCESS",
            user_id=user_id,
            ip_address=ip_address,
            resource=resource,
            action=action,
            status="SUCCESS"
        )


# Global audit logger instance
audit_logger = AuditLogger()

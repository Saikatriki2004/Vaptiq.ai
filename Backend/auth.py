"""
JWT Authentication Module for Vaptiq.ai

Security Features:
- Validates Supabase JWT tokens with mandatory secret
- Prevents user_id forgery attacks
- Returns 401 for invalid/expired tokens
- Role-based access control (RBAC)
- Comprehensive audit logging
- Fail-closed security (rejects if misconfigured)

Usage:
    from auth import get_current_user, require_role, UserRole
    
    @app.post("/scan")
    async def start_scan(user: User = Depends(get_current_user)):
        # user.id is now trustworthy
        # user.credits is current balance
    
    @app.get("/admin/users")
    async def list_users(user = Depends(require_role([UserRole.ADMIN]))):
        # Admin-only endpoint
"""

from fastapi import Security, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
import os
import logging
from enum import Enum
from typing import List, Optional
from db import db
from security import audit_logger

# Configure logger
logger = logging.getLogger(__name__)

# ============================================================================
# CRITICAL SECURITY: JWT Secret Validation (CRITICAL-001)
# ============================================================================

SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET")

if not SUPABASE_JWT_SECRET:
    raise ValueError(
        "❌ CRITICAL SECURITY ERROR: SUPABASE_JWT_SECRET is not set!\n"
        "This would allow anyone to forge authentication tokens.\n"
        "Please set SUPABASE_JWT_SECRET in your .env file.\n"
        "Example: SUPABASE_JWT_SECRET=your-secret-here-minimum-32-chars-long"
    )

if len(SUPABASE_JWT_SECRET) < 32:
    raise ValueError(
        f"❌ CRITICAL SECURITY ERROR: SUPABASE_JWT_SECRET is too short!\n"
        f"Current length: {len(SUPABASE_JWT_SECRET)} characters\n"
        f"Minimum required: 32 characters\n"
        "A short secret is vulnerable to brute-force attacks.\n"
        "Please generate a strong secret: openssl rand -hex 32"
    )

logger.info("✅ JWT secret validated (length: %d characters)", len(SUPABASE_JWT_SECRET))

# ============================================================================
# ROLE-BASED ACCESS CONTROL (MEDIUM-004)
# ============================================================================

class UserRole(str, Enum):
    """User roles for role-based access control"""
    ADMIN = "ADMIN"
    USER = "USER"
    AUDITOR = "AUDITOR"

security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security),
    request: Request = None
):
    """
    Validates Supabase JWT token and returns authenticated user.
    
    Security Improvements:
    - Uses validated SUPABASE_JWT_SECRET (fails at startup if missing)
    - Structured audit logging (no sensitive data in logs)
    - IP address tracking for security monitoring
    - Prevents user_id forgery attacks
    
    Args:
        credentials: HTTP Bearer token from Authorization header
        request: FastAPI request object (for IP logging)
        
    Returns:
        User: Authenticated user object with credits balance
        
    Raises:
        HTTPException 401: Invalid or expired token
    """
    token = credentials.credentials
    ip_address = request.client.host if request else None
    
    try:
        # Decode and verify JWT using validated secret
        payload = jwt.decode(
            token,
            SUPABASE_JWT_SECRET,  # ✅ Now validated at module load
            algorithms=["HS256"],
            audience="authenticated"  # Supabase-specific claim
        )
        
        user_id = payload.get('sub')  # Subject claim = user ID
        if not user_id:
            audit_logger.log_auth_failure(
                reason="Missing 'sub' claim in JWT",
                ip_address=ip_address
            )
            raise HTTPException(
                status_code=401, 
                detail="Invalid token structure"
            )
        
        # Fetch user from database
        user = await db.user.find_unique(where={"id": user_id})
        
        if not user:
            audit_logger.log_auth_failure(
                reason=f"User {user_id[:8]}... not found in database",
                ip_address=ip_address
            )
            raise HTTPException(status_code=401, detail="User not found")
        
        # ✅ Success - log authentication
        audit_logger.log_auth_success(
            user_id=user.id,
            ip_address=ip_address
        )
        
        return user
        
    except jwt.ExpiredSignatureError:
        audit_logger.log_auth_failure(
            reason="JWT token expired",
            ip_address=ip_address
        )
        raise HTTPException(status_code=401, detail="Token expired")
    
    except jwt.InvalidTokenError as e:
        audit_logger.log_auth_failure(
            reason=f"Invalid JWT: {type(e).__name__}",
            ip_address=ip_address
        )
        raise HTTPException(status_code=401, detail="Invalid token")
    
    except HTTPException:
        raise  # Re-raise HTTP exceptions as-is
    
    except Exception as e:
        # ✅ Structured logging - no sensitive data exposure
        logger.error(
            "Authentication error",
            extra={
                "error_type": type(e).__name__,
                "ip_address": ip_address
            },
            exc_info=False  # Don't log full stack trace in production
        )
        audit_logger.log_auth_failure(
            reason=f"Unexpected error: {type(e).__name__}",
            ip_address=ip_address
        )
        raise HTTPException(status_code=401, detail="Authentication failed")


# Configure security scheme with auto_error=False
security_optional = HTTPBearer(auto_error=False)

async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_optional),
    request: Request = None
):
    """
    Optional authentication - returns None if no token provided.
    Useful for endpoints that work with or without auth.
    
    Args:
        credentials: Optional HTTP Bearer token
        request: FastAPI request object
        
    Returns:
        User | None: Authenticated user or None
    """
    if not credentials:
        return None
    
    return await get_current_user(credentials, request)


def require_role(allowed_roles: List[UserRole]):
    """
    Dependency factory for role-based access control.
    
    Usage:
        @app.get("/admin/users")
        async def list_users(user = Depends(require_role([UserRole.ADMIN]))):
            return await db.user.find_many()
    
    Args:
        allowed_roles: List of roles that can access the endpoint
        
    Returns:
        Dependency function that validates user role
        
    Raises:
        HTTPException 403: If user doesn't have required role
    """
    async def check_role(
        user = Depends(get_current_user),
        request: Request = None
    ):
        if user.role not in [r.value for r in allowed_roles]:
            ip_address = request.client.host if request else None
            
            # Log authorization failure
            audit_logger.log_access_denied(
                user_id=user.id,
                resource=request.url.path if request else "unknown",
                reason=f"Role '{user.role}' not in {[r.value for r in allowed_roles]}",
                ip_address=ip_address
            )
            
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient permissions. Required role: {', '.join([r.value for r in allowed_roles])}"
            )
        return user
    
    return check_role

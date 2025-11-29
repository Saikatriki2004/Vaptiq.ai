"""
JWT Authentication Module for Vaptiq.ai

Security Features:
- Validates Supabase JWT tokens
- Prevents user_id forgery attacks
- Returns 401 for invalid/expired tokens
- Automatically fetches user from database

Usage:
    from auth import get_current_user
    
    @app.post("/scan")
    async def start_scan(user: User = Depends(get_current_user)):
        # user.id is now trustworthy
        # user.credits is current balance
"""

from fastapi import Security, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
import os
from db import db

security = HTTPBearer()


async def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
    """
    Validates Supabase JWT token and returns authenticated user.
    
    Security:
    - Verifies signature using SUPABASE_JWT_SECRET
    - Prevents user_id forgery attacks  
    - Returns 401 if token is invalid/expired
    
    Args:
        credentials: HTTP Bearer token from Authorization header
        
    Returns:
        User: Authenticated user object with credits balance
        
    Raises:
        HTTPException 401: Invalid or expired token
    """
    token = credentials.credentials
    
    try:
        # Decode and verify JWT
        payload = jwt.decode(
            token,
            os.getenv("SUPABASE_JWT_SECRET"),
            algorithms=["HS256"],
            audience="authenticated"  # Supabase-specific claim
        )
        
        user_id = payload['sub']  # Subject claim = user ID
        
        # Fetch user from database
        user = await db.user.find_unique(where={"id": user_id})
        
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        return user
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except KeyError:
        raise HTTPException(status_code=401, detail="Invalid token structure (missing 'sub' claim)")
    except Exception as e:
        # Log the error for debugging but don't expose internals to user
        print(f"❌ Authentication error: {str(e)}")
        raise HTTPException(status_code=401, detail="Authentication failed")


async def get_current_user_optional(credentials: HTTPAuthorizationCredentials | None = Depends(HTTPBearer(auto_error=False))):
    """
    Optional authentication - returns None if no token provided.
    Useful for endpoints that work with or without auth.
    
    Args:
        credentials: Optional HTTP Bearer token
        
    Returns:
        User | None: Authenticated user or None
    """
    if not credentials:
        return None
    
    return await get_current_user(credentials)

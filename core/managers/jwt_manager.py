from datetime import datetime, timedelta
import jwt
from typing import Dict, Any, Optional, Union
from tools.logger.custom_logging import custom_log
from utils.config.config import Config
from core.managers.redis_manager import RedisManager
from enum import Enum
import hashlib
from flask import request

class TokenType(Enum):
    ACCESS = "access"
    REFRESH = "refresh"
    WEBSOCKET = "websocket"

class JWTManager:
    def __init__(self):
        self.redis_manager = RedisManager()
        self.secret_key = Config.JWT_SECRET_KEY
        self.algorithm = Config.JWT_ALGORITHM
        # Shorter token lifetimes
        self.access_token_expire_seconds = 1800  # 30 minutes
        self.refresh_token_expire_seconds = 86400  # 24 hours
        self.websocket_token_expire_seconds = 1800  # 30 minutes
        custom_log("JWTManager initialized")

    def _get_client_fingerprint(self) -> str:
        """Generate a unique client fingerprint based on IP and User-Agent."""
        try:
            ip = request.remote_addr
            user_agent = request.headers.get('User-Agent', '')
            fingerprint = hashlib.sha256(f"{ip}-{user_agent}".encode()).hexdigest()
            return fingerprint
        except Exception as e:
            custom_log(f"Error generating client fingerprint: {str(e)}")
            return ""

    def create_token(self, data: Dict[str, Any], token_type: TokenType, expires_in: Optional[int] = None) -> str:
        """Create a new JWT token of specified type with client binding."""
        to_encode = data.copy()
        
        # Set expiration based on token type
        if expires_in:
            expire = datetime.utcnow() + timedelta(seconds=expires_in)
        else:
            if token_type == TokenType.ACCESS:
                expire = datetime.utcnow() + timedelta(seconds=self.access_token_expire_seconds)
            elif token_type == TokenType.REFRESH:
                expire = datetime.utcnow() + timedelta(seconds=self.refresh_token_expire_seconds)
            else:  # WEBSOCKET
                expire = datetime.utcnow() + timedelta(seconds=self.websocket_token_expire_seconds)
        
        # Add client fingerprint for token binding
        client_fingerprint = self._get_client_fingerprint()
        if client_fingerprint:
            to_encode["fingerprint"] = client_fingerprint
            
        to_encode.update({
            "exp": expire,
            "type": token_type.value,
            "iat": datetime.utcnow()
        })
        
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        
        # Store token in Redis for revocation capability
        self._store_token(encoded_jwt, expire, token_type)
        
        return encoded_jwt

    def verify_token(self, token: str, expected_type: Optional[TokenType] = None) -> Optional[Dict[str, Any]]:
        """Verify a JWT token and return its payload if valid."""
        try:
            # Check if token is revoked
            if self._is_token_revoked(token):
                custom_log(f"Token revoked: {token[:10]}...")
                return None
                
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # Verify token type if specified
            if expected_type and payload.get("type") != expected_type.value:
                custom_log(f"Invalid token type. Expected: {expected_type.value}, Got: {payload.get('type')}")
                return None
            
            # Verify client fingerprint if present
            if "fingerprint" in payload:
                current_fingerprint = self._get_client_fingerprint()
                if current_fingerprint and payload["fingerprint"] != current_fingerprint:
                    custom_log("Token bound to different client")
                    return None
                
            return payload
        except jwt.ExpiredSignatureError:
            custom_log("Token has expired")
            return None
        except jwt.JWTError as e:
            custom_log(f"JWT verification failed: {str(e)}")
            return None

    def revoke_token(self, token: str) -> bool:
        """Revoke a token by removing it from Redis."""
        try:
            # Remove from all token types
            for token_type in TokenType:
                key = f"token:{token_type.value}:{token}"
                self.redis_manager.delete(key)
            custom_log(f"Token revoked: {token[:10]}...")
            return True
        except Exception as e:
            custom_log(f"Error revoking token: {str(e)}")
            return False

    def refresh_token(self, refresh_token: str) -> Optional[str]:
        """Create a new access token using a refresh token."""
        payload = self.verify_token(refresh_token, TokenType.REFRESH)
        if payload:
            # Remove refresh-specific claims
            new_payload = {k: v for k, v in payload.items() 
                         if k not in ['exp', 'iat', 'type']}
            return self.create_token(new_payload, TokenType.ACCESS)
        return None

    def _store_token(self, token: str, expire: datetime, token_type: TokenType):
        """Store token in Redis with proper prefix and expiration."""
        try:
            # Use a prefix for faster revocation checks
            key = f"token:{token_type.value}:{token}"
            ttl = int((expire - datetime.utcnow()).total_seconds())
            
            if ttl > 0:
                # Store token with its TTL
                self.redis_manager.set(key, "1", expire=ttl)
                custom_log(f"Stored {token_type.value} token with TTL {ttl}s")
            else:
                custom_log(f"Token already expired, not storing: {token[:10]}...")
            
        except Exception as e:
            custom_log(f"Error storing token: {str(e)}")

    def _is_token_revoked(self, token: str) -> bool:
        """Check if a token is revoked using prefix-based lookup."""
        try:
            # Check all token types since we don't know which type it is
            for token_type in TokenType:
                key = f"token:{token_type.value}:{token}"
                if self.redis_manager.exists(key):
                    return False  # Token exists in Redis, so it's not revoked
            return True  # Token not found in any type, so it's revoked
        except Exception as e:
            custom_log(f"Error checking token revocation: {str(e)}")
            return True  # Fail safe: consider token revoked on error

    def cleanup_expired_tokens(self):
        """Clean up expired tokens from Redis."""
        # This can be called periodically to clean up expired tokens
        # Implementation depends on your Redis key pattern
        pass

    # Convenience methods for specific use cases
    def create_access_token(self, data: Dict[str, Any], expires_in: Optional[int] = None) -> str:
        """Create a new access token."""
        return self.create_token(data, TokenType.ACCESS, expires_in)

    def create_refresh_token(self, data: Dict[str, Any], expires_in: Optional[int] = None) -> str:
        """Create a new refresh token."""
        return self.create_token(data, TokenType.REFRESH, expires_in)

    def create_websocket_token(self, data: Dict[str, Any], expires_in: Optional[int] = None) -> str:
        """Create a new WebSocket token."""
        return self.create_token(data, TokenType.WEBSOCKET, expires_in)

    def verify_websocket_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify a WebSocket token."""
        return self.verify_token(token, TokenType.WEBSOCKET) 
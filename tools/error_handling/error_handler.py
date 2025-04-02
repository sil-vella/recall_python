import logging
from typing import Any, Dict, Optional
from datetime import datetime
import traceback
import re
from tools.logger.custom_logging import custom_log
import psycopg2

class ValidationError(Exception):
    """Raised when input validation fails."""
    pass

class DatabaseError(Exception):
    """Raised when database operations fail."""
    pass

class RedisError(Exception):
    """Raised when Redis operations fail."""
    pass

class ErrorHandler:
    """Centralized error handling for the application."""
    
    def __init__(self):
        self.error_counts = {}  # Track error frequencies
        self.max_error_count = 100  # Maximum errors to track
        self.error_window = 3600  # 1 hour window for rate limiting
        self.max_query_size = 1024 * 1024  # 1MB max query size
        self.sensitive_patterns = [
            r'password',
            r'secret',
            r'key',
            r'token',
            r'credential'
        ]
        self.error_codes = {
            'DATABASE_ERROR': 500,
            'CACHE_ERROR': 500,
            'VALIDATION_ERROR': 400,
            'AUTH_ERROR': 401,
            'AUTHZ_ERROR': 403,
            'RATE_LIMIT_EXCEEDED': 429,
            'NOT_FOUND': 404,
            'CONFLICT': 409,
            'BAD_REQUEST': 400,
            'INTERNAL_ERROR': 500
        }

    def handle_error(self, error: Exception, operation: str = "unknown") -> Dict[str, Any]:
        """Handle any type of error and return appropriate response."""
        if isinstance(error, ValidationError):
            return self.handle_validation_error(error)
        elif isinstance(error, DatabaseError):
            return self.handle_database_error(error, operation)
        elif isinstance(error, RedisError):
            return self.handle_redis_error(error, operation)
        elif isinstance(error, psycopg2.OperationalError):
            return self.handle_database_error(error, operation)
        elif isinstance(error, psycopg2.IntegrityError):
            return self.handle_conflict_error(error)
        elif isinstance(error, psycopg2.ProgrammingError):
            return self.handle_bad_request_error(error)
        else:
            return self.handle_internal_error(error)

    def sanitize_error_message(self, error: Exception) -> str:
        """Sanitize error messages to prevent information leakage."""
        error_msg = str(error)
        
        # Remove sensitive information
        for pattern in self.sensitive_patterns:
            error_msg = re.sub(
                f'{pattern}[=:]\s*[^\s]+',
                f'{pattern}=[REDACTED]',
                error_msg,
                flags=re.IGNORECASE
            )
        
        # Remove stack traces from user-facing errors
        if 'Traceback' in error_msg:
            error_msg = error_msg.split('Traceback')[0]
        
        return error_msg

    def is_rate_limited(self, operation: str) -> bool:
        """Check if an operation is rate limited."""
        current_time = datetime.now().timestamp()
        
        if operation not in self.error_counts:
            self.error_counts[operation] = []
        
        # Clean old errors
        self.error_counts[operation] = [
            t for t in self.error_counts[operation]
            if current_time - t < self.error_window
        ]
        
        # Check if rate limit exceeded
        if len(self.error_counts[operation]) >= self.max_error_count:
            return True
        
        return False

    def track_error(self, operation: str, error: Exception) -> None:
        """Track error occurrence for rate limiting."""
        if operation not in self.error_counts:
            self.error_counts[operation] = []
        
        self.error_counts[operation].append(datetime.now().timestamp())
        
        # Trim old errors if needed
        if len(self.error_counts[operation]) > self.max_error_count:
            self.error_counts[operation] = self.error_counts[operation][-self.max_error_count:]

    def validate_query_size(self, query: str, params: Optional[tuple] = None) -> bool:
        """Validate query size against maximum allowed size."""
        query_size = len(query.encode('utf-8'))
        if params:
            query_size += sum(len(str(p).encode('utf-8')) for p in params)
        
        return query_size <= self.max_query_size

    def handle_database_error(self, error: Exception, operation: str) -> Dict[str, Any]:
        """Handle database-specific errors."""
        if self.is_rate_limited(operation):
            return {
                "error": "Too many requests. Please try again later.",
                "code": "RATE_LIMIT_EXCEEDED",
                "status": self.error_codes['RATE_LIMIT_EXCEEDED']
            }
        
        self.track_error(operation, error)
        
        # Log the full error for debugging
        custom_log(f"❌ Database error in {operation}: {str(error)}")
        
        # Return sanitized error for client
        return {
            "error": "A database error occurred. Please try again later.",
            "code": "DATABASE_ERROR",
            "status": self.error_codes['DATABASE_ERROR']
        }

    def handle_redis_error(self, error: Exception, operation: str) -> Dict[str, Any]:
        """Handle Redis-specific errors."""
        if self.is_rate_limited(operation):
            return {
                "error": "Too many requests. Please try again later.",
                "code": "RATE_LIMIT_EXCEEDED",
                "status": self.error_codes['RATE_LIMIT_EXCEEDED']
            }
        
        self.track_error(operation, error)
        
        # Log the full error for debugging
        custom_log(f"❌ Redis error in {operation}: {str(error)}")
        
        # Return sanitized error for client
        return {
            "error": "A caching error occurred. Please try again later.",
            "code": "CACHE_ERROR",
            "status": self.error_codes['CACHE_ERROR']
        }

    def handle_validation_error(self, error: Exception) -> Dict[str, Any]:
        """Handle validation errors."""
        return {
            "error": "Invalid input provided.",
            "code": "VALIDATION_ERROR",
            "status": self.error_codes['VALIDATION_ERROR']
        }

    def handle_authentication_error(self, error: Exception) -> Dict[str, Any]:
        """Handle authentication errors."""
        return {
            "error": "Authentication failed.",
            "code": "AUTH_ERROR",
            "status": self.error_codes['AUTH_ERROR']
        }

    def handle_authorization_error(self, error: Exception) -> Dict[str, Any]:
        """Handle authorization errors."""
        return {
            "error": "You don't have permission to perform this action.",
            "code": "AUTHZ_ERROR",
            "status": self.error_codes['AUTHZ_ERROR']
        }

    def handle_not_found_error(self, error: Exception) -> Dict[str, Any]:
        """Handle not found errors."""
        return {
            "error": "The requested resource was not found.",
            "code": "NOT_FOUND",
            "status": self.error_codes['NOT_FOUND']
        }

    def handle_conflict_error(self, error: Exception) -> Dict[str, Any]:
        """Handle conflict errors."""
        return {
            "error": "A conflict occurred with the current state of the resource.",
            "code": "CONFLICT",
            "status": self.error_codes['CONFLICT']
        }

    def handle_bad_request_error(self, error: Exception) -> Dict[str, Any]:
        """Handle bad request errors."""
        return {
            "error": "The request was malformed or invalid.",
            "code": "BAD_REQUEST",
            "status": self.error_codes['BAD_REQUEST']
        }

    def handle_internal_error(self, error: Exception) -> Dict[str, Any]:
        """Handle internal server errors."""
        return {
            "error": "An internal server error occurred.",
            "code": "INTERNAL_ERROR",
            "status": self.error_codes['INTERNAL_ERROR']
        }

    def log_security_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """Log security-related events."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "details": details
        }
        custom_log(f"🔒 Security Event: {event_type} - {details}") 
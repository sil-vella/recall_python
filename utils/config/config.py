import os

class Config:
    # Debug mode
    DEBUG = os.getenv("FLASK_DEBUG", "False").lower() in ("true", "1")

    # JWT Configuration
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-super-secret-key-change-in-production")
    JWT_ACCESS_TOKEN_EXPIRES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES", "3600"))  # 1 hour in seconds
    JWT_REFRESH_TOKEN_EXPIRES = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRES", "604800"))  # 7 days in seconds
    JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
    JWT_TOKEN_TYPE = os.getenv("JWT_TOKEN_TYPE", "bearer")
    JWT_HEADER_NAME = os.getenv("JWT_HEADER_NAME", "Authorization")
    JWT_HEADER_TYPE = os.getenv("JWT_HEADER_TYPE", "Bearer")
    JWT_QUERY_STRING_NAME = os.getenv("JWT_QUERY_STRING_NAME", "token")
    JWT_QUERY_STRING_VALUE_PREFIX = os.getenv("JWT_QUERY_STRING_VALUE_PREFIX", "Bearer")
    JWT_COOKIE_NAME = os.getenv("JWT_COOKIE_NAME", "access_token")
    JWT_COOKIE_CSRF_PROTECT = os.getenv("JWT_COOKIE_CSRF_PROTECT", "true").lower() == "true"
    JWT_COOKIE_SECURE = os.getenv("JWT_COOKIE_SECURE", "true").lower() == "true"
    JWT_COOKIE_SAMESITE = os.getenv("JWT_COOKIE_SAMESITE", "Lax")
    JWT_COOKIE_DOMAIN = os.getenv("JWT_COOKIE_DOMAIN", None)
    JWT_COOKIE_PATH = os.getenv("JWT_COOKIE_PATH", "/")
    JWT_COOKIE_MAX_AGE = int(os.getenv("JWT_COOKIE_MAX_AGE", "3600"))  # 1 hour in seconds

    # Toggle SSL for PostgreSQL
    USE_SSL = os.getenv("USE_SSL", "False").lower() in ("true", "1")

    # Database Pool Configuration
    DB_POOL_MIN_CONN = int(os.getenv("DB_POOL_MIN_CONN", "1"))
    DB_POOL_MAX_CONN = int(os.getenv("DB_POOL_MAX_CONN", "10"))
    
    # Connection Pool Security Settings
    DB_CONNECT_TIMEOUT = int(os.getenv("DB_CONNECT_TIMEOUT", "10"))  # Connection timeout in seconds
    DB_STATEMENT_TIMEOUT = int(os.getenv("DB_STATEMENT_TIMEOUT", "30000"))  # Statement timeout in milliseconds
    DB_KEEPALIVES = int(os.getenv("DB_KEEPALIVES", "1"))  # Enable keepalive
    DB_KEEPALIVES_IDLE = int(os.getenv("DB_KEEPALIVES_IDLE", "30"))  # Idle timeout in seconds
    DB_KEEPALIVES_INTERVAL = int(os.getenv("DB_KEEPALIVES_INTERVAL", "10"))  # Keepalive interval in seconds
    DB_KEEPALIVES_COUNT = int(os.getenv("DB_KEEPALIVES_COUNT", "5"))  # Maximum number of keepalive attempts
    DB_MAX_CONNECTIONS_PER_USER = int(os.getenv("DB_MAX_CONNECTIONS_PER_USER", "5"))  # Maximum connections per user
    
    # Resource Protection
    DB_MAX_QUERY_SIZE = int(os.getenv("DB_MAX_QUERY_SIZE", "10000"))  # Maximum query size in bytes
    DB_MAX_RESULT_SIZE = int(os.getenv("DB_MAX_RESULT_SIZE", "1048576"))  # Maximum result size in bytes (1MB)
    
    # Connection Retry Settings
    DB_RETRY_COUNT = int(os.getenv("DB_RETRY_COUNT", "3"))  # Number of connection retry attempts
    DB_RETRY_DELAY = int(os.getenv("DB_RETRY_DELAY", "1"))  # Delay between retries in seconds
    
    # Flask-Limiter: Redis backend for rate limiting
    RATE_LIMIT_STORAGE_URL = os.getenv("RATE_LIMIT_STORAGE_URL", "redis://localhost:6379/0")

    # Enable or disable logging
    LOGGING_ENABLED = os.getenv("LOGGING_ENABLED", "True").lower() in ("true", "1")

    # Redis Security Settings
    REDIS_USE_SSL = os.getenv("REDIS_USE_SSL", "false").lower() == "true"
    REDIS_SSL_VERIFY_MODE = os.getenv("REDIS_SSL_VERIFY_MODE", "required")
    REDIS_MAX_CONNECTIONS = int(os.getenv("REDIS_MAX_CONNECTIONS", "10"))
    REDIS_SOCKET_TIMEOUT = int(os.getenv("REDIS_SOCKET_TIMEOUT", "5"))
    REDIS_SOCKET_CONNECT_TIMEOUT = int(os.getenv("REDIS_SOCKET_CONNECT_TIMEOUT", "5"))
    REDIS_RETRY_ON_TIMEOUT = os.getenv("REDIS_RETRY_ON_TIMEOUT", "true").lower() == "true"
    REDIS_MAX_RETRIES = int(os.getenv("REDIS_MAX_RETRIES", "3"))
    REDIS_KEY_PREFIX = os.getenv("REDIS_KEY_PREFIX", "app")
    REDIS_ENCRYPTION_KEY = os.getenv("REDIS_ENCRYPTION_KEY", "")
    REDIS_ENCRYPTION_SALT = os.getenv("REDIS_ENCRYPTION_SALT", "")
    REDIS_ENCRYPTION_ITERATIONS = int(os.getenv("REDIS_ENCRYPTION_ITERATIONS", "100000"))
    REDIS_MAX_CACHE_SIZE = int(os.getenv("REDIS_MAX_CACHE_SIZE", "1048576"))  # 1MB in bytes
    REDIS_CACHE_TTL = int(os.getenv("REDIS_CACHE_TTL", "300"))  # 5 minutes in seconds

    # WebSocket Configuration
    WS_MAX_MESSAGE_SIZE = 1024 * 1024  # 1MB default max message size
    WS_MAX_TEXT_MESSAGE_SIZE = 1024 * 1024  # 1MB for text messages
    WS_MAX_BINARY_MESSAGE_SIZE = 5 * 1024 * 1024  # 5MB for binary messages
    WS_MAX_JSON_MESSAGE_SIZE = 512 * 1024  # 512KB for JSON messages
    WS_MESSAGE_RATE_LIMIT = 100  # messages per second per user
    WS_MESSAGE_RATE_WINDOW = 1  # seconds for rate limiting
    WS_COMPRESSION_THRESHOLD = 1024  # 1KB - compress messages larger than this
    WS_COMPRESSION_LEVEL = 6  # zlib compression level (1-9)
    WS_MAX_PAYLOAD_SIZE = 1024 * 1024  # 1MB max payload size
    WS_PING_TIMEOUT = 60
    WS_PING_INTERVAL = 25
    WS_RATE_LIMIT_CONNECTIONS = 100
    WS_RATE_LIMIT_MESSAGES = 1000
    WS_RATE_LIMIT_WINDOW = 3600  # 1 hour
    WS_SESSION_TTL = 3600  # 1 hour
    WS_ROOM_SIZE_LIMIT = 2
    WS_ROOM_SIZE_CHECK_INTERVAL = 300  # 5 minutes
    WS_ALLOWED_ORIGINS = ['http://localhost:5000', 'http://localhost:3000']

    # Presence Tracking Configuration
    WS_PRESENCE_CHECK_INTERVAL = 30  # seconds between presence checks
    WS_PRESENCE_TIMEOUT = 90  # seconds before marking user as offline
    WS_PRESENCE_CLEANUP_INTERVAL = 300  # seconds between cleanup operations
    WS_PRESENCE_STATUSES = {
        'online': 'online',
        'away': 'away',
        'offline': 'offline',
        'busy': 'busy'
    }

    # Message Size Limits
    WS_MAX_MESSAGE_LENGTH = 1000  # Maximum length for text messages
    WS_MAX_BINARY_SIZE = 5 * 1024 * 1024  # 5MB for binary data
    WS_MAX_JSON_DEPTH = 10  # Maximum nesting depth for JSON messages
    WS_MAX_JSON_SIZE = 1024 * 1024  # 1MB for JSON messages
    WS_MAX_ARRAY_SIZE = 1000  # Maximum number of elements in arrays
    WS_MAX_OBJECT_SIZE = 100  # Maximum number of properties in objects

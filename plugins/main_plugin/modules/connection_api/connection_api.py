import psycopg2
import psycopg2.extras
import psycopg2.pool
import os
import json
from tools.logger.custom_logging import custom_log, log_function_call
from utils.config.config import Config
from core.managers.redis_manager import RedisManager
from core.managers.jwt_manager import JWTManager, TokenType
from tools.error_handling import ErrorHandler
from datetime import datetime
import time
import uuid
import logging

class ConnectionAPI:
    def __init__(self, app_manager=None):
        """Initialize the ConnectionAPI with Redis and database connections."""
        self.registered_routes = []
        self.app = None  # Reference to Flask app
        self.app_manager = app_manager  # Reference to AppManager if provided
        self.connection_pool = self._create_connection_pool()  # Initialize PostgreSQL connection pool
        self.redis_manager = RedisManager()  # Initialize Redis manager
        self.jwt_manager = JWTManager()  # Initialize JWT manager
        self.error_handler = ErrorHandler()  # Initialize error handler
        self.logger = logging.getLogger(__name__)
        
        # Session management settings
        self.session_timeout = 3600  # 1 hour in seconds
        self.max_concurrent_sessions = 3  # Maximum concurrent sessions per user
        self.session_check_interval = 300  # 5 minutes in seconds

        # ✅ Ensure tables exist in the database
        self.initialize_database()

    def initialize(self, app):
        """Initialize the ConnectionAPI with a Flask app."""
        if not hasattr(app, "add_url_rule"):
            raise RuntimeError("ConnectionAPI requires a valid Flask app instance.")
        self.app = app

    def _create_connection_pool(self):
        """Create a PostgreSQL connection pool with security features."""
        try:
            # Get database credentials from environment
            db_host = os.getenv("POSTGRES_HOST", "localhost")
            db_port = os.getenv("POSTGRES_PORT", "5432")
            db_name = os.getenv("POSTGRES_DB", "postgres")
            db_user = os.getenv("POSTGRES_USER", "postgres")
            
            # Get password from file or environment variable
            password_file = os.getenv("POSTGRES_PASSWORD_FILE")
            if password_file and os.path.exists(password_file):
                with open(password_file, 'r') as f:
                    db_password = f.read().strip()
            else:
                db_password = os.getenv("POSTGRES_PASSWORD")
            
            if not db_password:
                raise ValueError("Database password not found in file or environment variable")

            # Connection parameters with security features
            connection_params = {
                "host": db_host,
                "port": db_port,
                "database": db_name,
                "user": db_user,
                "password": db_password,
                "connect_timeout": Config.DB_CONNECT_TIMEOUT,
                "keepalives": Config.DB_KEEPALIVES,
                "keepalives_idle": Config.DB_KEEPALIVES_IDLE,
                "keepalives_interval": Config.DB_KEEPALIVES_INTERVAL,
                "keepalives_count": Config.DB_KEEPALIVES_COUNT,
                "application_name": "template_three_app"
            }

            # Add SSL if enabled
            if Config.USE_SSL:
                connection_params["sslmode"] = "require"

            # Create connection pool with security features
            pool = psycopg2.pool.SimpleConnectionPool(
                minconn=Config.DB_POOL_MIN_CONN,
                maxconn=Config.DB_POOL_MAX_CONN,
                **connection_params
            )

            # Test the pool with a health check
            with pool.getconn() as conn:
                with conn.cursor() as cur:
                    # Set statement timeout for this connection
                    cur.execute(f"SET statement_timeout = {Config.DB_STATEMENT_TIMEOUT}")
                    cur.execute("SELECT 1")
                    result = cur.fetchone()
                    if not result or result[0] != 1:
                        raise RuntimeError("Health check failed")

            custom_log(f"✅ Database connection pool created successfully with security features. Pool size: {Config.DB_POOL_MIN_CONN}-{Config.DB_POOL_MAX_CONN}")
            return pool

        except Exception as e:
            custom_log(f"❌ Error creating connection pool: {e}")
            raise RuntimeError(f"Failed to create database connection pool: {str(e)}")

    def get_connection(self):
        """Get a connection from the pool with retry logic and state tracking."""
        retry_count = 0
        last_error = None

        while retry_count < Config.DB_RETRY_COUNT:
            try:
                # Check if pool exists, if not create it
                if not self.connection_pool:
                    self.connection_pool = self._create_connection_pool()

                # Get connection from pool with timeout
                conn = self.connection_pool.getconn()
                if not conn:
                    raise RuntimeError("Failed to get connection from pool")

                # Set statement timeout for this connection
                with conn.cursor() as cur:
                    cur.execute(f"SET statement_timeout = {Config.DB_STATEMENT_TIMEOUT}")

                # Track connection state in Redis
                connection_id = id(conn)
                connection_state = {
                    "created_at": time.time(),
                    "status": "active",
                    "statement_timeout": Config.DB_STATEMENT_TIMEOUT,
                    "last_used": time.time()
                }
                
                # Cache connection state with expiration
                self.redis_manager.set(
                    f"connection:{connection_id}",
                    connection_state,
                    expire=Config.DB_KEEPALIVES_IDLE * 2
                )

                custom_log(f"✅ Got connection from pool (ID: {connection_id})")
                return conn

            except (psycopg2.OperationalError, RuntimeError) as e:
                last_error = e
                retry_count += 1
                custom_log(f"Connection attempt {retry_count} failed: {str(e)}")
                
                if retry_count < Config.DB_RETRY_COUNT:
                    time.sleep(Config.DB_RETRY_DELAY)
                    continue
                
                # If we've exhausted retries, try to recreate the pool
                custom_log("Max retries reached, attempting to recreate connection pool")
                self.connection_pool = self._create_connection_pool()
                retry_count = 0  # Reset retry count after pool recreation
                time.sleep(Config.DB_RETRY_DELAY)

            except Exception as e:
                custom_log(f"Unexpected error getting connection: {str(e)}")
                raise

        # If we get here, all retries failed
        raise RuntimeError(f"Failed to get connection after {Config.DB_RETRY_COUNT} attempts. Last error: {str(last_error)}")

    def return_connection(self, connection):
        """Return a connection to the pool and update Redis cache."""
        if self.connection_pool is not None and connection is not None:
            try:
                conn_id = id(connection)
                # Update connection state in Redis
                self.redis_manager.set(
                    f"connection:{conn_id}",
                    {
                        "status": "returned",
                        "returned_at": str(datetime.now().isoformat())
                    },
                    expire=Config.DB_KEEPALIVES_IDLE * 2
                )
                
                self.connection_pool.putconn(connection)
                custom_log(f"✅ Returned connection to pool (ID: {conn_id})")
            except Exception as e:
                custom_log(f"❌ Error returning connection to pool: {e}")

    def fetch_from_db(self, query, params=None, as_dict=False):
        """Execute a SELECT query and cache results in Redis."""
        connection = None
        try:
            # Validate query type and format
            if not query or not isinstance(query, str):
                raise ValueError("Invalid query format")
                
            # Validate query is SELECT
            if not query.strip().upper().startswith('SELECT'):
                raise ValueError("Only SELECT queries are allowed in fetch_from_db")
                
            # Validate parameters
            if params is not None:
                if not isinstance(params, (tuple, list)):
                    raise ValueError("Parameters must be a tuple or list")
                if any(not isinstance(p, (str, int, float, bool, type(None))) for p in params):
                    raise ValueError("Invalid parameter types")

            # Validate query size
            if not self.error_handler.validate_query_size(query, params):
                error_response = self.error_handler.handle_validation_error(
                    ValueError("Query size exceeds maximum allowed size")
                )
                raise ValueError(error_response["error"])

            connection = self.get_connection()
            cursor = connection.cursor(cursor_factory=psycopg2.extras.DictCursor if as_dict else None)
            
            # Create cache key based on query and parameters
            cache_key = f"query:{hash(query + str(params or ()))}"
            
            # Try to get from Redis cache first
            try:
                cached_result = self.redis_manager.get(cache_key)
                if cached_result:
                    custom_log(f"✅ Retrieved query result from Redis cache")
                    # Convert list of lists back to list of tuples for non-dict results
                    if not as_dict:
                        cached_result = [tuple(row) for row in cached_result]
                    return cached_result
            except Exception as e:
                error_response = self.error_handler.handle_redis_error(e, "cache_get")
                custom_log(f"⚠️ Cache retrieval failed: {error_response['error']}")
            
            cursor.execute(query, params or ())
            result = cursor.fetchall()
            cursor.close()
            
            # Convert to dict if requested
            if as_dict:
                processed_result = [dict(row) for row in result]
            else:
                processed_result = [tuple(row) for row in result]
            
            # Validate result size before caching
            MAX_RESULT_SIZE = 1024 * 1024  # 1MB
            result_size = len(json.dumps(processed_result))
            if result_size > MAX_RESULT_SIZE:
                custom_log("⚠️ Query result too large for caching")
                return processed_result
            
            # Cache the result
            try:
                self.redis_manager.set(cache_key, processed_result, expire=300)  # Cache for 5 minutes
                custom_log(f"✅ Cached query result in Redis")
            except Exception as e:
                error_response = self.error_handler.handle_redis_error(e, "cache_set")
                custom_log(f"⚠️ Cache storage failed: {error_response['error']}")
            
            return processed_result
            
        except Exception as e:
            error_response = self.error_handler.handle_database_error(e, "fetch_from_db")
            custom_log(f"❌ Error executing query: {error_response['error']}")
            raise ValueError(error_response["error"])
        finally:
            if connection:
                self.return_connection(connection)

    def execute_query(self, query, params=None):
        """Execute a non-SELECT query and invalidate relevant caches."""
        connection = None
        try:
            # Validate query size
            if not self.error_handler.validate_query_size(query, params):
                error_response = self.error_handler.handle_validation_error(
                    ValueError("Query size exceeds maximum allowed size")
                )
                raise ValueError(error_response["error"])

            connection = self.get_connection()
            cursor = connection.cursor()
            cursor.execute(query, params or ())
            connection.commit()
            cursor.close()
            
            # Invalidate relevant caches
            self._invalidate_caches(query)
            
        except Exception as e:
            if connection:
                connection.rollback()
            error_response = self.error_handler.handle_database_error(e, "execute_query")
            custom_log(f"❌ Error executing query: {error_response['error']}")
            raise ValueError(error_response["error"])
        finally:
            if connection:
                self.return_connection(connection)

    def initialize_database(self):
        """Ensure required tables exist in the database."""
        custom_log("⚙️ Initializing database tables...")
        self._create_users_table()
        custom_log("✅ Database tables verified.")

    def _create_users_table(self):
        """Create users table with proper constraints and indexes."""
        query = """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        """
        self.execute_query(query)

    def get_user_by_email(self, email):
        """Get user by email with proper error handling."""
        query = "SELECT id, username, password, email FROM users WHERE email = %s;"
        return self.fetch_from_db(query, (email,), as_dict=True)

    def create_user(self, username, email, hashed_password):
        """Create a new user with proper error handling."""
        query = "INSERT INTO users (username, email, password) VALUES (%s, %s, %s);"
        self.execute_query(query, (username, email, hashed_password))
        return self.get_user_by_email(email)

    def delete_user(self, user_id):
        """Delete a user and all associated data with proper error handling."""
        # Delete guessed names
        self.execute_query("DELETE FROM guessed_names WHERE user_id = %s", (user_id,))
        # Delete user progress
        self.execute_query("DELETE FROM user_category_progress WHERE user_id = %s", (user_id,))
        # Delete the user
        self.execute_query("DELETE FROM users WHERE id = %s", (user_id,))
        # Invalidate any cached user data
        self._invalidate_caches(f"user:{user_id}")

    def register_route(self, path, view_func, methods=None, endpoint=None):
        """Register a route with the Flask app."""
        if self.app is None:
            raise RuntimeError("ConnectionAPI must be initialized with a Flask app before registering routes.")

        methods = methods or ["GET"]
        endpoint = endpoint or view_func.__name__

        self.app.add_url_rule(path, endpoint=endpoint, view_func=view_func, methods=methods)
        self.registered_routes.append((path, methods))
        custom_log(f"🌐 Route registered: {path} [{', '.join(methods)}] as '{endpoint}'")

    def dispose(self):
        """Clean up registered routes and resources."""
        custom_log("🔄 Disposing ConnectionAPI...")
        self.registered_routes.clear()
        if self.connection_pool:
            self.connection_pool.closeall()
            custom_log("🔌 Database connection pool closed.")
        if self.redis_manager:
            self.redis_manager.dispose()
            custom_log("🔌 Redis connections closed.")

    def cache_user_data(self, user_id, data):
        """Cache user data in Redis with encryption."""
        # Validate user_id
        if not isinstance(user_id, (int, str)) or not str(user_id).isdigit():
            raise ValueError("Invalid user_id")
        
        # Validate data structure
        if not isinstance(data, dict):
            raise ValueError("Data must be a dictionary")
        
        # Validate required fields
        required_fields = ['id', 'username', 'email']
        if not all(field in data for field in required_fields):
            raise ValueError("Missing required user data fields")
        
        # Validate data size
        data_size = len(json.dumps(data))
        if data_size > 1024 * 1024:  # 1MB limit
            raise ValueError("User data too large for caching")
        
        # Validate data types
        if not isinstance(data['id'], (int, str)) or not str(data['id']).isdigit():
            raise ValueError("Invalid user ID in data")
        if not isinstance(data['username'], str) or len(data['username']) > 50:
            raise ValueError("Invalid username format")
        if not isinstance(data['email'], str) or '@' not in data['email']:
            raise ValueError("Invalid email format")
        
        self.redis_manager.set(f"user:{user_id}", data, expire=3600)  # Cache for 1 hour

    def get_cached_user_data(self, user_id):
        """Get cached user data from Redis with decryption."""
        # Validate user_id
        if not isinstance(user_id, (int, str)) or not str(user_id).isdigit():
            raise ValueError("Invalid user_id")
        
        # Get cached data
        data = self.redis_manager.get(f"user:{user_id}")
        
        # Validate cached data structure
        if data:
            if not isinstance(data, dict):
                self.redis_manager.delete(f"user:{user_id}")  # Clear invalid data
                return None
                
            # Validate required fields
            required_fields = ['id', 'username', 'email']
            if not all(field in data for field in required_fields):
                self.redis_manager.delete(f"user:{user_id}")  # Clear invalid data
                return None
                
            # Validate data types
            if not isinstance(data['id'], (int, str)) or not str(data['id']).isdigit():
                self.redis_manager.delete(f"user:{user_id}")  # Clear invalid data
                return None
        
        return data

    @property
    def redis(self):
        """Access Redis manager methods directly."""
        return self.redis_manager

    def _invalidate_caches(self, query):
        """Invalidate relevant Redis caches based on the query."""
        query = query.lower()
        
        # Invalidate query cache
        cache_key = f"query:{hash(query)}"
        self.redis_manager.delete(cache_key)
        
        # Invalidate user data cache if user-related query
        if "users" in query:
            pattern = "user:*"
            keys = self.redis_manager.redis.keys(pattern)
            for key in keys:
                self.redis_manager.delete(key)
        
        custom_log("✅ Relevant caches invalidated")

    def _create_session(self, user_id, session_data=None):
        """Create a new session with JWT support."""
        try:
            session_id = str(uuid.uuid4())
            current_time = time.time()
            
            # Get existing sessions
            sessions = self.redis_manager.get(f"user_sessions:{user_id}", default=[])
            if not isinstance(sessions, list):
                sessions = []
            
            # Check concurrent sessions limit
            if len(sessions) >= self.max_concurrent_sessions:
                # Remove oldest session
                sessions.pop(0)
            
            # Create new session
            new_session = {
                "session_id": session_id,
                "created_at": current_time,
                "last_active": current_time,
                "data": session_data or {}
            }
            
            # Add new session
            sessions.append(new_session)
            
            # Store updated sessions
            self.redis_manager.set(
                f"user_sessions:{user_id}",
                sessions,
                expire=self.session_timeout
            )
            
            return session_id
            
        except Exception as e:
            custom_log(f"❌ Error creating session: {e}")
            return None

    def _validate_session(self, user_id, session_id):
        """Validate a session with JWT support."""
        try:
            sessions = self.redis_manager.get(f"user_sessions:{user_id}", default=[])
            if not isinstance(sessions, list):
                return False
                
            # Find session
            session = next((s for s in sessions if s["session_id"] == session_id), None)
            if not session:
                return False
                
            # Check session timeout
            if time.time() - session["last_active"] > self.session_timeout:
                self._remove_session(user_id, session_id)
                return False
                
            # Update last active time
            session["last_active"] = time.time()
            self.redis_manager.set(
                f"user_sessions:{user_id}",
                sessions,
                expire=self.session_timeout
            )
            
            return True
            
        except Exception as e:
            custom_log(f"❌ Error validating session: {e}")
            return False

    def create_user_tokens(self, user_data):
        """Create access and refresh tokens for a user."""
        try:
            # Create access token
            access_token = self.jwt_manager.create_token(
                user_data,
                token_type=TokenType.ACCESS,
                expires_in=3600  # 1 hour
            )
            
            # Create refresh token
            refresh_token = self.jwt_manager.create_token(
                user_data,
                token_type=TokenType.REFRESH,
                expires_in=604800  # 7 days
            )
            
            # Store tokens in Redis
            self.redis_manager.set(
                f"user_tokens:{user_data['id']}",  # Changed from user_id to id
                {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "created_at": time.time()
                },
                expire=604800  # 7 days
            )

            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer"
            }

        except Exception as e:
            custom_log(f"❌ Error creating user tokens: {e}")
            raise

    def validate_access_token(self, token):
        """Validate an access token."""
        try:
            return self.jwt_manager.validate_token(token, TokenType.ACCESS)
        except Exception as e:
            custom_log(f"❌ Error validating access token: {e}")
            return None

    def refresh_user_tokens(self, refresh_token):
        """Refresh user tokens using a valid refresh token."""
        try:
            # Validate refresh token
            payload = self.jwt_manager.validate_token(refresh_token, TokenType.REFRESH)
            if not payload:
                return None
                
            user_id = payload.get('id')  # Changed from user_id to id
            if not user_id:
                return None
                
            # Get user data from Redis
            user_data = self.redis_manager.get(f"user:{user_id}")
            if not user_data:
                return None
                
            # Create new tokens
            return self.create_user_tokens(user_data)

        except Exception as e:
            custom_log(f"❌ Error refreshing user tokens: {e}")
            return None

    def revoke_user_tokens(self, user_id):
        """Revoke all tokens for a user."""
        try:
            # Delete tokens from Redis
            self.redis_manager.delete(f"user_tokens:{user_id}")
            return True
        except Exception as e:
            custom_log(f"❌ Error revoking user tokens: {e}")
            return False

    def _remove_session(self, user_id, session_id):
        """Remove a session from the user's session list."""
        sessions = self.redis_manager.get(f"user_sessions:{user_id}", default=[])
        if isinstance(sessions, list):
            sessions = [s for s in sessions if s["session_id"] != session_id]
            self.redis_manager.set(
                f"user_sessions:{user_id}",
                sessions,
                expire=self.session_timeout
            )

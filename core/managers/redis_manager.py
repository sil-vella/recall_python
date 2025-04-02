import os
import redis
from redis import Redis
from redis.connection import ConnectionPool
from typing import Optional, Any, Union, List
from tools.logger.custom_logging import custom_log
import hashlib
from utils.config.config import Config
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class RedisManager:
    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(RedisManager, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not RedisManager._initialized:
            self.redis = None
            self.connection_pool = None
            self._initialize_connection_pool()
            self._setup_encryption()
            RedisManager._initialized = True

    def _setup_encryption(self):
        """Set up encryption key using PBKDF2."""
        # Use Redis password as salt for key derivation
        salt = os.getenv("REDIS_PASSWORD", "").encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(os.getenv("REDIS_PASSWORD", "").encode()))
        self.cipher_suite = Fernet(key)

    def _initialize_connection_pool(self):
        """Initialize Redis connection pool with security settings."""
        try:
            redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
            
            # Get Redis password from file if specified
            redis_password = ""
            redis_password_file = os.getenv("REDIS_PASSWORD_FILE")
            if redis_password_file and os.path.exists(redis_password_file):
                with open(redis_password_file, 'r') as f:
                    redis_password = f.read().strip()
            else:
                redis_password = os.getenv("REDIS_PASSWORD", "")
            
            # Parse Redis URL to get host and port
            redis_host = os.getenv("REDIS_HOST", "localhost")
            redis_port = int(os.getenv("REDIS_PORT", "6379"))
            
            # Base connection pool settings
            pool_settings = {
                'host': redis_host,
                'port': redis_port,
                'password': redis_password,
                'decode_responses': True,
                'socket_timeout': 5,
                'socket_connect_timeout': 5,
                'retry_on_timeout': True
            }
            
            # Add SSL settings only if SSL is enabled
            if Config.REDIS_USE_SSL:
                pool_settings.update({
                    'ssl': True,
                    'ssl_cert_reqs': Config.REDIS_SSL_VERIFY_MODE
                })
            
            # Create connection pool
            self.connection_pool = redis.ConnectionPool(**pool_settings)
            
            # Test connection
            self.redis = redis.Redis(connection_pool=self.connection_pool)
            self.redis.ping()
            custom_log("✅ Redis connection pool initialized successfully")
        except Exception as e:
            custom_log(f"❌ Error initializing Redis connection pool: {e}")
            raise

    def _generate_secure_key(self, prefix, *args):
        """Generate a cryptographically secure cache key."""
        # Combine all arguments into a single string
        key_data = ':'.join(str(arg) for arg in args)
        
        # Use SHA-256 for key generation
        key_hash = hashlib.sha256(key_data.encode()).hexdigest()
        
        # Add prefix and hash to create final key
        return f"{prefix}:{key_hash}"

    def _encrypt_data(self, data):
        """Encrypt data before storing in Redis."""
        if isinstance(data, (dict, list)):
            data = json.dumps(data)
        return self.cipher_suite.encrypt(data.encode()).decode()

    def _decrypt_data(self, encrypted_data):
        """Decrypt data retrieved from Redis."""
        try:
            decrypted = self.cipher_suite.decrypt(encrypted_data.encode())
            return json.loads(decrypted.decode())
        except:
            return None

    def get(self, key, *args):
        """Get value from Redis with secure key generation."""
        try:
            secure_key = self._generate_secure_key(key, *args)
            value = self.redis.get(secure_key)
            if value:
                return self._decrypt_data(value)
            return None
        except Exception as e:
            custom_log(f"❌ Error getting value from Redis: {e}")
            return None

    def set(self, key, value, expire=None, *args):
        """Set value in Redis with secure key generation and encryption."""
        try:
            secure_key = self._generate_secure_key(key, *args)
            encrypted_value = self._encrypt_data(value)
            if expire:
                self.redis.setex(secure_key, expire, encrypted_value)
            else:
                self.redis.set(secure_key, encrypted_value)
            return True
        except Exception as e:
            custom_log(f"❌ Error setting value in Redis: {e}")
            return False

    def delete(self, key, *args):
        """Delete value from Redis with secure key generation."""
        try:
            secure_key = self._generate_secure_key(key, *args)
            self.redis.delete(secure_key)
            return True
        except Exception as e:
            custom_log(f"❌ Error deleting value from Redis: {e}")
            return False

    def exists(self, key, *args):
        """Check if key exists in Redis with secure key generation."""
        try:
            secure_key = self._generate_secure_key(key, *args)
            return self.redis.exists(secure_key)
        except Exception as e:
            custom_log(f"❌ Error checking key existence in Redis: {e}")
            return False

    def expire(self, key, seconds, *args):
        """Set expiration for key in Redis with secure key generation."""
        try:
            secure_key = self._generate_secure_key(key, *args)
            return self.redis.expire(secure_key, seconds)
        except Exception as e:
            custom_log(f"❌ Error setting expiration in Redis: {e}")
            return False

    def ttl(self, key, *args):
        """Get time to live for key in Redis with secure key generation."""
        try:
            secure_key = self._generate_secure_key(key, *args)
            return self.redis.ttl(secure_key)
        except Exception as e:
            custom_log(f"❌ Error getting TTL from Redis: {e}")
            return -1

    def incr(self, key, *args):
        """Increment value in Redis with secure key generation."""
        try:
            secure_key = self._generate_secure_key(key, *args)
            return self.redis.incr(secure_key)
        except Exception as e:
            custom_log(f"❌ Error incrementing value in Redis: {e}")
            return None

    def decr(self, key, *args):
        """Decrement value in Redis with secure key generation."""
        try:
            secure_key = self._generate_secure_key(key, *args)
            return self.redis.decr(secure_key)
        except Exception as e:
            custom_log(f"❌ Error decrementing value in Redis: {e}")
            return None

    def hset(self, key, field, value, *args):
        """Set hash field in Redis with secure key generation and encryption."""
        try:
            secure_key = self._generate_secure_key(key, *args)
            encrypted_value = self._encrypt_data(value)
            return self.redis.hset(secure_key, field, encrypted_value)
        except Exception as e:
            custom_log(f"❌ Error setting hash field in Redis: {e}")
            return False

    def hget(self, key, field, *args):
        """Get hash field from Redis with secure key generation and decryption."""
        try:
            secure_key = self._generate_secure_key(key, *args)
            value = self.redis.hget(secure_key, field)
            if value:
                return self._decrypt_data(value)
            return None
        except Exception as e:
            custom_log(f"❌ Error getting hash field from Redis: {e}")
            return None

    def hdel(self, key, field, *args):
        """Delete hash field from Redis with secure key generation."""
        try:
            secure_key = self._generate_secure_key(key, *args)
            return self.redis.hdel(secure_key, field)
        except Exception as e:
            custom_log(f"❌ Error deleting hash field from Redis: {e}")
            return False

    def hgetall(self, key, *args):
        """Get all hash fields from Redis with secure key generation and decryption."""
        try:
            secure_key = self._generate_secure_key(key, *args)
            values = self.redis.hgetall(secure_key)
            return {k: self._decrypt_data(v) for k, v in values.items()}
        except Exception as e:
            custom_log(f"❌ Error getting all hash fields from Redis: {e}")
            return {}

    def lpush(self, key, value, *args):
        """Push value to list in Redis with secure key generation and encryption."""
        try:
            secure_key = self._generate_secure_key(key, *args)
            encrypted_value = self._encrypt_data(value)
            return self.redis.lpush(secure_key, encrypted_value)
        except Exception as e:
            custom_log(f"❌ Error pushing to list in Redis: {e}")
            return False

    def rpush(self, key, value, *args):
        """Push value to end of list in Redis with secure key generation and encryption."""
        try:
            secure_key = self._generate_secure_key(key, *args)
            encrypted_value = self._encrypt_data(value)
            return self.redis.rpush(secure_key, encrypted_value)
        except Exception as e:
            custom_log(f"❌ Error pushing to end of list in Redis: {e}")
            return False

    def lpop(self, key, *args):
        """Pop value from list in Redis with secure key generation and decryption."""
        try:
            secure_key = self._generate_secure_key(key, *args)
            value = self.redis.lpop(secure_key)
            if value:
                return self._decrypt_data(value)
            return None
        except Exception as e:
            custom_log(f"❌ Error popping from list in Redis: {e}")
            return None

    def rpop(self, key, *args):
        """Pop value from end of list in Redis with secure key generation and decryption."""
        try:
            secure_key = self._generate_secure_key(key, *args)
            value = self.redis.rpop(secure_key)
            if value:
                return self._decrypt_data(value)
            return None
        except Exception as e:
            custom_log(f"❌ Error popping from end of list in Redis: {e}")
            return None

    def lrange(self, key, start, end, *args):
        """Get range of values from list in Redis with secure key generation and decryption."""
        try:
            secure_key = self._generate_secure_key(key, *args)
            values = self.redis.lrange(secure_key, start, end)
            return [self._decrypt_data(v) for v in values]
        except Exception as e:
            custom_log(f"❌ Error getting range from list in Redis: {e}")
            return []

    def dispose(self):
        """Clean up Redis connections."""
        try:
            if self.connection_pool:
                self.connection_pool.disconnect()
                custom_log("✅ Redis connection pool disposed")
        except Exception as e:
            custom_log(f"❌ Error disposing Redis connection pool: {e}")

    def set_room_size(self, room_id: str, size: int, expire: int = 3600) -> bool:
        """Set room size in Redis without encryption."""
        try:
            key = f"room:size:{room_id}"
            self.redis.set(key, str(size))  # Convert int to string
            if expire:
                self.redis.expire(key, expire)
            custom_log(f"Set room size for {room_id} to {size}")
            return True
        except Exception as e:
            custom_log(f"Error setting room size for {room_id}: {str(e)}")
            return False

    def get_room_size(self, room_id: str) -> int:
        """Get room size from Redis without encryption."""
        try:
            key = f"room:size:{room_id}"
            value = self.redis.get(key)
            size = int(value) if value is not None else 0
            custom_log(f"Got room size for {room_id}: {size}")
            return size
        except Exception as e:
            custom_log(f"Error getting room size from Redis: {str(e)}")
            return 0

    def update_room_size(self, room_id: str, delta: int):
        """Update room size atomically."""
        try:
            key = f"room:size:{room_id}"
            
            # Use Redis transaction for atomicity
            with self.redis.pipeline() as pipe:
                while True:
                    try:
                        # Watch the room size key
                        pipe.watch(key)
                        
                        # Get current size
                        current_size = pipe.get(key)
                        current_size = int(current_size) if current_size else 0
                        
                        # Calculate new size
                        new_size = max(0, current_size + delta)
                        
                        # Update size
                        pipe.multi()
                        if new_size > 0:
                            pipe.set(key, str(new_size))
                            pipe.expire(key, 3600)  # 1 hour expiry
                        else:
                            pipe.delete(key)
                            
                        # Execute transaction
                        pipe.execute()
                        custom_log(f"Updated room {room_id} size from {current_size} to {new_size}")
                        return
                        
                    except Exception as e:
                        custom_log(f"Error in room size update transaction: {str(e)}")
                        continue
                        
        except Exception as e:
            custom_log(f"Error updating room size: {str(e)}")

    def check_and_increment_room_size(self, room_id: str, room_size_limit: int = 100) -> bool:
        """Atomically check and increment room size if under limit."""
        try:
            key = f"room:size:{room_id}"
            
            # Use Redis transaction for atomicity
            with self.redis.pipeline() as pipe:
                while True:
                    try:
                        # Watch the room size key
                        pipe.watch(key)
                        
                        # Get current size
                        current_size = pipe.get(key)
                        current_size = int(current_size) if current_size else 0
                        
                        # Check if we've hit the limit
                        if current_size >= room_size_limit:
                            custom_log(f"Room {room_id} has reached size limit of {room_size_limit}")
                            return False
                            
                        # Increment size
                        pipe.multi()
                        pipe.incr(key)
                        pipe.expire(key, 3600)  # 1 hour expiry
                        
                        # Execute transaction
                        pipe.execute()
                        custom_log(f"Incremented room {room_id} size to {current_size + 1}")
                        return True
                        
                    except Exception as e:
                        custom_log(f"Error in room size transaction: {str(e)}")
                        continue
                        
        except Exception as e:
            custom_log(f"Error checking and incrementing room size: {str(e)}")
            return False

    def reset_room_size(self, room_id: str):
        """Reset room size to 0."""
        try:
            key = f"room:size:{room_id}"
            self.redis.delete(key)
            custom_log(f"Reset room size for {room_id}")
        except Exception as e:
            custom_log(f"Error resetting room size: {str(e)}")

    def cleanup_room_keys(self, room_id: str) -> bool:
        """Clean up all Redis keys related to a room using pattern matching."""
        try:
            # Pattern to match all room-related keys
            pattern = f"ws:room:{room_id}:*"
            cursor = 0
            cleaned = 0
            
            while True:
                cursor, keys = self.redis.scan(cursor, match=pattern, count=100)
                for key in keys:
                    custom_log(f"Found room key: {key}")
                    self.redis.delete(key)
                    cleaned += 1
                    custom_log(f"Deleted room key: {key}")
                    
                if cursor == 0:
                    break
                    
            custom_log(f"Cleaned up {cleaned} keys for room {room_id}")
            return True
            
        except Exception as e:
            custom_log(f"Error cleaning up room keys for {room_id}: {str(e)}")
            return False 
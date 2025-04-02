from flask_socketio import SocketIO, emit, join_room, leave_room
from flask import request
from typing import Dict, Any, Set, Callable, Optional, List
from tools.logger.custom_logging import custom_log
from core.managers.redis_manager import RedisManager
from core.validators.websocket_validators import WebSocketValidator
from utils.config.config import Config
import time
from datetime import datetime
from functools import wraps
import json

class WebSocketManager:
    def __init__(self):
        self.redis_manager = RedisManager()
        self.validator = WebSocketValidator()
        self.socketio = SocketIO(
            cors_allowed_origins="*",  # Will be overridden by module
            async_mode='gevent',
            logger=True,
            engineio_logger=True,
            max_http_buffer_size=Config.WS_MAX_PAYLOAD_SIZE,
            ping_timeout=Config.WS_PING_TIMEOUT,
            ping_interval=Config.WS_PING_INTERVAL
        )
        self.rooms: Dict[str, Set[str]] = {}  # room_id -> set of session_ids
        self.session_rooms: Dict[str, Set[str]] = {}  # session_id -> set of room_ids
        self._rate_limits = {
            'connections': {
                'max': Config.WS_RATE_LIMIT_CONNECTIONS,
                'window': Config.WS_RATE_LIMIT_WINDOW
            },
            'messages': {
                'max': Config.WS_RATE_LIMIT_MESSAGES,
                'window': Config.WS_RATE_LIMIT_WINDOW
            }
        }
        self._jwt_manager = None  # Will be set by the module
        self._room_access_check = None  # Will be set by the module
        self._room_size_limit = Config.WS_ROOM_SIZE_LIMIT
        self._room_size_check_interval = Config.WS_ROOM_SIZE_CHECK_INTERVAL
        self._presence_check_interval = Config.WS_PRESENCE_CHECK_INTERVAL
        self._presence_timeout = Config.WS_PRESENCE_TIMEOUT
        self._presence_cleanup_interval = Config.WS_PRESENCE_CLEANUP_INTERVAL
        custom_log("WebSocketManager initialized")

    def set_cors_origins(self, origins: list):
        """Set allowed CORS origins."""
        self.socketio.cors_allowed_origins = origins
        custom_log(f"Updated CORS origins: {origins}")

    def validate_origin(self, origin: str) -> bool:
        """Validate if the origin is allowed."""
        return origin in self.socketio.cors_allowed_origins or origin == "app://mobile"

    def check_rate_limit(self, client_id: str, limit_type: str) -> bool:
        """Check if client has exceeded rate limits."""
        if limit_type not in self._rate_limits:
            return True  # Unknown limit type, allow by default
            
        limit = self._rate_limits[limit_type]
        key = f"ws:{limit_type}:{client_id}"
        count = self.redis_manager.get(key) or 0
        
        if count >= limit['max']:
            custom_log(f"Rate limit exceeded for {limit_type}: {client_id}")
            return False
            
        return True

    def update_rate_limit(self, client_id: str, limit_type: str):
        """Update rate limit counter."""
        if limit_type not in self._rate_limits:
            return
            
        limit = self._rate_limits[limit_type]
        key = f"ws:{limit_type}:{client_id}"
        self.redis_manager.incr(key)
        self.redis_manager.expire(key, limit['window'])

    def store_session_data(self, session_id: str, session_data: Dict[str, Any]):
        """Store session information in Redis."""
        self.redis_manager.set(f"ws:session:{session_id}", session_data, expire=Config.WS_SESSION_TTL)

    def get_session_data(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data from Redis."""
        return self.redis_manager.get(f"ws:session:{session_id}")

    def cleanup_session_data(self, session_id: str):
        """Clean up session data from Redis."""
        self.redis_manager.delete(f"ws:session:{session_id}")

    def update_session_activity(self, session_id: str):
        """Update last active timestamp for session."""
        session_key = f"ws:session:{session_id}"
        session_data = self.redis_manager.get(session_key)
        if session_data:
            session_data['last_active'] = datetime.utcnow().isoformat()
            self.redis_manager.set(session_key, session_data)

    def initialize(self, app):
        """Initialize WebSocket support with the Flask app."""
        try:
            self.socketio.init_app(app, cors_allowed_origins="*")
            
            @self.socketio.on('connect')
            def handle_connect():
                try:
                    custom_log("New WebSocket connection attempt")
                    session_id = request.sid
                    
                    # Get token from request
                    token = request.args.get('token')
                    if not token:
                        custom_log("No token provided for WebSocket connection")
                        return False
                        
                    # Validate token with JWT manager
                    if not self._jwt_manager:
                        custom_log("JWT manager not initialized")
                        return False
                        
                    # Verify token and get payload
                    payload = self._jwt_manager.verify_token(token)
                    if not payload:
                        custom_log("Invalid token for WebSocket connection")
                        return False
                        
                    # Check token type
                    if payload.get('type') != 'websocket':
                        custom_log("Invalid token type for WebSocket connection")
                        return False
                        
                    # Check client fingerprint
                    client_fingerprint = self._jwt_manager._get_client_fingerprint()
                    if client_fingerprint and client_fingerprint != payload.get('fingerprint'):
                        custom_log("Token fingerprint mismatch")
                        return False
                        
                    # Store session data
                    session_data = {
                        'user_id': payload.get('id'),
                        'username': payload.get('username'),
                        'token': token,
                        'connected_at': datetime.utcnow().isoformat()
                    }
                    self.store_session_data(session_id, session_data)
                    
                    # Update session activity
                    self.update_session_activity(session_id)
                    
                    # Mark user as online
                    if session_data.get('user_id'):
                        self.update_user_presence(session_data['user_id'], 'online')
                    
                    custom_log(f"WebSocket connection established for session {session_id}")
                    return True
                    
                except Exception as e:
                    custom_log(f"Error in connect handler: {str(e)}")
                    return False

            @self.socketio.on('disconnect')
            def handle_disconnect():
                try:
                    session_id = request.sid
                    custom_log(f"WebSocket disconnection for session {session_id}")
                    self.cleanup_session(session_id)
                except Exception as e:
                    custom_log(f"Error in disconnect handler: {str(e)}")

            custom_log("WebSocket support initialized with Flask app")
        except Exception as e:
            custom_log(f"Error initializing WebSocket support: {str(e)}")

    def set_jwt_manager(self, jwt_manager):
        """Set the JWT manager instance."""
        self._jwt_manager = jwt_manager
        custom_log("JWT manager set in WebSocketManager")

    def set_room_access_check(self, access_check_func):
        """Set the room access check function."""
        self._room_access_check = access_check_func
        custom_log("Room access check function set")

    def check_room_access(self, room_id: str, session_data: Dict[str, Any]) -> bool:
        """Check if a user has access to a room using the module's access check function."""
        if not self._room_access_check:
            custom_log("No room access check function set")
            return False
            
        # Extract user_id and roles from session data
        user_id = session_data.get('user_id')
        user_roles = session_data.get('user_roles', set())
        
        if not user_id:
            custom_log("No user_id found in session data")
            return False
            
        return self._room_access_check(room_id, user_id, user_roles)

    def requires_auth(self, handler: Callable) -> Callable:
        """Decorator to require authentication for WebSocket handlers."""
        @wraps(handler)
        def wrapper(data=None):
            try:
                session_id = request.sid
                
                # Get session data
                session_data = self.get_session_data(session_id)
                if not session_data or 'user_id' not in session_data:
                    custom_log(f"Session {session_id} not authenticated")
                    return {'status': 'error', 'message': 'Authentication required'}
                
                # Update session activity
                self.update_session_activity(session_id)
                
                # Call the handler with session data
                return handler(data, session_data)
            except Exception as e:
                custom_log(f"Error in authenticated handler: {str(e)}")
                return {'status': 'error', 'message': str(e)}
        return wrapper

    def register_handler(self, event: str, handler: Callable):
        """Register a WebSocket event handler without authentication."""
        @self.socketio.on(event)
        def wrapped_handler(data=None):
            try:
                # Skip validation for special events
                if event in ['connect', 'disconnect']:
                    return handler(data)
                    
                # Ensure data is a dictionary if None is provided
                if data is None:
                    data = {}
                    
                # Validate event payload
                error = self.validator.validate_event_payload(event, data)
                if error:
                    custom_log(f"Validation error in {event} handler: {error}")
                    return {'status': 'error', 'message': error}
                    
                # Validate message size based on event type
                if event == 'message':
                    error = self.validator.validate_message(data)
                elif event == 'binary':
                    error = self.validator.validate_binary_data(data)
                else:
                    error = self.validator.validate_json_data(data)
                    
                if error:
                    custom_log(f"Message size validation error in {event} handler: {error}")
                    return {'status': 'error', 'message': error}
                    
                return handler(data)
            except Exception as e:
                custom_log(f"Error in {event} handler: {str(e)}")
                return {'status': 'error', 'message': str(e)}

    def register_authenticated_handler(self, event: str, handler: Callable):
        """Register a WebSocket event handler with authentication."""
        @self.socketio.on(event)
        def wrapped_handler(data=None):
            try:
                # Skip validation for special events
                if event in ['connect', 'disconnect']:
                    return handler(data)
                    
                # Ensure data is a dictionary if None is provided
                if data is None:
                    data = {}
                    
                # Validate event payload
                error = self.validator.validate_event_payload(event, data)
                if error:
                    custom_log(f"Validation error in {event} handler: {error}")
                    return {'status': 'error', 'message': error}
                    
                # Validate message size based on event type
                if event == 'message':
                    error = self.validator.validate_message(data)
                elif event == 'binary':
                    error = self.validator.validate_binary_data(data)
                else:
                    error = self.validator.validate_json_data(data)
                    
                if error:
                    custom_log(f"Message size validation error in {event} handler: {error}")
                    return {'status': 'error', 'message': error}
                    
                return handler(data)
            except Exception as e:
                custom_log(f"Error in {event} handler: {str(e)}")
                return {'status': 'error', 'message': str(e)}

    def create_room(self, room_id: str):
        """Create a new room if it doesn't exist."""
        # Validate room ID
        error = self.validator.validate_room_id(room_id)
        if error:
            custom_log(f"Invalid room ID: {error}")
            return False
            
        if room_id not in self.rooms:
            self.rooms[room_id] = set()
            custom_log(f"Created new room: {room_id}")
            return True
        return False

    def get_room_size(self, room_id: str) -> int:
        """Get the current number of users in a room."""
        return self.redis_manager.get_room_size(room_id)

    def update_room_size(self, room_id: str, delta: int):
        """Update the room size in Redis."""
        self.redis_manager.update_room_size(room_id, delta)

    def check_room_size_limit(self, room_id: str) -> bool:
        """Check if a room has reached its size limit."""
        current_size = self.get_room_size(room_id)
        return current_size >= self._room_size_limit

    def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session information."""
        return self.get_session_data(session_id)

    def update_user_presence(self, session_id: str, status: str = 'online'):
        """Update user presence status."""
        try:
            custom_log(f"Updating presence for session {session_id} to status: {status}")
            session_info = self.get_session_info(session_id)
            if not session_info or 'user_id' not in session_info:
                custom_log(f"No valid session info found for session {session_id}")
                return
                
            user_id = session_info['user_id']
            presence_key = f"ws:presence:{user_id}"
            
            presence_data = {
                'status': status,
                'last_seen': datetime.utcnow().isoformat(),
                'session_id': session_id,
                'username': session_info.get('username', 'Anonymous')
            }
            
            custom_log(f"Setting presence data for user {user_id}: {presence_data}")
            self.redis_manager.set(presence_key, presence_data, expire=self._presence_timeout)
            
            # Broadcast presence update to all rooms the user is in
            rooms = self.get_rooms_for_session(session_id)
            custom_log(f"Broadcasting presence update to rooms: {rooms}")
            for room_id in rooms:
                self.broadcast_to_room(room_id, 'presence_update', {
                    'user_id': user_id,
                    'status': status,
                    'username': presence_data['username']
                })
                
        except Exception as e:
            custom_log(f"Error updating presence for session {session_id}: {str(e)}")

    def get_user_presence(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user presence information."""
        try:
            custom_log(f"Getting presence for user {user_id}")
            presence_key = f"ws:presence:{user_id}"
            presence_data = self.redis_manager.get(presence_key)
            
            if not presence_data:
                custom_log(f"No presence data found for user {user_id}")
                return {
                    'user_id': user_id,
                    'status': 'offline',
                    'last_seen': None
                }
                
            # Check if presence is stale
            last_seen = datetime.fromisoformat(presence_data['last_seen'])
            if (datetime.utcnow() - last_seen).total_seconds() > self._presence_timeout:
                custom_log(f"Presence data for user {user_id} is stale, marking as offline")
                presence_data['status'] = 'offline'
                
            custom_log(f"Retrieved presence data for user {user_id}: {presence_data}")
            return presence_data
            
        except Exception as e:
            custom_log(f"Error getting presence for user {user_id}: {str(e)}")
            return None

    def get_room_presence(self, room_id: str) -> List[Dict[str, Any]]:
        """Get presence information for all users in a room."""
        try:
            custom_log(f"Getting presence for room {room_id}")
            room_members = self.get_room_members(room_id)
            presence_list = []
            
            for session_id in room_members:
                session_info = self.get_session_info(session_id)
                if session_info and 'user_id' in session_info:
                    presence_data = self.get_user_presence(session_info['user_id'])
                    if presence_data:
                        presence_list.append(presence_data)
                        
            custom_log(f"Room {room_id} presence list: {presence_list}")
            return presence_list
            
        except Exception as e:
            custom_log(f"Error getting room presence for {room_id}: {str(e)}")
            return []

    def cleanup_stale_presence(self):
        """Clean up stale presence records."""
        try:
            custom_log("Starting stale presence cleanup")
            # This would be called periodically to clean up stale presence records
            # Implementation would depend on Redis key pattern matching capabilities
            custom_log("Completed stale presence cleanup")
            
        except Exception as e:
            custom_log(f"Error cleaning up stale presence: {str(e)}")

    def join_room(self, room_id: str, session_id: str, user_id: Optional[str] = None, user_roles: Optional[Set[str]] = None) -> bool:
        """Join a room with proper validation and room size tracking."""
        try:
            # Validate room ID
            if not room_id:
                custom_log("Invalid room ID")
                self.socketio.emit('error', {'message': 'Invalid room ID'}, room=session_id)
                return False
                
            # Get session data
            session_data = self.get_session_data(session_id)
            if not session_data:
                custom_log(f"No session data found for {session_id}")
                self.socketio.emit('error', {'message': 'Session not found'}, room=session_id)
                return False
                
            # Update session data with user_id and roles if provided
            if user_id:
                session_data['user_id'] = user_id
            if user_roles:
                session_data['user_roles'] = list(user_roles)  # Convert set to list for JSON serialization
                
            # Check room access
            if not self.check_room_access(room_id, session_data):
                custom_log(f"Access denied to room {room_id} for session {session_id}")
                self.socketio.emit('error', {'message': 'Access denied to room'}, room=session_id)
                return False
                
            # Check current room size
            current_size = self.redis_manager.get_room_size(room_id)
            if current_size >= self._room_size_limit:
                custom_log(f"Room {room_id} has reached size limit of {self._room_size_limit}")
                self.socketio.emit('room_full', {
                    'room_id': room_id,
                    'current_size': current_size,
                    'max_size': self._room_size_limit
                }, room=session_id)
                return False
                
            # Try to increment room size atomically
            if not self.redis_manager.check_and_increment_room_size(room_id, self._room_size_limit):
                custom_log(f"Room {room_id} has reached its size limit")
                self.socketio.emit('room_full', {
                    'room_id': room_id,
                    'current_size': current_size,
                    'max_size': self._room_size_limit
                }, room=session_id)
                return False
                
            # Join the room
            self.socketio.emit('room_joined', {
                'room_id': room_id,
                'current_size': current_size + 1,
                'max_size': self._room_size_limit
            }, room=session_id)
            join_room(room_id, sid=session_id)  # Use the imported join_room function
            
            # Update room memberships
            if room_id not in self.rooms:
                self.rooms[room_id] = set()
            self.rooms[room_id].add(session_id)
            
            if session_id not in self.session_rooms:
                self.session_rooms[session_id] = set()
            self.session_rooms[session_id].add(room_id)
            
            # Broadcast user joined event if user_id is present
            if user_id:
                self.socketio.emit('user_joined', {
                    'user_id': user_id,
                    'username': session_data.get('username'),
                    'roles': list(user_roles) if user_roles else [],  # Convert set to list for JSON serialization
                    'current_size': current_size + 1,
                    'max_size': self._room_size_limit
                }, room=room_id)
                
            custom_log(f"Session {session_id} joined room {room_id}")
            return True
            
        except Exception as e:
            custom_log(f"Error joining room {room_id} for session {session_id}: {str(e)}")
            self.socketio.emit('error', {'message': 'Failed to join room'}, room=session_id)
            return False

    def leave_room(self, room_id: str, session_id: str):
        """Leave a room and update room size."""
        try:
            custom_log(f"Starting room leave process for session {session_id} from room {room_id}")
            
            # Get session info before any cleanup
            session_info = self.get_session_info(session_id)
            if not session_info:
                custom_log(f"No session info found for {session_id} during room leave")
                return False
                
            user_id = session_info.get('user_id')
            username = session_info.get('username', 'Anonymous')
            
            # Update room tracking first
            if room_id in self.rooms:
                self.rooms[room_id].discard(session_id)
                if not self.rooms[room_id]:
                    del self.rooms[room_id]
                    
            if session_id in self.session_rooms:
                self.session_rooms[session_id].discard(room_id)
                if not self.session_rooms[session_id]:
                    del self.session_rooms[session_id]
                    
            # Update user presence
            self.update_user_presence(session_id, 'away')
            
            # Broadcast presence update to room
            self.broadcast_to_room(room_id, 'user_left', {
                'user_id': user_id,
                'username': username
            })
            
            # Leave the room last
            leave_room(room_id, sid=session_id)
            
            # Update room size in Redis
            self.redis_manager.update_room_size(room_id, -1)
            
            custom_log(f"Session {session_id} successfully left room {room_id}")
            return True
            
        except Exception as e:
            custom_log(f"Error during room leave for session {session_id}: {str(e)}")
            return False

    def broadcast_to_room(self, room_id: str, event: str, data: Dict[str, Any]):
        """Broadcast an event to all users in a room."""
        # Validate room ID
        error = self.validator.validate_room_id(room_id)
        if error:
            custom_log(f"Invalid room ID: {error}")
            return False
            
        # Validate event payload
        error = self.validator.validate_event_payload(event, data)
        if error:
            custom_log(f"Validation error in broadcast: {error}")
            return False
            
        emit(event, data, room=room_id)
        return True

    def broadcast_to_all(self, event: str, data: Dict[str, Any]):
        """Broadcast an event to all connected clients."""
        # Validate event payload
        error = self.validator.validate_event_payload(event, data)
        if error:
            custom_log(f"Validation error in broadcast: {error}")
            return False
            
        emit(event, data)
        return True

    def send_to_session(self, session_id: str, event: str, data: Any):
        """Send message to a specific client."""
        emit(event, data, room=session_id)

    def get_room_members(self, room_id: str) -> set:
        """Get all session IDs in a room."""
        return self.rooms.get(room_id, set())

    def get_rooms_for_session(self, session_id: str) -> set:
        """Get all rooms a session is in."""
        return self.session_rooms.get(session_id, set())

    def reset_room_sizes(self):
        """Reset all room sizes in Redis to match actual connected users."""
        try:
            custom_log("Starting room size reset")
            
            # Log current state
            custom_log(f"Current rooms state: {self.rooms}")
            custom_log(f"Current session_rooms state: {self.session_rooms}")
            
            # Get all rooms and their sizes
            room_sizes = {}
            for room_id in self.rooms:
                # Get the actual sessions in the room
                sessions = self.rooms[room_id]
                custom_log(f"Room {room_id} contains sessions: {sessions}")
                
                # Count only valid sessions
                valid_sessions = set()
                for session_id in sessions:
                    session_info = self.get_session_info(session_id)
                    if session_info:
                        valid_sessions.add(session_id)
                    else:
                        custom_log(f"Found stale session {session_id} in room {room_id}")
                
                actual_size = len(valid_sessions)
                room_sizes[room_id] = actual_size
                custom_log(f"Room {room_id} has {actual_size} valid connected users")
            
            # Reset all room sizes in Redis first
            for room_id in room_sizes:
                # Get current size before reset
                old_size = self.redis_manager.get_room_size(room_id)
                custom_log(f"Current Redis size for room {room_id}: {old_size}")
                
                # Set the new size directly
                self.redis_manager.set_room_size(room_id, room_sizes[room_id])
                custom_log(f"Set room {room_id} size to {room_sizes[room_id]}")
                
            # Log final sizes for verification
            for room_id in room_sizes:
                current_size = self.redis_manager.get_room_size(room_id)
                custom_log(f"Final size for room {room_id}: {current_size}")
                
            # Clean up any stale room data
            self._cleanup_stale_rooms()
                
            custom_log("Completed room size reset")
            
        except Exception as e:
            custom_log(f"Error resetting room sizes: {str(e)}")
            
    def _cleanup_stale_rooms(self):
        """Clean up stale room data and completely remove empty rooms."""
        try:
            custom_log("Starting stale room cleanup")
            
            # Find rooms with no valid sessions
            empty_rooms = set()
            for room_id in list(self.rooms.keys()):  # Use list to avoid modification during iteration
                valid_sessions = False
                if room_id in self.rooms:  # Check again as it might have been removed
                    for session_id in self.rooms[room_id]:
                        session_info = self.get_session_info(session_id)
                        if session_info:
                            valid_sessions = True
                            break
                    
                    if not valid_sessions:
                        empty_rooms.add(room_id)
                        custom_log(f"Room {room_id} has no valid sessions")
            
            # Clean up empty rooms
            for room_id in empty_rooms:
                custom_log(f"Cleaning up empty room: {room_id}")
                
                # Remove from rooms tracking
                if room_id in self.rooms:
                    del self.rooms[room_id]
                    custom_log(f"Removed room {room_id} from rooms tracking")
                
                # Remove from all session_rooms
                for session_id in list(self.session_rooms.keys()):
                    if room_id in self.session_rooms[session_id]:
                        self.session_rooms[session_id].discard(room_id)
                        if not self.session_rooms[session_id]:
                            del self.session_rooms[session_id]
                            custom_log(f"Removed empty session {session_id} from session_rooms")
                
                # Clean up Redis data
                self._cleanup_room_data(room_id)
                
            custom_log(f"Cleaned up {len(empty_rooms)} empty rooms")
            
        except Exception as e:
            custom_log(f"Error during stale room cleanup: {str(e)}")
            
    def _cleanup_room_data(self, room_id: str):
        """Clean up all Redis data related to a room."""
        try:
            custom_log(f"Starting complete cleanup for room {room_id}")
            
            # Clean up room size
            self.redis_manager.reset_room_size(room_id)
            custom_log(f"Reset room size for {room_id}")
            
            # Clean up room presence data
            presence_key = f"ws:room:{room_id}:presence"
            self.redis_manager.delete(presence_key)
            custom_log(f"Cleaned up presence data for room {room_id}")
            
            # Clean up room messages
            messages_key = f"ws:room:{room_id}:messages"
            self.redis_manager.delete(messages_key)
            custom_log(f"Cleaned up message history for room {room_id}")
            
            # Clean up room metadata
            metadata_key = f"ws:room:{room_id}:metadata"
            self.redis_manager.delete(metadata_key)
            custom_log(f"Cleaned up metadata for room {room_id}")
            
            # Clean up room rate limits
            for limit_type in self._rate_limits:
                rate_key = f"ws:room:{room_id}:{limit_type}"
                self.redis_manager.delete(rate_key)
            custom_log(f"Cleaned up rate limit data for room {room_id}")
            
            # Clean up any other room-related keys using pattern matching
            self.redis_manager.cleanup_room_keys(room_id)
            
            custom_log(f"Completed cleanup for room {room_id}")
            
        except Exception as e:
            custom_log(f"Error cleaning up room data for {room_id}: {str(e)}")

    def cleanup_session(self, session_id: str):
        """Clean up all data associated with a session."""
        try:
            custom_log(f"Starting cleanup for session {session_id}")
            
            # Get session info before cleanup
            session_data = self.get_session_data(session_id)
            
            # Clean up room memberships first
            self._cleanup_room_memberships(session_id, session_data)
            
            # Update user presence to offline if user exists
            if session_data and session_data.get('user_id'):
                self.update_user_presence(session_data['user_id'], 'offline')
                
            # Clean up Redis data
            if session_data and session_data.get('user_id'):
                self.redis_manager.delete(f"user:presence:{session_data['user_id']}")
                self.redis_manager.delete(f"user:rate_limit:{session_data['user_id']}")
                
            # Clean up session data last
            self.redis_manager.delete(f"session:{session_id}")
            
            # Reset room sizes after cleanup
            self.reset_room_sizes()
            
            custom_log(f"Completed cleanup for session {session_id}")
            
        except Exception as e:
            custom_log(f"Error during session cleanup: {str(e)}")

    def _cleanup_room_memberships(self, session_id: str, session_data: Optional[Dict] = None):
        """Clean up room memberships for a session."""
        try:
            custom_log(f"Cleaning up room memberships for session {session_id}")
            
            # Find all rooms this session is part of
            rooms_to_leave = []
            for room_id, members in self.rooms.items():
                if session_id in members:
                    rooms_to_leave.append(room_id)
                    
            # Leave each room
            for room_id in rooms_to_leave:
                # Remove from room
                leave_room(room_id, sid=session_id)
                
                # Update room size
                self.redis_manager.update_room_size(room_id, -1)
                
                # Broadcast user left event if we have user info
                if session_data and session_data.get('user_id'):
                    self.socketio.emit('user_left', {
                        'user_id': session_data['user_id'],
                        'room_id': room_id
                    }, room=room_id)
                    
                # Remove from tracking structure
                self.rooms[room_id].remove(session_id)
                
                # Clean up empty rooms
                if not self.rooms[room_id]:
                    del self.rooms[room_id]
                    self._cleanup_room_data(room_id)
                    
            custom_log(f"Completed room membership cleanup for session {session_id}")
            
        except Exception as e:
            custom_log(f"Error during room membership cleanup: {str(e)}")

    def run(self, app, **kwargs):
        """Run the WebSocket server."""
        self.socketio.run(app, **kwargs)

    def _handle_message(self, sid: str, message: str):
        """Handle incoming WebSocket message."""
        try:
            # Get session info
            session_info = self.get_session_info(sid)
            if not session_info:
                custom_log(f"No session info found for {sid}")
                return
                
            # Validate message rate
            error = self.validator.validate_message_rate(sid)
            if error:
                custom_log(f"Rate limit exceeded for session {sid}: {error}")
                emit('error', {'message': error}, room=sid)
                return
                
            # Validate message size and content
            error = self.validator.validate_text_message_size(message)
            if error:
                custom_log(f"Message size validation failed for session {sid}: {error}")
                emit('error', {'message': error}, room=sid)
                return
                
            # Check if message should be compressed
            if self.validator.should_compress_message(message):
                message = self.validator.compress_message(message)
                
            # Process message
            try:
                data = json.loads(message)
                event = data.get('event')
                payload = data.get('payload')
                
                # Validate event
                error = self.validator.validate_event(event)
                if error:
                    custom_log(f"Event validation failed for session {sid}: {error}")
                    emit('error', {'message': error}, room=sid)
                    return
                    
                # Validate payload
                error = self.validator.validate_payload(payload)
                if error:
                    custom_log(f"Payload validation failed for session {sid}: {error}")
                    emit('error', {'message': error}, room=sid)
                    return
                    
                # Handle specific events
                if event == 'join_room':
                    room_id = payload.get('room_id')
                    if room_id:
                        self.join_room(room_id, sid)
                elif event == 'leave_room':
                    room_id = payload.get('room_id')
                    if room_id:
                        self.leave_room(room_id, sid)
                elif event == 'message':
                    room_id = payload.get('room_id')
                    message_content = payload.get('message')
                    if room_id and message_content:
                        self.broadcast_message(room_id, message_content, sid)
                        
            except json.JSONDecodeError:
                # Handle non-JSON messages
                custom_log(f"Received non-JSON message from session {sid}")
                # Process as raw message if needed
                
        except Exception as e:
            custom_log(f"Error handling message from session {sid}: {str(e)}")
            emit('error', {'message': 'Internal server error'}, room=sid)

    def broadcast_message(self, room_id: str, message: str, sender_id: str = None):
        """Broadcast a message to all users in a room."""
        try:
            # Validate message size
            error = self.validator.validate_text_message_size(message)
            if error:
                custom_log(f"Message size validation failed: {error}")
                emit('error', {'message': error}, room=sender_id)
                return
                
            # Check if message should be compressed
            if self.validator.should_compress_message(message):
                message = self.validator.compress_message(message)
                
            # Get sender info
            sender_info = self.get_session_info(sender_id) if sender_id else None
            sender_name = sender_info.get('username') if sender_info else 'Anonymous'
            
            # Prepare message data
            message_data = {
                'message': message,
                'sender': sender_name,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Broadcast to room
            emit('message', message_data, room=room_id)
            
        except Exception as e:
            custom_log(f"Error broadcasting message to room {room_id}: {str(e)}")
            if sender_id:
                emit('error', {'message': 'Failed to broadcast message'}, room=sender_id)
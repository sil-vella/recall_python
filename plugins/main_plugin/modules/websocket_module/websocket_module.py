from flask import request
from core.managers.websocket_manager import WebSocketManager
from core.managers.redis_manager import RedisManager
from core.managers.jwt_manager import JWTManager, TokenType
from tools.logger.custom_logging import custom_log
from typing import Dict, Any, Optional, Set
from flask_cors import CORS
import time
import os
from datetime import datetime, timedelta
from utils.config.config import Config
from enum import Enum

class RoomPermission(Enum):
    PUBLIC = "public"  # Anyone can join
    PRIVATE = "private"  # Only invited users can join
    RESTRICTED = "restricted"  # Only users with specific roles can join
    OWNER_ONLY = "owner_only"  # Only room owner can join

class WebSocketModule:
    def __init__(self, app_manager=None):
        self.app_manager = app_manager
        self.websocket_manager = WebSocketManager()
        self.redis_manager = RedisManager()
        self.jwt_manager = JWTManager()  # Initialize JWT manager
        
        # Set JWT manager in WebSocket manager
        self.websocket_manager.set_jwt_manager(self.jwt_manager)
        
        # Define room ID before initialization
        self.button_counter_room = "button_counter_room"
        
        if app_manager and app_manager.flask_app:
            self.websocket_manager.initialize(app_manager.flask_app)
        
        # Initialize CORS settings
        self._setup_cors()
        
        # Initialize room permissions
        self._initialize_room_permissions()
        
        # Set room access check function
        self.websocket_manager.set_room_access_check(self._check_room_access)
        
        self._register_handlers()
        custom_log("WebSocketModule initialized")

    def _setup_cors(self):
        """Configure CORS settings with security measures."""
        # Use allowed origins from Config
        allowed_origins = Config.WS_ALLOWED_ORIGINS
        
        # Configure CORS with specific origins
        self.websocket_manager.set_cors_origins(allowed_origins)
        custom_log(f"WebSocket CORS configured for origins: {allowed_origins}")

    def _initialize_room_permissions(self):
        """Initialize default room permissions."""
        # Default room permissions
        self.room_permissions = {
            self.button_counter_room: {
                'permission': RoomPermission.PUBLIC,
                'owner_id': None,
                'allowed_users': set(),
                'allowed_roles': set(),
                'created_at': datetime.utcnow().isoformat()
            }
        }
        custom_log("Room permissions initialized")

    def _check_room_access(self, room_id: str, user_id: str, user_roles: Set[str]) -> bool:
        """Check if a user has permission to join a room."""
        if room_id not in self.room_permissions:
            custom_log(f"Room {room_id} not found")
            return False
            
        room_data = self.room_permissions[room_id]
        permission = room_data['permission']
        
        # Check permission type
        if permission == RoomPermission.PUBLIC:
            return True
            
        if permission == RoomPermission.PRIVATE:
            return user_id in room_data['allowed_users']
            
        if permission == RoomPermission.RESTRICTED:
            return bool(room_data['allowed_roles'] & user_roles)
            
        if permission == RoomPermission.OWNER_ONLY:
            return user_id == room_data['owner_id']
            
        return False

    def _register_handlers(self):
        """Register all WebSocket event handlers."""
        # Connect and disconnect don't use authentication
        self.websocket_manager.register_handler('connect', self._handle_connect)
        self.websocket_manager.register_handler('disconnect', self._handle_disconnect)
        
        # All other handlers use authentication
        self.websocket_manager.register_authenticated_handler('join', self._handle_join)
        self.websocket_manager.register_authenticated_handler('leave', self._handle_leave)
        self.websocket_manager.register_authenticated_handler('message', self._handle_message)
        self.websocket_manager.register_authenticated_handler('button_press', self._handle_button_press)
        self.websocket_manager.register_authenticated_handler('get_counter', self._handle_get_counter)
        self.websocket_manager.register_authenticated_handler('get_users', self._handle_get_users)
        
        # Register game event handlers if game plugin is available
        if self.app_manager and self.app_manager.module_manager:
            game_event_handlers = self.app_manager.module_manager.get_module("game_event_handlers")
            if game_event_handlers:
                self.websocket_manager.register_authenticated_handler('join_game', game_event_handlers.handle_join_game)
                self.websocket_manager.register_authenticated_handler('leave_game', game_event_handlers.handle_leave_game)
                self.websocket_manager.register_authenticated_handler('game_action', game_event_handlers.handle_game_action)
                custom_log("Game event handlers registered")
        
        custom_log("WebSocket event handlers registered")

    def _validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate JWT token and return user data if valid."""
        try:
            # Validate the token
            payload = self.jwt_manager.verify_token(token, TokenType.ACCESS)
            if not payload:
                return None
                
            # Get user data from Redis cache
            user_data = self.redis_manager.get(f"user:{payload['id']}")
            if not user_data:
                return None
                
            return user_data
        except Exception as e:
            custom_log(f"Token validation error: {str(e)}")
            return None

    def _handle_connect(self, data=None):
        """Handle new WebSocket connections with security checks."""
        session_id = request.sid
        origin = request.headers.get('Origin', '')
        client_id = request.headers.get('X-Client-ID', session_id)
        token = request.args.get('token')  # Get token from query parameters
        
        # For testing, allow all origins
        if origin == 'null' or not origin:
            origin = 'http://localhost:5000'
            
        # Validate origin
        if not self.websocket_manager.validate_origin(origin):
            custom_log(f"Invalid origin rejected: {origin}")
            return {'status': 'error', 'message': 'Invalid origin'}
            
        # Check rate limits
        if not self.websocket_manager.check_rate_limit(client_id, 'connections'):
            custom_log(f"Rate limit exceeded for client: {client_id}")
            return {'status': 'error', 'message': 'Rate limit exceeded'}
            
        # Validate JWT token
        if not token:
            custom_log("No token provided for WebSocket connection")
            return {'status': 'error', 'message': 'Authentication required'}
            
        user_data = self._validate_token(token)
        if not user_data:
            custom_log("Invalid token for WebSocket connection")
            return {'status': 'error', 'message': 'Invalid authentication'}
            
        # Update rate limits
        self.websocket_manager.update_rate_limit(client_id, 'connections')
        
        # Store session info with user data
        session_data = {
            'client_id': client_id,
            'origin': origin,
            'user_id': user_data['id'],
            'username': user_data['username'],
            'connected_at': datetime.utcnow().isoformat(),
            'last_active': datetime.utcnow().isoformat()
        }
        self.websocket_manager.store_session_data(session_id, session_data)
        
        # Don't automatically join any room
        custom_log(f"New WebSocket connection: {session_id} from {origin} for user {user_data['id']}")
        return {'status': 'connected', 'session_id': session_id}

    def _handle_disconnect(self, data=None):
        """Handle WebSocket disconnections with cleanup."""
        session_id = request.sid
        
        # Get user data before cleanup
        session_data = self.websocket_manager.get_session_data(session_id)
        if session_data:
            username = session_data.get('username')
            if username:
                # Leave the room before cleanup
                self.websocket_manager.leave_room(self.button_counter_room, session_id)
                
                # Broadcast user left event
                self.websocket_manager.broadcast_to_room(
                    self.button_counter_room,
                    'user_left',
                    {'username': username}
                )
        
        # Clean up session data
        self.websocket_manager.cleanup_session_data(session_id)
        
        # Clean up WebSocket session
        self.websocket_manager.cleanup_session(session_id)
        custom_log(f"WebSocket disconnected: {session_id}")

    def _handle_join(self, data: Dict[str, Any], session_data: Dict[str, Any]):
        """Handle joining a room with authentication and permission checks."""
        session_id = request.sid
        room_id = data.get('room_id')
        if not room_id:
            raise ValueError("room_id is required")
            
        # Get user roles from session data
        user_roles = set(session_data.get('roles', []))
        
        # Check room access permission
        if not self._check_room_access(room_id, session_data['user_id'], user_roles):
            custom_log(f"Access denied for user {session_data['user_id']} to room {room_id}")
            return {'status': 'error', 'message': 'Access denied to room'}
        
        self.websocket_manager.join_room(room_id, session_id)
        return {'status': 'joined', 'room_id': room_id}

    def _handle_leave(self, data: Dict[str, Any], session_data: Dict[str, Any]):
        """Handle leaving a room with authentication."""
        session_id = request.sid
        room_id = data.get('room_id')
        if not room_id:
            raise ValueError("room_id is required")
        
        self.websocket_manager.leave_room(room_id, session_id)
        return {'status': 'left', 'room_id': room_id}

    def _handle_message(self, data: Dict[str, Any], session_data: Dict[str, Any]):
        """Handle incoming messages with authentication."""
        session_id = request.sid
        message = data.get('message')
        room_id = data.get('room_id')
        
        if not message:
            raise ValueError("message is required")
            
        # Check rate limits for messages
        if not self.websocket_manager.check_rate_limit(session_data['client_id'], 'messages'):
            return {'status': 'error', 'message': 'Rate limit exceeded'}
            
        # Update rate limits
        self.websocket_manager.update_rate_limit(session_data['client_id'], 'messages')
        
        # Broadcast message to room or all connected clients
        if room_id:
            self.websocket_manager.broadcast_to_room(room_id, 'message', {
                'message': message,
                'user_id': session_data['user_id'],
                'timestamp': datetime.utcnow().isoformat()
            })
        else:
            self.websocket_manager.broadcast_to_all('message', {
                'message': message,
                'user_id': session_data['user_id'],
                'timestamp': datetime.utcnow().isoformat()
            })
            
        return {'status': 'sent'}

    def _handle_button_press(self, data: Dict[str, Any]):
        """Handle button press events."""
        session_id = request.sid
        
        # Update counter in Redis
        counter_key = f"button_counter:{self.button_counter_room}"
        current_count = self.redis_manager.incr(counter_key)
        
        # Broadcast updated count to room
        self.websocket_manager.broadcast_to_room(
            self.button_counter_room,
            'counter_update',
            {'count': current_count}
        )
        
        return {'status': 'success', 'count': current_count}

    def _handle_get_counter(self, data: Dict[str, Any]):
        """Handle getting the current counter value."""
        counter_key = f"button_counter:{self.button_counter_room}"
        current_count = self.redis_manager.get(counter_key) or 0
        return {'status': 'success', 'count': current_count}

    def _handle_get_users(self, data: Dict[str, Any]):
        """Handle getting the list of connected users."""
        room_members = self.get_room_members(self.button_counter_room)
        users = []
        
        for session_id in room_members:
            session_data = self.websocket_manager.get_session_data(session_id)
            if session_data and 'username' in session_data:
                users.append(session_data['username'])
        
        return {'status': 'success', 'users': users}

    def broadcast_to_room(self, room_id: str, event: str, data: Any):
        """Broadcast message to a specific room."""
        self.websocket_manager.broadcast_to_room(room_id, event, data)

    def send_to_session(self, session_id: str, event: str, data: Any):
        """Send message to a specific session."""
        self.websocket_manager.send_to_session(session_id, event, data)

    def get_room_members(self, room_id: str) -> set:
        """Get all members in a room."""
        return self.websocket_manager.get_room_members(room_id)

    def get_rooms_for_session(self, session_id: str) -> set:
        """Get all rooms for a session."""
        return self.websocket_manager.get_rooms_for_session(session_id)

    def create_room(self, room_id: str, permission: RoomPermission, owner_id: str, 
                   allowed_users: Set[str] = None, allowed_roles: Set[str] = None) -> Dict[str, Any]:
        """Create a new room with specified permissions."""
        if room_id in self.room_permissions:
            raise ValueError(f"Room {room_id} already exists")
            
        room_data = {
            'permission': permission,
            'owner_id': owner_id,
            'allowed_users': allowed_users or set(),
            'allowed_roles': allowed_roles or set(),
            'created_at': datetime.utcnow().isoformat()
        }
        
        self.room_permissions[room_id] = room_data
        custom_log(f"Created new room {room_id} with permission {permission.value}")
        return room_data

    def update_room_permissions(self, room_id: str, permission: RoomPermission = None,
                              allowed_users: Set[str] = None, allowed_roles: Set[str] = None) -> Dict[str, Any]:
        """Update room permissions."""
        if room_id not in self.room_permissions:
            raise ValueError(f"Room {room_id} not found")
            
        room_data = self.room_permissions[room_id]
        
        if permission:
            room_data['permission'] = permission
        if allowed_users is not None:
            room_data['allowed_users'] = allowed_users
        if allowed_roles is not None:
            room_data['allowed_roles'] = allowed_roles
            
        custom_log(f"Updated permissions for room {room_id}")
        return room_data

    def get_room_permissions(self, room_id: str) -> Optional[Dict[str, Any]]:
        """Get room permissions."""
        return self.room_permissions.get(room_id)

    def delete_room(self, room_id: str):
        """Delete a room and its permissions."""
        if room_id in self.room_permissions:
            del self.room_permissions[room_id]
            custom_log(f"Deleted room {room_id}")
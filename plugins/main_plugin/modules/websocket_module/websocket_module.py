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
            # Validate the token - accept both access and websocket tokens
            payload = self.jwt_manager.verify_token(token, TokenType.ACCESS) or \
                     self.jwt_manager.verify_token(token, TokenType.WEBSOCKET)
                     
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
            'last_active': datetime.utcnow().isoformat(),
            'token': token,  # Store token for reconnection validation
            'rooms': set()  # Track rooms this session is in
        }
        
        # Store session data in Redis with expiration
        self.websocket_manager.store_session_data(session_id, session_data)
        
        # Send session data to client
        self.websocket_manager.socketio.emit('session_data', session_data, room=session_id)
        
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

    def _handle_join(self, data, session_data):
        """Handle join room event."""
        try:
            room_id = data.get('room_id') if data else None
            if not room_id:
                custom_log("No room_id provided in join event")
                return
                
            # Get session data from WebSocket manager if not provided
            session_id = request.sid
            if not session_data:
                session_data = self.websocket_manager.get_session_data(session_id)
                if not session_data:
                    custom_log("No session data found for join event")
                    return
                    
            # Convert any sets to lists for JSON serialization
            if 'rooms' in session_data and isinstance(session_data['rooms'], set):
                session_data['rooms'] = list(session_data['rooms'])
            if 'user_roles' in session_data and isinstance(session_data['user_roles'], set):
                session_data['user_roles'] = list(session_data['user_roles'])
                
            # Check if user is already in the room
            if room_id in session_data.get('rooms', []):
                custom_log(f"User {session_data.get('username')} already in room {room_id}")
                return
                
            # Join room - stop processing if join fails
            if not self.websocket_manager.join_room(room_id, session_id):
                custom_log(f"Failed to join room {room_id}")
                return
                
            # Update session data with room membership
            if 'rooms' not in session_data:
                session_data['rooms'] = []
            if room_id not in session_data['rooms']:
                session_data['rooms'].append(room_id)
            self.websocket_manager.store_session_data(session_id, session_data)
            
            # Update room permissions
            self.websocket_manager._update_room_permissions(room_id, session_id, session_data)
            
            # Broadcast join event
            self.websocket_manager.socketio.emit('user_joined', {
                'room_id': room_id,
                'user_id': session_data.get('user_id'),
                'username': session_data.get('username')
            }, room=room_id)
            
            # Send current room state to the joining user
            self._send_room_state(room_id, session_id)
            
            custom_log(f"User {session_data.get('username')} joined room {room_id}")
            
        except Exception as e:
            custom_log(f"Error in join handler: {str(e)}")
            
    def _send_room_state(self, room_id: str, session_id: str):
        """Send current room state to a user."""
        try:
            # Get room members
            room_members = self.websocket_manager.get_room_members(room_id)
            users = []
            
            for member_id in room_members:
                member_data = self.websocket_manager.get_session_data(member_id)
                if member_data:
                    users.append({
                        'user_id': member_data.get('user_id'),
                        'username': member_data.get('username')
                    })
            
            # Get current counter value
            counter_key = f"button_counter:{room_id}"
            current_count = self.redis_manager.get(counter_key) or 0
            
            # Send room state
            self.websocket_manager.socketio.emit('room_state', {
                'room_id': room_id,
                'users': users,
                'counter': current_count
            }, room=session_id)
            
        except Exception as e:
            custom_log(f"Error sending room state: {str(e)}")

    def _handle_leave(self, data):
        """Handle leave room event."""
        try:
            room_id = data.get('room_id')
            if not room_id:
                custom_log("No room_id provided in leave event")
                return
                
            # Get session data from WebSocket manager
            session_id = request.sid
            session_data = self.websocket_manager.get_session_data(session_id)
            if not session_data:
                custom_log("No session data found for leave event")
                return
                
            # Check if user is in the room
            if room_id not in session_data.get('rooms', set()):
                custom_log(f"User {session_data.get('username')} not in room {room_id}")
                return
                
            # Leave room
            self.websocket_manager.leave_room(room_id, session_id)
            
            # Update session data to remove room membership
            session_data['rooms'].remove(room_id)
            self.websocket_manager.store_session_data(session_id, session_data)
            
            # Broadcast leave event
            self.websocket_manager.socketio.emit('user_left', {
                'room_id': room_id,
                'user_id': session_data.get('user_id'),
                'username': session_data.get('username')
            }, room=room_id)
            
            custom_log(f"User {session_data.get('username')} left room {room_id}")
            
        except Exception as e:
            custom_log(f"Error in leave handler: {str(e)}")

    def _handle_message(self, data):
        """Handle message event."""
        try:
            room_id = data.get('room_id')
            message = data.get('message')
            if not room_id or not message:
                custom_log("Missing room_id or message in message event")
                return
                
            # Get session data from WebSocket manager
            session_id = request.sid
            session_data = self.websocket_manager.get_session_data(session_id)
            if not session_data:
                custom_log("No session data found for message event")
                return
                
            # Broadcast message
            self.websocket_manager.socketio.emit('message', {
                'room_id': room_id,
                'user_id': session_data.get('user_id'),
                'username': session_data.get('username'),
                'message': message,
                'timestamp': datetime.utcnow().isoformat()
            }, room=room_id)
            
            custom_log(f"Message from {session_data.get('username')} in room {room_id}")
            
        except Exception as e:
            custom_log(f"Error in message handler: {str(e)}")

    def _handle_button_press(self, data):
        """Handle button press event."""
        try:
            room_id = data.get('room_id')
            if not room_id:
                custom_log("No room_id provided in button press event")
                return
                
            # Get session data from WebSocket manager
            session_id = request.sid
            session_data = self.websocket_manager.get_session_data(session_id)
            if not session_data:
                custom_log("No session data found for button press event")
                return
                
            # Update counter in Redis
            counter_key = f"button_counter:{room_id}"
            current_count = self.redis_manager.incr(counter_key)
            
            # Broadcast updated count to room
            self.websocket_manager.socketio.emit('counter_update', {
                'room_id': room_id,
                'count': current_count
            }, room=room_id)
            
            custom_log(f"Button pressed by {session_data.get('username')} in room {room_id}")
            
        except Exception as e:
            custom_log(f"Error in button press handler: {str(e)}")

    def _handle_get_counter(self, data):
        """Handle get counter event."""
        try:
            room_id = data.get('room_id')
            if not room_id:
                custom_log("No room_id provided in get counter event")
                return
                
            # Get session data from WebSocket manager
            session_id = request.sid
            session_data = self.websocket_manager.get_session_data(session_id)
            if not session_data:
                custom_log("No session data found for get counter event")
                return
                
            # Get counter value from Redis
            counter_key = f"button_counter:{room_id}"
            current_count = self.redis_manager.get(counter_key) or 0
            
            # Send counter value to client
            self.websocket_manager.socketio.emit('counter_update', {
                'room_id': room_id,
                'count': current_count
            }, room=session_id)
            
            custom_log(f"Counter value sent to {session_data.get('username')} for room {room_id}")
            
        except Exception as e:
            custom_log(f"Error in get counter handler: {str(e)}")

    def _handle_get_users(self, data):
        """Handle get users event."""
        try:
            room_id = data.get('room_id')
            if not room_id:
                custom_log("No room_id provided in get users event")
                return
                
            # Get session data from WebSocket manager
            session_id = request.sid
            session_data = self.websocket_manager.get_session_data(session_id)
            if not session_data:
                custom_log("No session data found for get users event")
                return
                
            # Get room members
            room_members = self.websocket_manager.get_room_members(room_id)
            users = []
            
            for member_id in room_members:
                member_data = self.websocket_manager.get_session_data(member_id)
                if member_data:
                    users.append({
                        'user_id': member_data.get('user_id'),
                        'username': member_data.get('username')
                    })
            
            # Send users list to client
            self.websocket_manager.socketio.emit('users_list', {
                'room_id': room_id,
                'users': users
            }, room=session_id)
            
            custom_log(f"Users list sent to {session_data.get('username')} for room {room_id}")
            
        except Exception as e:
            custom_log(f"Error in get users handler: {str(e)}")

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
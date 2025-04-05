from typing import Dict, Any, Optional
from datetime import datetime
from tools.logger.custom_logging import custom_log
from flask import request
from core.managers.websocket_manager import WebSocketManager
from core.managers.redis_manager import RedisManager
from .room_manager import RoomManager, RoomPermission
from .session_manager import SessionManager

class EventHandler:
    def __init__(self, websocket_manager: WebSocketManager, room_manager: RoomManager, session_manager: SessionManager, redis_manager: RedisManager):
        self.websocket_manager = websocket_manager
        self.room_manager = room_manager
        self.session_manager = session_manager
        self.redis_manager = redis_manager

    def handle_connect(self, data=None):
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
            
        user_data = self.session_manager.validate_token(token)
        if not user_data:
            custom_log("Invalid token for WebSocket connection")
            return {'status': 'error', 'message': 'Invalid authentication'}
            
        # Update rate limits
        self.websocket_manager.update_rate_limit(client_id, 'connections')
        
        # Create session
        session_data = self.session_manager.create_session(session_id, client_id, origin, user_data, token)
        
        # Send session data to client
        self.websocket_manager.socketio.emit('session_data', session_data, room=session_id)
        
        custom_log(f"New WebSocket connection: {session_id} from {origin} for user {user_data['id']}")
        return {'status': 'connected', 'session_id': session_id}

    def handle_disconnect(self, data=None):
        """Handle WebSocket disconnections with cleanup."""
        session_id = request.sid
        
        # Get user data before cleanup
        session_data = self.session_manager.get_session(session_id)
        if session_data:
            username = session_data.get('username')
            if username:
                # Leave all rooms before cleanup
                for room_id in session_data.get('rooms', []):
                    self.websocket_manager.leave_room(room_id, session_id)
                    
                    # Broadcast user left event
                    self.websocket_manager.broadcast_to_room(
                        room_id,
                        'user_left',
                        {'username': username}
                    )
        
        # Clean up session data
        self.session_manager.delete_session(session_id)
        
        # Clean up WebSocket session
        self.websocket_manager.cleanup_session(session_id)
        custom_log(f"WebSocket disconnected: {session_id}")

    def handle_join(self, data, session_data):
        """Handle join room event."""
        try:
            room_id = data.get('room_id') if data else None
            if not room_id:
                custom_log("No room_id provided in join event")
                return
                
            # Get session data from WebSocket manager if not provided
            session_id = request.sid
            if not session_data:
                session_data = self.session_manager.get_session(session_id)
                if not session_data:
                    custom_log("No session data found for join event")
                    return
                    
            # Check if user is already in the room
            if room_id in session_data.get('rooms', []):
                custom_log(f"User {session_data.get('username')} already in room {room_id}")
                return
                
            # Join room - stop processing if join fails
            if not self.websocket_manager.join_room(room_id, session_id):
                custom_log(f"Failed to join room {room_id}")
                return
                
            # Update session data with room membership
            self.session_manager.add_room_to_session(session_id, room_id)
            
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

    def handle_leave(self, data):
        """Handle leave room event."""
        try:
            room_id = data.get('room_id')
            if not room_id:
                custom_log("No room_id provided in leave event")
                return
                
            # Get session data from WebSocket manager
            session_id = request.sid
            session_data = self.session_manager.get_session(session_id)
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
            self.session_manager.remove_room_from_session(session_id, room_id)
            
            # Broadcast leave event
            self.websocket_manager.socketio.emit('user_left', {
                'room_id': room_id,
                'user_id': session_data.get('user_id'),
                'username': session_data.get('username')
            }, room=room_id)
            
            custom_log(f"User {session_data.get('username')} left room {room_id}")
            
        except Exception as e:
            custom_log(f"Error in leave handler: {str(e)}")

    def handle_message(self, data):
        """Handle message event."""
        try:
            room_id = data.get('room_id')
            message = data.get('message')
            if not room_id or not message:
                custom_log("Missing room_id or message in message event")
                return
                
            # Get session data from WebSocket manager
            session_id = request.sid
            session_data = self.session_manager.get_session(session_id)
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

    def handle_button_press(self, data):
        """Handle button press event."""
        try:
            room_id = data.get('room_id')
            if not room_id:
                custom_log("No room_id provided in button press event")
                return
                
            # Get session data from WebSocket manager
            session_id = request.sid
            session_data = self.session_manager.get_session(session_id)
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

    def handle_get_counter(self, data):
        """Handle get counter event."""
        try:
            room_id = data.get('room_id')
            if not room_id:
                custom_log("No room_id provided in get counter event")
                return
                
            # Get session data from WebSocket manager
            session_id = request.sid
            session_data = self.session_manager.get_session(session_id)
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

    def handle_get_users(self, data):
        """Handle get users event."""
        try:
            room_id = data.get('room_id')
            if not room_id:
                custom_log("No room_id provided in get users event")
                return
                
            # Get session data from WebSocket manager
            session_id = request.sid
            session_data = self.session_manager.get_session(session_id)
            if not session_data:
                custom_log("No session data found for get users event")
                return
                
            # Get room members
            room_members = self.websocket_manager.get_room_members(room_id)
            users = []
            
            for member_id in room_members:
                member_data = self.session_manager.get_session(member_id)
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

    def handle_create_room(self, data):
        """Handle create room event."""
        try:
            # Get session data from WebSocket manager
            session_id = request.sid
            session_data = self.session_manager.get_session(session_id)
            if not session_data:
                custom_log("No session data found for create room event")
                return
                
            user_id = data.get('user_id')
            if not user_id:
                custom_log("No user_id provided in create room event")
                return
                
            # Validate that the user ID matches the session
            if user_id != session_data.get('user_id'):
                custom_log(f"User ID mismatch in create room event: {user_id} != {session_data.get('user_id')}")
                return
                
            # Generate a unique room ID
            room_id = f"room_{int(time.time())}_{user_id}"
            
            # Create room with public permission
            room_data = self.room_manager.create_room(
                room_id=room_id,
                permission=RoomPermission.PUBLIC,
                owner_id=user_id
            )
            
            # Join the room
            if not self.websocket_manager.join_room(room_id, session_id):
                custom_log(f"Failed to join newly created room {room_id}")
                return
                
            # Update session data with room membership
            self.session_manager.add_room_to_session(session_id, room_id)
            
            # Send room created event
            self.websocket_manager.socketio.emit('room_created', {
                'room_id': room_id,
                'owner_id': user_id,
                'created_at': room_data['created_at']
            }, room=session_id)
            
            # Send user joined event
            self.websocket_manager.socketio.emit('user_joined', {
                'room_id': room_id,
                'user_id': user_id,
                'username': session_data.get('username')
            }, room=room_id)
            
            # Send initial room state
            self._send_room_state(room_id, session_id)
            
            custom_log(f"Room {room_id} created by user {user_id}")
            
        except Exception as e:
            custom_log(f"Error in create room handler: {str(e)}")
            # Send error event to client
            self.websocket_manager.socketio.emit('error', {
                'message': f"Failed to create room: {str(e)}",
                'type': 'room_creation_error'
            }, room=session_id)

    def _send_room_state(self, room_id: str, session_id: str):
        """Send current room state to a user."""
        try:
            # Get room members
            room_members = self.websocket_manager.get_room_members(room_id)
            users = []
            
            for member_id in room_members:
                member_data = self.session_manager.get_session(member_id)
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
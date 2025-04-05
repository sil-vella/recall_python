from flask import request
from core.managers.websocket_manager import WebSocketManager
from core.managers.redis_manager import RedisManager
from core.managers.jwt_manager import JWTManager
from tools.logger.custom_logging import custom_log
from typing import Dict, Any, Optional, Set
from flask_cors import CORS
import time
from datetime import datetime
from utils.config.config import Config
from .components.room_manager import RoomManager, RoomPermission
from .components.session_manager import SessionManager
from .components.event_handler import EventHandler

class WebSocketModule:
    def __init__(self, app_manager=None):
        self.app_manager = app_manager
        self.websocket_manager = WebSocketManager()
        self.redis_manager = RedisManager()
        self.jwt_manager = JWTManager()
        
        # Set JWT manager in WebSocket manager
        self.websocket_manager.set_jwt_manager(self.jwt_manager)
        
        # Initialize components
        self.room_manager = RoomManager()
        self.session_manager = SessionManager(self.redis_manager, self.jwt_manager)
        self.event_handler = EventHandler(
            self.websocket_manager,
            self.room_manager,
            self.session_manager,
            self.redis_manager
        )
        
        if app_manager and app_manager.flask_app:
            self.websocket_manager.initialize(app_manager.flask_app)
        
        # Initialize CORS settings
        self._setup_cors()
        
        # Set room access check function
        self.websocket_manager.set_room_access_check(self.room_manager.check_room_access)
        
        self._register_handlers()
        custom_log("WebSocketModule initialized")

    def _setup_cors(self):
        """Configure CORS settings with security measures."""
        # Use allowed origins from Config
        allowed_origins = Config.WS_ALLOWED_ORIGINS
        
        # Configure CORS with specific origins
        self.websocket_manager.set_cors_origins(allowed_origins)
        custom_log(f"WebSocket CORS configured for origins: {allowed_origins}")

    def _register_handlers(self):
        """Register all WebSocket event handlers."""
        # Connect and disconnect don't use authentication
        self.websocket_manager.register_handler('connect', self.event_handler.handle_connect)
        self.websocket_manager.register_handler('disconnect', self.event_handler.handle_disconnect)
        
        # All other handlers use authentication
        self.websocket_manager.register_authenticated_handler('join', self.event_handler.handle_join)
        self.websocket_manager.register_authenticated_handler('leave', self.event_handler.handle_leave)
        self.websocket_manager.register_authenticated_handler('message', self.event_handler.handle_message)
        self.websocket_manager.register_authenticated_handler('button_press', self.event_handler.handle_button_press)
        self.websocket_manager.register_authenticated_handler('get_counter', self.event_handler.handle_get_counter)
        self.websocket_manager.register_authenticated_handler('get_users', self.event_handler.handle_get_users)
        self.websocket_manager.register_authenticated_handler('create_room', self.event_handler.handle_create_room)
        
        # Register game event handlers if game plugin is available
        if self.app_manager and self.app_manager.module_manager:
            game_event_handlers = self.app_manager.module_manager.get_module("game_event_handlers")
            if game_event_handlers:
                self.websocket_manager.register_authenticated_handler('join_game', game_event_handlers.handle_join_game)
                self.websocket_manager.register_authenticated_handler('leave_game', game_event_handlers.handle_leave_game)
                self.websocket_manager.register_authenticated_handler('game_action', game_event_handlers.handle_game_action)
                custom_log("Game event handlers registered")
        
        custom_log("WebSocket event handlers registered")

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
        return self.room_manager.create_room(room_id, permission, owner_id, allowed_users, allowed_roles)

    def update_room_permissions(self, room_id: str, permission: RoomPermission = None,
                              allowed_users: Set[str] = None, allowed_roles: Set[str] = None) -> Dict[str, Any]:
        """Update room permissions."""
        return self.room_manager.update_room_permissions(room_id, permission, allowed_users, allowed_roles)

    def get_room_permissions(self, room_id: str) -> Optional[Dict[str, Any]]:
        """Get room permissions."""
        return self.room_manager.get_room_permissions(room_id)

    def delete_room(self, room_id: str):
        """Delete a room and its permissions."""
        self.room_manager.delete_room(room_id)
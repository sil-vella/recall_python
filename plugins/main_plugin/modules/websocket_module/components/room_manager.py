from typing import Dict, Any, Optional, Set
from datetime import datetime
from enum import Enum
from tools.logger.custom_logging import custom_log

class RoomPermission(Enum):
    PUBLIC = "public"  # Anyone can join
    PRIVATE = "private"  # Only invited users can join
    RESTRICTED = "restricted"  # Only users with specific roles can join
    OWNER_ONLY = "owner_only"  # Only room owner can join

class RoomManager:
    def __init__(self):
        self.room_permissions = {}
        self._initialize_room_permissions()

    def _initialize_room_permissions(self):
        """Initialize default room permissions."""
        # Default room permissions
        self.room_permissions = {
            "button_counter_room": {
                'permission': RoomPermission.PUBLIC,
                'owner_id': None,
                'allowed_users': set(),
                'allowed_roles': set(),
                'created_at': datetime.utcnow().isoformat()
            }
        }
        custom_log("Room permissions initialized")

    def check_room_access(self, room_id: str, user_id: str, user_roles: Set[str]) -> bool:
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
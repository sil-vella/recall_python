from typing import Dict, Any, Optional, Tuple
from datetime import datetime
from ..game_state_module.state_manager import StateManager
from ..game_state_module.models.game_session import GameSession

class GameEventValidators:
    """Validates game-specific WebSocket events."""
    
    def __init__(self, state_manager: StateManager):
        self.state_manager = state_manager
        
    def validate_join_game(self, data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate join game event data."""
        if not data:
            return False, "No data provided"
            
        session_id = data.get('session_id')
        if not session_id:
            return False, "Missing session ID"
            
        session = self.state_manager.get_session(session_id)
        if not session:
            return False, "Game session not found"
            
        if session.status == 'finished':
            return False, "Game session has ended"
            
        if session.status == 'cancelled':
            return False, "Game session was cancelled"
            
        return True, None
        
    def validate_leave_game(self, data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate leave game event data."""
        if not data:
            return False, "No data provided"
            
        session_id = data.get('session_id')
        if not session_id:
            return False, "Missing session ID"
            
        session = self.state_manager.get_session(session_id)
        if not session:
            return False, "Game session not found"
            
        return True, None
        
    def validate_game_action(self, data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate game action event data."""
        if not data:
            return False, "No data provided"
            
        session_id = data.get('session_id')
        action = data.get('action')
        
        if not session_id or not action:
            return False, "Missing session ID or action"
            
        session = self.state_manager.get_session(session_id)
        if not session:
            return False, "Game session not found"
            
        if session.status != 'active':
            return False, "Game is not active"
            
        # Validate action type
        if not isinstance(action, dict):
            return False, "Action must be a dictionary"
            
        action_type = action.get('type')
        if not action_type:
            return False, "Action must have a type"
            
        # Add more specific action validation here
        # This will depend on the game rules
        
        return True, None
        
    def validate_game_state(self, session: GameSession) -> Tuple[bool, Optional[str]]:
        """Validate the current game state."""
        if not session:
            return False, "No game session provided"
            
        if not session.players:
            return False, "No players in game"
            
        if session.status == 'active' and not session.game_board:
            return False, "Active game has no board state"
            
        return True, None 
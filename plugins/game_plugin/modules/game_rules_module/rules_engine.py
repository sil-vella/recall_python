from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime
from ..game_state_module.state_manager import StateManager
from ..game_state_module.models.game_session import GameSession
from ..game_state_module.models.player_state import PlayerState

class GameRulesEngine:
    """Handles game rules and logic."""
    
    def __init__(self, state_manager: StateManager):
        self.state_manager = state_manager
        
    def validate_action(self, session: GameSession, player: PlayerState, action: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate a player's action against game rules."""
        if not session or not player or not action:
            return False, "Invalid parameters"
            
        # Check if it's the player's turn
        if not self._is_player_turn(session, player):
            return False, "Not your turn"
            
        # Validate action type
        action_type = action.get('type')
        if not action_type:
            return False, "Action must have a type"
            
        # Validate action data
        action_data = action.get('data', {})
        if not self._validate_action_data(action_type, action_data):
            return False, f"Invalid action data for type: {action_type}"
            
        return True, None
        
    def process_action(self, session: GameSession, player: PlayerState, action: Dict[str, Any]) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """Process a valid game action and return the result."""
        try:
            # Get action type and data
            action_type = action.get('type')
            action_data = action.get('data', {})
            
            # Process the action based on type
            result = self._process_action_by_type(session, player, action_type, action_data)
            
            # Update game state
            self._update_game_state(session, result)
            
            return True, None, result
            
        except Exception as e:
            return False, str(e), None
            
    def check_win_condition(self, session: GameSession) -> Tuple[bool, Optional[PlayerState]]:
        """Check if the game has been won."""
        # This will be implemented based on specific game rules
        # For now, return False to indicate game is not won
        return False, None
        
    def _is_player_turn(self, session: GameSession, player: PlayerState) -> bool:
        """Check if it's the player's turn."""
        # This will be implemented based on specific game rules
        # For now, return True to allow all actions
        return True
        
    def _validate_action_data(self, action_type: str, action_data: Dict[str, Any]) -> bool:
        """Validate action data based on action type."""
        # This will be implemented based on specific game rules
        # For now, return True to allow all actions
        return True
        
    def _process_action_by_type(self, session: GameSession, player: PlayerState, action_type: str, action_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process an action based on its type."""
        # This will be implemented based on specific game rules
        # For now, return a basic result
        return {
            'type': action_type,
            'player_id': player.user_id,
            'timestamp': datetime.utcnow().isoformat(),
            'data': action_data
        }
        
    def _update_game_state(self, session: GameSession, result: Dict[str, Any]) -> None:
        """Update the game state based on action result."""
        # Update the game board
        if session.game_board:
            session.game_board.board_data.update(result)
            self.state_manager.save_game_board(session.game_board)
            
        # Update player state if needed
        if 'score_change' in result:
            player = session.players.get(result['player_id'])
            if player:
                player.update_score(result['score_change'])
                self.state_manager.save_player_state(player)
                
        # Update session
        self.state_manager.update_session(session) 
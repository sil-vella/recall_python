from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime

class GameActionValidator:
    """Validates game-specific actions."""
    
    def __init__(self):
        self.valid_action_types = {
            'move': self._validate_move_action,
            'answer': self._validate_answer_action,
            'skip': self._validate_skip_action,
            'end_turn': self._validate_end_turn_action
        }
        
    def validate_action(self, action: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate a game action."""
        if not action:
            return False, "No action provided"
            
        action_type = action.get('type')
        if not action_type:
            return False, "Action must have a type"
            
        if action_type not in self.valid_action_types:
            return False, f"Invalid action type: {action_type}"
            
        action_data = action.get('data', {})
        return self.valid_action_types[action_type](action_data)
        
    def _validate_move_action(self, data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate a move action."""
        if not data:
            return False, "No move data provided"
            
        # Add specific move validation rules here
        # For example:
        # - Check if position is valid
        # - Check if move is allowed
        # - Check if piece exists
        # - etc.
        
        return True, None
        
    def _validate_answer_action(self, data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate an answer action."""
        if not data:
            return False, "No answer data provided"
            
        answer = data.get('answer')
        if not answer:
            return False, "No answer provided"
            
        # Add specific answer validation rules here
        # For example:
        # - Check if answer is in correct format
        # - Check if answer is within allowed length
        # - Check if answer contains valid characters
        # - etc.
        
        return True, None
        
    def _validate_skip_action(self, data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate a skip action."""
        # Skip actions might not need data validation
        return True, None
        
    def _validate_end_turn_action(self, data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate an end turn action."""
        # End turn actions might not need data validation
        return True, None 
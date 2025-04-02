from dataclasses import dataclass
from typing import Dict, Any, List, Optional
from datetime import datetime

@dataclass
class GameBoard:
    """Represents the game board state."""
    game_id: str
    current_round: int = 1
    max_rounds: int = 10
    is_active: bool = True
    created_at: datetime = datetime.utcnow()
    last_updated: datetime = datetime.utcnow()
    board_data: Dict[str, Any] = None
    round_history: List[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.board_data is None:
            self.board_data = {}
        if self.round_history is None:
            self.round_history = []
            
    def update_round(self) -> bool:
        """Increment the current round and check if game should end."""
        self.current_round += 1
        self.last_updated = datetime.utcnow()
        return self.current_round <= self.max_rounds
        
    def add_round_history(self, round_data: Dict[str, Any]) -> None:
        """Add a round's data to the history."""
        self.round_history.append(round_data)
        self.last_updated = datetime.utcnow()
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert game board to dictionary for serialization."""
        return {
            'game_id': self.game_id,
            'current_round': self.current_round,
            'max_rounds': self.max_rounds,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat(),
            'last_updated': self.last_updated.isoformat(),
            'board_data': self.board_data,
            'round_history': self.round_history
        }
        
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'GameBoard':
        """Create a GameBoard instance from a dictionary."""
        if 'created_at' in data:
            data['created_at'] = datetime.fromisoformat(data['created_at'])
        if 'last_updated' in data:
            data['last_updated'] = datetime.fromisoformat(data['last_updated'])
        return cls(**data) 
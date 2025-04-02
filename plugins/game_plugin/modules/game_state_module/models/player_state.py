from dataclasses import dataclass
from typing import Dict, Any, Optional
from datetime import datetime

@dataclass
class PlayerState:
    """Represents the state of a player in the game."""
    user_id: str
    username: str
    score: int = 0
    is_active: bool = True
    last_active: datetime = datetime.utcnow()
    game_data: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.game_data is None:
            self.game_data = {}
            
    def update_score(self, points: int) -> None:
        """Update the player's score."""
        self.score += points
        
    def update_activity(self) -> None:
        """Update the player's last active timestamp."""
        self.last_active = datetime.utcnow()
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert player state to dictionary for serialization."""
        return {
            'user_id': self.user_id,
            'username': self.username,
            'score': self.score,
            'is_active': self.is_active,
            'last_active': self.last_active.isoformat(),
            'game_data': self.game_data
        }
        
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PlayerState':
        """Create a PlayerState instance from a dictionary."""
        if 'last_active' in data:
            data['last_active'] = datetime.fromisoformat(data['last_active'])
        return cls(**data) 
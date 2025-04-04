from dataclasses import dataclass
from typing import Dict, Any, Optional, List
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
    hand: List[Dict[str, Any]] = None  # Player's cards
    tricks_won: int = 0  # Number of tricks won by the player
    has_called_dutch: bool = False  # Whether the player has called "Dutch"
    
    def __post_init__(self):
        if self.game_data is None:
            self.game_data = {}
        if self.hand is None:
            self.hand = []
            
    def update_score(self, points: int) -> None:
        """Update the player's score."""
        self.score += points
        
    def update_activity(self) -> None:
        """Update the player's last active timestamp."""
        self.last_active = datetime.utcnow()
        
    def add_card(self, card: Dict[str, Any]) -> None:
        """Add a card to the player's hand."""
        self.hand.append(card)
        
    def remove_card(self, card_id: str) -> Dict[str, Any]:
        """Remove a card from the player's hand."""
        for i, card in enumerate(self.hand):
            if card['id'] == card_id:
                return self.hand.pop(i)
        return None
        
    def has_card(self, card_id: str) -> bool:
        """Check if the player has a specific card."""
        return any(card['id'] == card_id for card in self.hand)
        
    def call_dutch(self) -> None:
        """Player calls 'Dutch'."""
        self.has_called_dutch = True
        
    def win_trick(self) -> None:
        """Player wins a trick."""
        self.tricks_won += 1
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert player state to dictionary for serialization."""
        return {
            'user_id': self.user_id,
            'username': self.username,
            'score': self.score,
            'is_active': self.is_active,
            'last_active': self.last_active.isoformat(),
            'game_data': self.game_data,
            'hand': self.hand,
            'tricks_won': self.tricks_won,
            'has_called_dutch': self.has_called_dutch
        }
        
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PlayerState':
        """Create a PlayerState instance from a dictionary."""
        if 'last_active' in data:
            data['last_active'] = datetime.fromisoformat(data['last_active'])
        return cls(**data) 
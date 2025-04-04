from dataclasses import dataclass
from typing import Dict, Any, List, Optional
from datetime import datetime

@dataclass
class GameBoard:
    """Represents the game board state."""
    game_id: str
    current_round: int = 1
    max_rounds: int = 13  # Dutch game has 13 rounds (one for each card)
    is_active: bool = True
    created_at: datetime = datetime.utcnow()
    last_updated: datetime = datetime.utcnow()
    board_data: Dict[str, Any] = None
    round_history: List[Dict[str, Any]] = None
    current_trick: List[Dict[str, Any]] = None  # Cards played in the current trick
    trump_suit: Optional[str] = None  # The trump suit for the current round
    lead_suit: Optional[str] = None  # The suit led in the current trick
    trick_winner: Optional[str] = None  # user_id of the player who won the current trick
    
    def __post_init__(self):
        if self.board_data is None:
            self.board_data = {}
        if self.round_history is None:
            self.round_history = []
        if self.current_trick is None:
            self.current_trick = []
            
    def update_round(self) -> bool:
        """Increment the current round and check if game should end."""
        self.current_round += 1
        self.last_updated = datetime.utcnow()
        
        # Reset trick-related fields for the new round
        self.current_trick = []
        self.lead_suit = None
        self.trick_winner = None
        
        return self.current_round <= self.max_rounds
        
    def add_round_history(self, round_data: Dict[str, Any]) -> None:
        """Add a round's data to the history."""
        self.round_history.append(round_data)
        self.last_updated = datetime.utcnow()
        
    def play_card(self, player_id: str, card: Dict[str, Any]) -> None:
        """Play a card in the current trick."""
        # If this is the first card, set the lead suit
        if not self.current_trick:
            self.lead_suit = card['suit']
            
        # Add the card to the current trick
        self.current_trick.append({
            'player_id': player_id,
            'card': card
        })
        
    def determine_trick_winner(self) -> str:
        """Determine the winner of the current trick."""
        if not self.current_trick:
            return None
            
        # Get the first card to determine the lead suit
        lead_suit = self.current_trick[0]['card']['suit']
        
        # Find the highest card that follows the lead suit or is a trump
        highest_card = None
        highest_player = None
        
        for play in self.current_trick:
            card = play['card']
            player_id = play['player_id']
            
            # If this is the first card, it's automatically the highest so far
            if highest_card is None:
                highest_card = card
                highest_player = player_id
                continue
                
            # If the card is a trump and the highest card is not, the trump wins
            if card['suit'] == self.trump_suit and highest_card['suit'] != self.trump_suit:
                highest_card = card
                highest_player = player_id
                continue
                
            # If both cards are trumps, the higher value wins
            if card['suit'] == self.trump_suit and highest_card['suit'] == self.trump_suit:
                if card['value'] > highest_card['value']:
                    highest_card = card
                    highest_player = player_id
                continue
                
            # If neither card is a trump, the higher card of the lead suit wins
            if card['suit'] == lead_suit and highest_card['suit'] == lead_suit:
                if card['value'] > highest_card['value']:
                    highest_card = card
                    highest_player = player_id
                    
        return highest_player
        
    def end_trick(self) -> None:
        """End the current trick and determine the winner."""
        self.trick_winner = self.determine_trick_winner()
        
        # Add the trick to the round history
        self.add_round_history({
            'trick': self.current_trick,
            'winner': self.trick_winner,
            'round': self.current_round
        })
        
        # Clear the current trick
        self.current_trick = []
        self.lead_suit = None
        
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
            'round_history': self.round_history,
            'current_trick': self.current_trick,
            'trump_suit': self.trump_suit,
            'lead_suit': self.lead_suit,
            'trick_winner': self.trick_winner
        }
        
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'GameBoard':
        """Create a GameBoard instance from a dictionary."""
        if 'created_at' in data:
            data['created_at'] = datetime.fromisoformat(data['created_at'])
        if 'last_updated' in data:
            data['last_updated'] = datetime.fromisoformat(data['last_updated'])
        return cls(**data) 
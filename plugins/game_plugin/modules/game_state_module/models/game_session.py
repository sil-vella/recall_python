from dataclasses import dataclass
from typing import Dict, Any, List, Optional
from datetime import datetime
from .player_state import PlayerState
from .game_board import GameBoard
from ..game_cards_module import CardManager, Card

@dataclass
class GameSession:
    """Represents a complete game session."""
    session_id: str
    game_id: str
    created_at: datetime = datetime.utcnow()
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    status: str = 'waiting'  # waiting, active, finished, cancelled
    players: Dict[str, PlayerState] = None
    game_board: Optional[GameBoard] = None
    settings: Dict[str, Any] = None
    current_turn: Optional[str] = None  # user_id of the player whose turn it is
    dutch_called: bool = False  # Whether a player has called "Dutch"
    dutch_caller: Optional[str] = None  # user_id of the player who called "Dutch"
    
    def __post_init__(self):
        if self.players is None:
            self.players = {}
        if self.settings is None:
            self.settings = {}
            
    def add_player(self, player: PlayerState) -> None:
        """Add a player to the game session."""
        self.players[player.user_id] = player
        
    def remove_player(self, user_id: str) -> None:
        """Remove a player from the game session."""
        if user_id in self.players:
            del self.players[user_id]
            
    def start_game(self) -> None:
        """Start the game session."""
        self.status = 'active'
        self.started_at = datetime.utcnow()
        self.game_board = GameBoard(game_id=self.game_id)
        
        # Set up the game with cards
        self.setup_game()
        
    def setup_game(self) -> None:
        """Set up the game with initial state."""
        # Initialize card manager and shuffle deck
        card_manager = CardManager()
        deck = card_manager.shuffle_deck()
        
        # Deal cards to players
        num_players = len(self.players)
        cards_per_player = 13  # For Dutch game
        hands = card_manager.deal_cards(deck, num_players, cards_per_player)
        
        # Store hands in player states
        for i, (player_id, player) in enumerate(self.players.items()):
            player.game_data["hand"] = [card_manager.card_to_dict(card) for card in hands[f"player_{i}"]]
            
        # Set the first player's turn
        if self.players:
            self.current_turn = list(self.players.keys())[0]
            
    def end_game(self) -> None:
        """End the game session."""
        self.status = 'finished'
        self.ended_at = datetime.utcnow()
        
    def cancel_game(self) -> None:
        """Cancel the game session."""
        self.status = 'cancelled'
        self.ended_at = datetime.utcnow()
        
    def call_dutch(self, user_id: str) -> None:
        """A player calls 'Dutch' to end the game."""
        self.dutch_called = True
        self.dutch_caller = user_id
        self.end_game()
        
    def next_turn(self) -> None:
        """Move to the next player's turn."""
        if not self.players:
            return
            
        player_ids = list(self.players.keys())
        if not self.current_turn:
            self.current_turn = player_ids[0]
            return
            
        current_index = player_ids.index(self.current_turn)
        next_index = (current_index + 1) % len(player_ids)
        self.current_turn = player_ids[next_index]
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert game session to dictionary for serialization."""
        return {
            'session_id': self.session_id,
            'game_id': self.game_id,
            'created_at': self.created_at.isoformat(),
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'ended_at': self.ended_at.isoformat() if self.ended_at else None,
            'status': self.status,
            'players': {uid: player.to_dict() for uid, player in self.players.items()},
            'game_board': self.game_board.to_dict() if self.game_board else None,
            'settings': self.settings,
            'current_turn': self.current_turn,
            'dutch_called': self.dutch_called,
            'dutch_caller': self.dutch_caller
        }
        
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'GameSession':
        """Create a GameSession instance from a dictionary."""
        if 'created_at' in data:
            data['created_at'] = datetime.fromisoformat(data['created_at'])
        if 'started_at' in data and data['started_at']:
            data['started_at'] = datetime.fromisoformat(data['started_at'])
        if 'ended_at' in data and data['ended_at']:
            data['ended_at'] = datetime.fromisoformat(data['ended_at'])
            
        # Convert player dictionaries to PlayerState objects
        if 'players' in data:
            data['players'] = {
                uid: PlayerState.from_dict(player_data)
                for uid, player_data in data['players'].items()
            }
            
        # Convert game board dictionary to GameBoard object
        if 'game_board' in data and data['game_board']:
            data['game_board'] = GameBoard.from_dict(data['game_board'])
            
        return cls(**data) 
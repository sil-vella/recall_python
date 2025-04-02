from dataclasses import dataclass
from typing import Dict, Any, List, Optional
from datetime import datetime
from .player_state import PlayerState
from .game_board import GameBoard

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
        
    def end_game(self) -> None:
        """End the game session."""
        self.status = 'finished'
        self.ended_at = datetime.utcnow()
        
    def cancel_game(self) -> None:
        """Cancel the game session."""
        self.status = 'cancelled'
        self.ended_at = datetime.utcnow()
        
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
            'settings': self.settings
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
from typing import Dict, Any, Optional, List
from datetime import datetime
import uuid
from core.managers.redis_manager import RedisManager
from .models.player_state import PlayerState
from .models.game_board import GameBoard
from .models.game_session import GameSession

class StateManager:
    """Manages game state persistence and retrieval."""
    
    def __init__(self, redis_manager: RedisManager):
        self.redis = redis_manager
        self.session_prefix = "game:session:"
        self.board_prefix = "game:board:"
        self.player_prefix = "game:player:"
        
    def create_session(self, game_id: str, settings: Dict[str, Any] = None) -> GameSession:
        """Create a new game session."""
        session_id = str(uuid.uuid4())
        session = GameSession(
            session_id=session_id,
            game_id=game_id,
            settings=settings or {}
        )
        self._save_session(session)
        return session
        
    def get_session(self, session_id: str) -> Optional[GameSession]:
        """Retrieve a game session by ID."""
        data = self.redis.get(f"{self.session_prefix}{session_id}")
        if data:
            return GameSession.from_dict(data)
        return None
        
    def update_session(self, session: GameSession) -> None:
        """Update an existing game session."""
        self._save_session(session)
        
    def delete_session(self, session_id: str) -> None:
        """Delete a game session and its associated data."""
        session = self.get_session(session_id)
        if session:
            # Delete associated game board
            if session.game_board:
                self.redis.delete(f"{self.board_prefix}{session.game_board.game_id}")
            # Delete player states
            for player_id in session.players:
                self.redis.delete(f"{self.player_prefix}{player_id}")
            # Delete session
            self.redis.delete(f"{self.session_prefix}{session_id}")
            
    def get_active_sessions(self) -> List[GameSession]:
        """Get all active game sessions."""
        sessions = []
        for key in self.redis.keys(f"{self.session_prefix}*"):
            data = self.redis.get(key)
            if data:
                session = GameSession.from_dict(data)
                if session.status == 'active':
                    sessions.append(session)
        return sessions
        
    def _save_session(self, session: GameSession) -> None:
        """Save a game session to Redis."""
        self.redis.set(
            f"{self.session_prefix}{session.session_id}",
            session.to_dict(),
            expire=3600  # 1 hour expiration
        )
        
    def save_player_state(self, player: PlayerState) -> None:
        """Save a player's state to Redis."""
        self.redis.set(
            f"{self.player_prefix}{player.user_id}",
            player.to_dict(),
            expire=3600  # 1 hour expiration
        )
        
    def get_player_state(self, user_id: str) -> Optional[PlayerState]:
        """Retrieve a player's state by user ID."""
        data = self.redis.get(f"{self.player_prefix}{user_id}")
        if data:
            return PlayerState.from_dict(data)
        return None
        
    def save_game_board(self, board: GameBoard) -> None:
        """Save a game board to Redis."""
        self.redis.set(
            f"{self.board_prefix}{board.game_id}",
            board.to_dict(),
            expire=3600  # 1 hour expiration
        )
        
    def get_game_board(self, game_id: str) -> Optional[GameBoard]:
        """Retrieve a game board by game ID."""
        data = self.redis.get(f"{self.board_prefix}{game_id}")
        if data:
            return GameBoard.from_dict(data)
        return None 
from typing import Dict, Any, Optional
from flask_socketio import emit, join_room, leave_room
from core.managers.websocket_manager import WebSocketManager
from ..game_state_module.state_manager import StateManager
from ..game_state_module.models.game_session import GameSession
from ..game_state_module.models.player_state import PlayerState
from ..game_rules_module.rules_engine import GameRulesEngine
from ..game_rules_module.action_validator import GameActionValidator
from ..game_events_module.event_validators import GameEventValidators
from datetime import datetime

class GameEventHandlers:
    """Handles game-specific WebSocket events."""
    
    def __init__(self, websocket_manager: WebSocketManager, state_manager: StateManager,
                 rules_engine: GameRulesEngine, action_validator: GameActionValidator,
                 event_validators: GameEventValidators):
        self.ws_manager = websocket_manager
        self.state_manager = state_manager
        self.rules_engine = rules_engine
        self.action_validator = action_validator
        self.event_validators = event_validators
        
    def handle_join_game(self, session_id: str, data: Dict[str, Any]) -> None:
        """Handle a player joining a game session."""
        try:
            game_session_id = data.get('session_id')
            if not game_session_id:
                emit('error', {'message': 'Missing session ID'}, room=session_id)
                return
                
            session = self.state_manager.get_session(game_session_id)
            if not session:
                emit('error', {'message': 'Game session not found'}, room=session_id)
                return
                
            # Get user data from session
            user_data = self.ws_manager.get_session_data(session_id)
            if not user_data:
                emit('error', {'message': 'User session not found'}, room=session_id)
                return
                
            # Create player state
            player = PlayerState(
                user_id=str(user_data['id']),
                username=user_data.get('username', 'Anonymous')
            )
            
            # Add player to session
            session.add_player(player)
            self.state_manager.update_session(session)
            self.state_manager.save_player_state(player)
            
            # Join the game room
            join_room(game_session_id, sid=session_id)
            
            # Emit success event
            emit('game_joined', {
                'session_id': game_session_id,
                'player': player.to_dict(),
                'game_state': session.to_dict()
            }, room=session_id)
            
            # Notify other players
            emit('player_joined_game', {
                'player': player.to_dict()
            }, room=game_session_id, include_self=False)
            
        except Exception as e:
            emit('error', {'message': f'Failed to join game: {str(e)}'}, room=session_id)
            
    def handle_leave_game(self, session_id: str, data: Dict[str, Any]) -> None:
        """Handle a player leaving a game session."""
        try:
            game_session_id = data.get('session_id')
            if not game_session_id:
                emit('error', {'message': 'Missing session ID'}, room=session_id)
                return
                
            session = self.state_manager.get_session(game_session_id)
            if not session:
                emit('error', {'message': 'Game session not found'}, room=session_id)
                return
                
            # Get user data
            user_data = self.ws_manager.get_session_data(session_id)
            if not user_data:
                emit('error', {'message': 'User session not found'}, room=session_id)
                return
                
            user_id = str(user_data['id'])
            
            # Remove player from session
            session.remove_player(user_id)
            self.state_manager.update_session(session)
            
            # Leave the game room
            leave_room(game_session_id, sid=session_id)
            
            # Emit success event
            emit('game_left', {
                'session_id': game_session_id
            }, room=session_id)
            
            # Notify other players
            emit('player_left_game', {
                'user_id': user_id
            }, room=game_session_id, include_self=False)
            
        except Exception as e:
            emit('error', {'message': f'Failed to leave game: {str(e)}'}, room=session_id)
            
    def handle_game_action(self, session_id: str, data: Dict[str, Any]) -> None:
        """Handle a player's game action."""
        try:
            game_session_id = data.get('session_id')
            action = data.get('action')
            
            if not game_session_id or not action:
                emit('error', {'message': 'Missing session ID or action'}, room=session_id)
                return
                
            session = self.state_manager.get_session(game_session_id)
            if not session:
                emit('error', {'message': 'Game session not found'}, room=session_id)
                return
                
            if session.status != 'active':
                emit('error', {'message': 'Game is not active'}, room=session_id)
                return
                
            # Get user data
            user_data = self.ws_manager.get_session_data(session_id)
            if not user_data:
                emit('error', {'message': 'User session not found'}, room=session_id)
                return
                
            user_id = str(user_data['id'])
            
            # Validate player is in the game
            if user_id not in session.players:
                emit('error', {'message': 'Player not in game'}, room=session_id)
                return
                
            # Process the action (to be implemented by game rules)
            # This is a placeholder for the actual game logic
            action_result = {
                'user_id': user_id,
                'action': action,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Broadcast the action to all players
            emit('game_action', action_result, room=game_session_id)
            
        except Exception as e:
            emit('error', {'message': f'Failed to process game action: {str(e)}'}, room=session_id) 
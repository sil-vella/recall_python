from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime
from ..game_state_module.state_manager import StateManager
from ..game_state_module.models.game_session import GameSession
from ..game_state_module.models.player_state import PlayerState
from ..game_cards_module.card_manager import CardManager

class GameRulesEngine:
    """Handles game rules and logic for the Dutch card game."""
    
    def __init__(self, state_manager: StateManager):
        self.state_manager = state_manager
        self.card_manager = CardManager()
        
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
        if not self._validate_action_data(action_type, action_data, session, player):
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
        # If a player has called "Dutch", the game is over
        if session.dutch_called:
            # Find the player with the lowest score
            lowest_score = float('inf')
            winner = None
            
            for player in session.players.values():
                if player.score < lowest_score:
                    lowest_score = player.score
                    winner = player
                    
            return True, winner
            
        # If all rounds are complete, the game is over
        if session.game_board.current_round > session.game_board.max_rounds:
            # Find the player with the lowest score
            lowest_score = float('inf')
            winner = None
            
            for player in session.players.values():
                if player.score < lowest_score:
                    lowest_score = player.score
                    winner = player
                    
            return True, winner
            
        return False, None
        
    def _is_player_turn(self, session: GameSession, player: PlayerState) -> bool:
        """Check if it's the player's turn."""
        return session.current_turn == player.user_id
        
    def _validate_action_data(self, action_type: str, action_data: Dict[str, Any], session: GameSession, player: PlayerState) -> bool:
        """Validate action data based on action type."""
        if action_type == "play_card":
            # Validate card play
            card_id = action_data.get("card_id")
            if not card_id:
                return False
                
            # Check if player has the card
            if not player.has_card(card_id):
                return False
                
            # Check if it's a valid play (follows suit if possible)
            card = self.card_manager.get_card_by_id(card_id)
            if not card:
                return False
                
            # If there's a lead suit and the player has a card of that suit, they must play it
            if session.game_board.lead_suit:
                has_lead_suit = any(c['suit'] == session.game_board.lead_suit for c in player.hand)
                if has_lead_suit and card.suit != session.game_board.lead_suit:
                    return False
                    
            return True
            
        elif action_type == "call_dutch":
            # Validate Dutch call
            # Player can only call Dutch if they haven't already
            if player.has_called_dutch:
                return False
                
            return True
            
        # Add other action types
        return True
        
    def _process_action_by_type(self, session: GameSession, player: PlayerState, action_type: str, action_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process an action based on its type."""
        if action_type == "play_card":
            # Process card play
            card_id = action_data.get("card_id")
            card = self.card_manager.get_card_by_id(card_id)
            
            # Remove card from player's hand
            player.remove_card(card_id)
            
            # Add card to the current trick
            session.game_board.play_card(player.user_id, self.card_manager.card_to_dict(card))
            
            # Check if the trick is complete
            if len(session.game_board.current_trick) == len(session.players):
                # End the trick and determine the winner
                session.game_board.end_trick()
                
                # Award the trick to the winner
                winner_id = session.game_board.trick_winner
                if winner_id in session.players:
                    winner = session.players[winner_id]
                    winner.win_trick()
                    
                    # Calculate points for the trick
                    points = self.card_manager.calculate_points([self.card_manager.card_to_dict(card) for card in session.game_board.current_trick])
                    winner.update_score(points)
                    
                    # Set the winner as the next player's turn
                    session.current_turn = winner_id
                else:
                    # If no winner, move to the next player
                    session.next_turn()
                    
                # Check if the round is complete
                if session.game_board.current_round >= session.game_board.max_rounds:
                    # End the game
                    session.end_game()
                else:
                    # Move to the next round
                    session.game_board.update_round()
            else:
                # Move to the next player's turn
                session.next_turn()
                
            return {
                "type": "card_played",
                "player_id": player.user_id,
                "card": self.card_manager.card_to_dict(card),
                "trick_complete": len(session.game_board.current_trick) == len(session.players),
                "trick_winner": session.game_board.trick_winner,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        elif action_type == "call_dutch":
            # Process Dutch call
            player.call_dutch()
            session.call_dutch(player.user_id)
            
            return {
                "type": "dutch_called",
                "player_id": player.user_id,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        # Add other action types
        return {
            "type": action_type,
            "player_id": player.user_id,
            "timestamp": datetime.utcnow().isoformat(),
            "data": action_data
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
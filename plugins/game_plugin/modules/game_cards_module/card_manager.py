from typing import Dict, Any, List
import random
from dataclasses import dataclass

@dataclass
class Card:
    """Represents a card in the Dutch card game."""
    id: str
    rank: str
    suit: str
    color: str
    value: int
    special_ability: str = None

class CardManager:
    """Manages card operations for the Dutch card game."""
    
    def __init__(self):
        # Initialize the deck with all cards
        self.cards = self._initialize_deck()
        
    def _initialize_deck(self) -> List[Card]:
        """Initialize the deck with all cards."""
        cards = []
        
        # Define suits and their colors
        suits = {
            'hearts': 'red',
            'diamonds': 'red',
            'clubs': 'black',
            'spades': 'black'
        }
        
        # Define ranks and their values
        ranks = {
            '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9, '10': 10,
            'J': 11, 'Q': 12, 'K': 13, 'A': 14
        }
        
        # Create all cards
        for suit, color in suits.items():
            for rank, value in ranks.items():
                card_id = f"{rank}_{suit}"
                special_ability = None
                
                # Assign special abilities to Queens and Jacks
                if rank == 'Q':
                    special_ability = "queen_ability"
                elif rank == 'J':
                    special_ability = "jack_ability"
                
                cards.append(Card(
                    id=card_id,
                    rank=rank,
                    suit=suit,
                    color=color,
                    value=value,
                    special_ability=special_ability
                ))
        
        return cards
    
    def shuffle_deck(self) -> List[Card]:
        """Shuffle the deck and return a new deck."""
        deck = self.cards.copy()
        random.shuffle(deck)
        return deck
    
    def deal_cards(self, deck: List[Card], num_players: int, cards_per_player: int) -> Dict[str, List[Card]]:
        """Deal cards to players."""
        hands = {}
        for i in range(num_players):
            hand = deck[i * cards_per_player:(i + 1) * cards_per_player]
            hands[f"player_{i}"] = hand
        return hands
    
    def get_card_by_id(self, card_id: str) -> Card:
        """Get a card by its ID."""
        for card in self.cards:
            if card.id == card_id:
                return card
        return None
    
    def calculate_points(self, cards: List[Card]) -> int:
        """Calculate points for a set of cards."""
        points = 0
        for card in cards:
            # Queens are worth 13 points
            if card.rank == 'Q':
                points += 13
            # Jacks are worth 11 points
            elif card.rank == 'J':
                points += 11
            # Aces are worth 14 points
            elif card.rank == 'A':
                points += 14
            # Kings are worth 13 points
            elif card.rank == 'K':
                points += 13
            # Other cards are worth their face value
            else:
                points += card.value
        return points
    
    def card_to_dict(self, card: Card) -> Dict[str, Any]:
        """Convert a card to a dictionary for serialization."""
        return {
            'id': card.id,
            'rank': card.rank,
            'suit': card.suit,
            'color': card.color,
            'value': card.value,
            'special_ability': card.special_ability
        }
    
    def cards_to_dict(self, cards: List[Card]) -> List[Dict[str, Any]]:
        """Convert a list of cards to dictionaries for serialization."""
        return [this.card_to_dict(card) for card in cards] 
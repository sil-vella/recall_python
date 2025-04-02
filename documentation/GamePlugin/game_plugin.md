# Game Plugin Documentation

## Overview
The Game Plugin is a modular system for handling real-time multiplayer games. It provides a robust foundation for game state management, event handling, and rule enforcement through WebSocket communication.

## Core Components

### 1. Game State Module
The Game State Module manages all game-related state and persistence.

#### Models

##### PlayerState
```python
@dataclass
class PlayerState:
    user_id: str
    username: str
    score: int = 0
    is_active: bool = True
    last_active: datetime = datetime.utcnow()
    game_data: Dict[str, Any] = None
```
- Represents a player's state in the game
- Tracks score, activity status, and game-specific data
- Provides serialization methods for Redis storage

##### GameBoard
```python
@dataclass
class GameBoard:
    game_id: str
    current_round: int = 1
    max_rounds: int = 10
    is_active: bool = True
    created_at: datetime = datetime.utcnow()
    last_updated: datetime = datetime.utcnow()
    board_data: Dict[str, Any] = None
    round_history: List[Dict[str, Any]] = None
```
- Manages the game board state
- Tracks rounds and game progress
- Stores board-specific data and round history

##### GameSession
```python
@dataclass
class GameSession:
    session_id: str
    game_id: str
    created_at: datetime = datetime.utcnow()
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    status: str = 'waiting'  # waiting, active, finished, cancelled
    players: Dict[str, PlayerState] = None
    game_board: Optional[GameBoard] = None
    settings: Dict[str, Any] = None
```
- Represents a complete game session
- Manages player participation
- Controls game lifecycle (waiting, active, finished, cancelled)

#### StateManager
The StateManager handles all state persistence and retrieval operations.

Key Features:
- Redis-based state storage
- Session management
- Player state tracking
- Game board persistence
- Automatic cleanup of expired sessions

### 2. Game Events Module
The Game Events Module handles all WebSocket communication for game-related events.

#### Event Handlers
```python
class GameEventHandlers:
    def handle_join_game(self, session_id: str, data: Dict[str, Any]) -> None
    def handle_leave_game(self, session_id: str, data: Dict[str, Any]) -> None
    def handle_game_action(self, session_id: str, data: Dict[str, Any]) -> None
```

Supported Events:
1. `join_game`
   - Handles player joining a game session
   - Creates player state
   - Updates session state
   - Notifies other players

2. `leave_game`
   - Handles player leaving a game session
   - Removes player state
   - Updates session state
   - Notifies other players

3. `game_action`
   - Processes player actions
   - Validates action against game rules
   - Updates game state
   - Broadcasts results to all players

#### Event Validators
```python
class GameEventValidators:
    def validate_join_game(self, data: Dict[str, Any]) -> Tuple[bool, Optional[str]]
    def validate_leave_game(self, data: Dict[str, Any]) -> Tuple[bool, Optional[str]]
    def validate_game_action(self, data: Dict[str, Any]) -> Tuple[bool, Optional[str]]
    def validate_game_state(self, session: GameSession) -> Tuple[bool, Optional[str]]
```

### 3. Game Rules Module
The Game Rules Module enforces game rules and processes player actions.

#### Rules Engine
```python
class GameRulesEngine:
    def validate_action(self, session: GameSession, player: PlayerState, action: Dict[str, Any]) -> Tuple[bool, Optional[str]]
    def process_action(self, session: GameSession, player: PlayerState, action: Dict[str, Any]) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]
    def check_win_condition(self, session: GameSession) -> Tuple[bool, Optional[PlayerState]]
```

#### Action Validator
```python
class GameActionValidator:
    def validate_action(self, action: Dict[str, Any]) -> Tuple[bool, Optional[str]]
```

Supported Action Types:
1. `move`
   - Validates move actions
   - Checks position validity
   - Verifies move legality

2. `answer`
   - Validates answer submissions
   - Checks answer format
   - Verifies answer content

3. `skip`
   - Handles turn skipping
   - Validates skip conditions

4. `end_turn`
   - Manages turn completion
   - Validates turn end conditions

## WebSocket Events

### Client to Server
1. `join_game`
   ```json
   {
     "session_id": "game-session-uuid"
   }
   ```

2. `leave_game`
   ```json
   {
     "session_id": "game-session-uuid"
   }
   ```

3. `game_action`
   ```json
   {
     "session_id": "game-session-uuid",
     "action": {
       "type": "move|answer|skip|end_turn",
       "data": {
         // Action-specific data
       }
     }
   }
   ```

### Server to Client
1. `game_joined`
   ```json
   {
     "session_id": "game-session-uuid",
     "player": {
       "user_id": "user-uuid",
       "username": "player-name",
       "score": 0,
       "is_active": true
     },
     "game_state": {
       // Complete game session state
     }
   }
   ```

2. `player_joined_game`
   ```json
   {
     "player": {
       // Player state
     }
   }
   ```

3. `game_left`
   ```json
   {
     "session_id": "game-session-uuid"
   }
   ```

4. `player_left_game`
   ```json
   {
     "user_id": "user-uuid"
   }
   ```

5. `game_action`
   ```json
   {
     "user_id": "user-uuid",
     "action": {
       // Action details
     },
     "timestamp": "ISO-8601 timestamp"
   }
   ```

6. `error`
   ```json
   {
     "message": "Error description"
   }
   ```

## Redis Storage

### Key Patterns
1. Game Sessions: `game:session:{session_id}`
2. Game Boards: `game:board:{game_id}`
3. Player States: `game:player:{user_id}`

### Data Expiration
- All game data expires after 1 hour (3600 seconds)
- This prevents stale data accumulation

## Error Handling

### Common Error Scenarios
1. Invalid Session
   - Missing session ID
   - Session not found
   - Session already ended

2. Invalid Player
   - Player not in game
   - Player already in game
   - Invalid player state

3. Invalid Action
   - Missing action type
   - Invalid action data
   - Action not allowed

4. Game State Errors
   - Game not active
   - Invalid game state
   - Missing required data

## Security Considerations

### Authentication
- All WebSocket connections require valid JWT tokens
- Player actions are validated against user identity

### Authorization
- Room access is controlled by WebSocket manager
- Game actions are validated against player permissions

### Data Validation
- All incoming data is validated
- Action data is sanitized
- State changes are atomic

## Performance Considerations

### State Management
- Redis-based state storage for fast access
- Efficient serialization/deserialization
- Atomic operations for state updates

### Event Handling
- Asynchronous event processing
- Efficient room-based broadcasting
- Optimized state updates

## Usage Examples

### Creating a New Game Session
```python
# Initialize managers
state_manager = StateManager(redis_manager)
event_handlers = GameEventHandlers(websocket_manager, state_manager)

# Create new session
session = state_manager.create_session(
    game_id="trivia_game",
    settings={
        "max_players": 4,
        "round_time": 30,
        "score_multiplier": 1.5
    }
)
```

### Handling Player Join
```python
# Client sends join_game event
@websocket.on('join_game')
def on_join_game(data):
    event_handlers.handle_join_game(request.sid, data)
```

### Processing Game Action
```python
# Client sends game_action event
@websocket.on('game_action')
def on_game_action(data):
    event_handlers.handle_game_action(request.sid, data)
```

## Integration with Other Modules

### WebSocket Manager
- Handles connection management
- Manages room subscriptions
- Provides session data

### Redis Manager
- Provides state persistence
- Handles data serialization
- Manages data expiration

### JWT Manager
- Handles authentication
- Manages token validation
- Controls access permissions

## Future Enhancements

### Planned Features
1. Game Replay System
   - Record game actions
   - Replay game sessions
   - Analyze game history

2. Advanced Analytics
   - Player performance tracking
   - Game statistics
   - Leaderboard integration

3. Enhanced Security
   - Rate limiting
   - Anti-cheat measures
   - Action validation

4. Performance Optimizations
   - State compression
   - Batch updates
   - Caching strategies

## Best Practices

### Development
1. Always validate input data
2. Use type hints for better code clarity
3. Implement proper error handling
4. Write comprehensive tests

### Deployment
1. Monitor Redis memory usage
2. Set appropriate TTL values
3. Implement proper logging
4. Use connection pooling

### Security
1. Validate all user input
2. Implement rate limiting
3. Use secure WebSocket connections
4. Regular security audits 
from tools.logger.custom_logging import custom_log
from flask import request, jsonify

from plugins.game_plugin.modules.function_helper_module.function_helper_module import FunctionHelperModule
from plugins.game_plugin.modules.game_state_module.state_manager import StateManager
from plugins.game_plugin.modules.game_events_module.event_handlers import GameEventHandlers
from plugins.game_plugin.modules.game_events_module.event_validators import GameEventValidators
from plugins.game_plugin.modules.game_rules_module.rules_engine import GameRulesEngine
from plugins.game_plugin.modules.game_rules_module.action_validator import GameActionValidator


class GamePlugin:
    def initialize(self, app_manager):
        """
        Initialize the GamePlugin with AppManager.
        :param app_manager: AppManager - The main application manager.
        """
        custom_log("Initializing GamePlugin...")

        try:
            # First, ensure ConnectionAPI is available
            connection_api = app_manager.module_manager.get_module("connection_api")
            if not connection_api:
                raise RuntimeError("ConnectionAPI is not registered in ModuleManager.")

            # Register function helper module
            app_manager.module_manager.register_module(
                "function_helper_module", 
                FunctionHelperModule, 
                app_manager=app_manager
            )
            
            # Register state management module
            app_manager.module_manager.register_module(
                "game_state_module",
                StateManager,
                redis_manager=app_manager.websocket_manager.redis_manager
            )
            
            # Register rules engine module
            app_manager.module_manager.register_module(
                "game_rules_engine",
                GameRulesEngine,
                state_manager=app_manager.module_manager.get_module("game_state_module")
            )
            
            # Register action validator module
            app_manager.module_manager.register_module(
                "game_action_validator",
                GameActionValidator
            )
            
            # Register event validators module
            app_manager.module_manager.register_module(
                "game_event_validators",
                GameEventValidators,
                state_manager=app_manager.module_manager.get_module("game_state_module")
            )
            
            # Register event handlers module
            app_manager.module_manager.register_module(
                "game_event_handlers",
                GameEventHandlers,
                None,  # app_manager is not needed for GameEventHandlers
                app_manager.websocket_manager,
                app_manager.module_manager.get_module("game_state_module"),
                app_manager.module_manager.get_module("game_rules_engine"),
                app_manager.module_manager.get_module("game_action_validator"),
                app_manager.module_manager.get_module("game_event_validators")
            )

            # Register game event handlers with WebSocket manager
            game_event_handlers = app_manager.module_manager.get_module("game_event_handlers")
            app_manager.websocket_manager.register_authenticated_handler('join_game', game_event_handlers.handle_join_game)
            app_manager.websocket_manager.register_authenticated_handler('leave_game', game_event_handlers.handle_leave_game)
            app_manager.websocket_manager.register_authenticated_handler('game_action', game_event_handlers.handle_game_action)

            # Register API routes
            self._register_routes(app_manager)

            custom_log("GamePlugin initialized successfully")

        except Exception as e:
            custom_log(f"Error initializing GamePlugin: {e}")
            raise

    def _register_routes(self, app_manager):
        """Register API routes for the game plugin."""
        @app_manager.flask_app.route('/api/game/create_session', methods=['POST'])
        def create_game_session():
            try:
                # Get user data from JWT token
                auth_header = request.headers.get('Authorization')
                if not auth_header or not auth_header.startswith('Bearer '):
                    return jsonify({'error': 'No token provided'}), 401

                token = auth_header.split(' ')[1]
                user_data = app_manager.jwt_manager.verify_token(token)
                if not user_data:
                    return jsonify({'error': 'Invalid token'}), 401

                # Get request data
                data = request.get_json()
                if not data:
                    return jsonify({'error': 'No data provided'}), 400

                game_id = data.get('game_id')
                settings = data.get('settings', {})

                if not game_id:
                    return jsonify({'error': 'Game ID is required'}), 400

                # Create new game session
                state_manager = app_manager.module_manager.get_module("game_state_module")
                session = state_manager.create_session(game_id, settings)

                return jsonify({
                    'session_id': session.session_id,
                    'game_id': session.game_id,
                    'status': session.status
                })

            except Exception as e:
                custom_log(f"Error creating game session: {e}")
                return jsonify({'error': str(e)}), 500
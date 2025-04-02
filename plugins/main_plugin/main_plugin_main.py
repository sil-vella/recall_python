from plugins.main_plugin.modules.connection_api.connection_api import ConnectionAPI
from plugins.main_plugin.modules.login_module.login_module import LoginModule
from plugins.main_plugin.modules.websocket_module.websocket_module import WebSocketModule

class MainPlugin:
    def initialize(self, app_manager):
        """
        Initialize the MainPlugin with AppManager.
        :param app_manager: AppManager - The main application manager.
        """
        print("Initializing MainPlugin...")

        try:
            # Ensure ConnectionAPI is registered FIRST
            if not app_manager.module_manager.get_module("connection_api"):
                print("Registering ConnectionAPI...")
                app_manager.module_manager.register_module(
                    "connection_api", 
                    ConnectionAPI, 
                    app_manager=app_manager
                )

            # Retrieve the ConnectionAPI
            connection_api = app_manager.module_manager.get_module("connection_api")
            if not connection_api:
                raise Exception("ConnectionAPI is not registered in ModuleManager.")

            connection_api.initialize(app_manager.flask_app)

            # Register WebSocket Module
            if not app_manager.module_manager.get_module("websocket_module"):
                print("Registering WebSocket Module...")
                app_manager.module_manager.register_module(
                    "websocket_module",
                    WebSocketModule,
                    app_manager=app_manager
                )

            # Ensure LoginModule is registered LAST
            if not app_manager.module_manager.get_module("login_module"):
                print("Registering LoginModule...")
                app_manager.module_manager.register_module(
                    "login_module", 
                    LoginModule, 
                    app_manager=app_manager
                )

            login_module = app_manager.module_manager.get_module("login_module")
            if login_module:
                login_module.register_routes() 

            print("MainPlugin initialized successfully.")

            # Register the `/` route with the correct view function
            connection_api.register_route("/", self.home, methods=["GET"])
            print("Route '/' registered successfully.")
        except Exception as e:
            print(f"Error initializing MainPlugin: {e}")
            raise

    def home(self):
        """Handle the root route."""
        return "Flush Me I'm Famousapp / route."

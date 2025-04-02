from plugins.plugin_registry import PluginRegistry
from tools.logger.custom_logging import custom_log, function_log, game_play_log, log_function_call

class PluginManager:
    def __init__(self):
        # Dictionary to store registered plugins
        self.plugins = {}
        custom_log("PluginManager instance created.")

    @log_function_call
    def register_plugins(self, app_manager):
        """
        Fetch plugins from PluginRegistry and register them.
        :param app_manager: AppManager - The main application manager.
        """
        custom_log("Registering plugins...")

        # Get plugins from PluginRegistry
        plugin_definitions = PluginRegistry.get_plugins()

        for plugin_key, plugin_class in plugin_definitions.items():
            # Instantiate and register the plugin
            plugin_instance = plugin_class()
            self.register_plugin(plugin_key, plugin_instance)

        # Initialize plugins
        for plugin_key, plugin_instance in self.plugins.items():
            if hasattr(plugin_instance, "initialize"):
                custom_log(f"Initializing plugin: {plugin_key}")
                plugin_instance.initialize(app_manager)
                custom_log(f"Plugin '{plugin_key}' initialized successfully.")

    @log_function_call
    def register_plugin(self, plugin_key, plugin_instance):
        """
        Register a plugin instance by name.
        :param plugin_key: str - The unique key for the plugin.
        :param plugin_instance: object - The plugin instance.
        """
        if plugin_key in self.plugins:
            raise ValueError(f"Plugin '{plugin_key}' is already registered.")
        
        self.plugins[plugin_key] = plugin_instance
        custom_log(f"Plugin '{plugin_key}' registered successfully.")

    @log_function_call
    def get_plugin(self, plugin_key):
        """
        Retrieve a plugin by its key.
        :param plugin_key: str - The unique identifier for the plugin.
        :return: object - The plugin instance or None if not found.
        """
        plugin = self.plugins.get(plugin_key)
        custom_log(f"Retrieved plugin '{plugin_key}': {plugin}")
        return plugin
    
    @log_function_call
    def get_all_plugins(self):
        """Returns all registered plugin instances."""
        return self.plugins.values()

    @log_function_call
    def dispose_plugins(self):
        """
        Dispose of all registered plugins.
        """
        for plugin_key, plugin in self.plugins.items():
            if hasattr(plugin, "dispose"):
                custom_log(f"Disposing plugin: {plugin_key}")
                plugin.dispose()
        
        self.plugins.clear()
        custom_log("All plugins have been disposed of.")

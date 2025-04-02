class PluginRegistry:
    """
    A static registry of all available plugins.
    """
    @staticmethod
    def get_plugins():
        """
        Return a dictionary of plugin keys and their corresponding classes.
        :return: dict - A dictionary mapping plugin keys to plugin classes.
        """
        from plugins.main_plugin.main_plugin_main import MainPlugin
        from plugins.game_plugin.game_plugin_main import GamePlugin

        return {
            "main_plugin": MainPlugin,
            "game_plugin": GamePlugin,

        }

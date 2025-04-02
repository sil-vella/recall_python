from tools.logger.custom_logging import custom_log, function_log, game_play_log, log_function_call

class ModuleManager:
    def __init__(self):
        # A dictionary to hold all registered modules
        self.modules = {}
        custom_log("ModuleManager instance created.")

    @log_function_call
    def register_module(self, module_key, module_class, app_manager=None, *args, **kwargs):
        """
        Register and initialize a module.
        :param module_key: str - The unique key for the module.
        :param module_class: type - The class of the module to initialize.
        :param app_manager: AppManager - The central application manager to pass to modules.
        :param args: list - Positional arguments for the module class.
        :param kwargs: dict - Keyword arguments for the module class.
        """
        if module_key in self.modules:
            raise ValueError(f"Module with key '{module_key}' is already registered.")
        
        # Pass the app_manager as a keyword argument if provided
        if app_manager:
            kwargs['app_manager'] = app_manager

        # Instantiate the module
        module_instance = module_class(*args, **kwargs)
        self.modules[module_key] = module_instance
        custom_log(f"Module '{module_key}' registered successfully.")

    @log_function_call
    def get_module(self, module_key):
        """
        Retrieve a registered module.
        :param module_key: str - The unique key for the module.
        :return: object - The module instance or None if not found.
        """
        module = self.modules.get(module_key)
        if not module:
            custom_log(f"Error: Module '{module_key}' is not registered.")
        else:
            custom_log(f"Retrieved module '{module_key}': {module}")
        return module


    @log_function_call
    def call_module_method(self, module_key, method_name, *args, **kwargs):
        """
        Dynamically call a method on a registered module.
        :param module_key: str - The unique key for the module.
        :param method_name: str - The name of the method to call.
        :param args: list - Positional arguments for the method.
        :param kwargs: dict - Keyword arguments for the method.
        :return: Any - The return value of the method call.
        """
        module = self.get_module(module_key)
        if not module:
            raise ValueError(f"Module with key '{module_key}' is not registered.")
        if not hasattr(module, method_name):
            raise AttributeError(f"Module '{module_key}' has no method '{method_name}'.")

        custom_log(f"Calling method '{method_name}' on module '{module_key}' with args: {args}, kwargs: {kwargs}")
        result = getattr(module, method_name)(*args, **kwargs)
        custom_log(f"Method '{method_name}' on module '{module_key}' returned: {result}")
        return result

    @log_function_call
    def dispose(self):
        """
        Dispose of all registered modules, calling their cleanup methods if available.
        """
        for module_key, module in self.modules.items():
            if hasattr(module, "dispose"):
                custom_log(f"Disposing module: {module_key}")
                module.dispose()

        self.modules.clear()
        custom_log("All modules have been disposed of.")

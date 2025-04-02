from tools.logger.custom_logging import custom_log, function_log, game_play_log, log_function_call

class HooksManager:
    def __init__(self):
        # A dictionary to hold hooks and their callbacks with priorities and optional context
        self.hooks = {
            "app_startup": [],  # Predefined default hook
        }
        custom_log("HooksManager instance created.")

    @log_function_call
    def register_hook(self, hook_name):
        """
        Register a new hook with the given name.
        :param hook_name: str - The name of the hook to register.
        """
        if hook_name in self.hooks:
            raise ValueError(f"Hook '{hook_name}' is already registered.")
        
        self.hooks[hook_name] = []
        custom_log(f"Hook '{hook_name}' registered successfully.")

    @log_function_call
    def register_hook_callback(self, hook_name, callback, priority=10, context=None):
        """
        Register a callback function to a specific hook with a priority and optional context.
        :param hook_name: str - The name of the hook.
        :param callback: function - The callback function to register.
        :param priority: int - The priority of the callback (lower number = higher priority).
        :param context: str - The optional context (e.g., article type) for the callback.
        """
        if hook_name not in self.hooks:
            raise ValueError(f"Hook '{hook_name}' is not registered.")
        
        # Add the callback to the hook
        self.hooks[hook_name].append({
            "priority": priority,
            "callback": callback,
            "context": context
        })
        
        # Sort callbacks by priority
        self.hooks[hook_name].sort(key=lambda x: x["priority"])

        # Detailed logging of the callback registration
        context_info = f" (context: {context})" if context else ""
        callback_name = callback.__name__ if hasattr(callback, "__name__") else str(callback)
        custom_log(f"Callback '{callback_name}' registered to hook '{hook_name}' with priority {priority}{context_info}.")

    @log_function_call
    def trigger_hook(self, hook_name, data=None, context=None):
        """
        Trigger a specific hook, executing only callbacks matching the context.
        :param hook_name: str - The name of the hook to trigger.
        :param data: Any - Optional data to pass to the callbacks.
        :param context: str - The context to filter callbacks (e.g., article type).
        """
        if hook_name not in self.hooks:
            custom_log(f"Warning: Hook '{hook_name}' is not registered. Skipping trigger.")
            return
        
        custom_log(f"Triggering hook '{hook_name}' with context: {context} and data: {data}")

        for entry in self.hooks[hook_name]:
            # Execute only callbacks matching the context or global callbacks (no context)
            if context is None or entry["context"] == context:
                custom_log(f"Executing callback for hook '{hook_name}' with priority {entry['priority']} (context: {entry['context']}).")
                entry["callback"](data)

    @log_function_call
    def clear_hook(self, hook_name):
        """
        Clear all callbacks registered to a specific hook.
        :param hook_name: str - The name of the hook to clear.
        """
        if hook_name in self.hooks:
            self.hooks[hook_name] = []
            custom_log(f"Cleared all callbacks for hook '{hook_name}'.")
        else:
            custom_log(f"Warning: Hook '{hook_name}' is not registered. Nothing to clear.")

    @log_function_call
    def dispose(self):
        """
        Dispose of all hooks and their callbacks.
        """
        self.hooks.clear()
        custom_log("All hooks have been disposed of.")

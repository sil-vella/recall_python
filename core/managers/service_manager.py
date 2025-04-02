from tools.logger.custom_logging import custom_log, function_log, game_play_log, log_function_call

class ServicesManager:
    def __init__(self):
        # A dictionary to hold all registered services
        self.services = {}
        custom_log("ServicesManager instance created.")

    @log_function_call
    def register_service(self, service_key, service_instance):
        """
        Register a service with a unique key.
        :param service_key: str - The unique key for the service.
        :param service_instance: object - The service instance to register.
        """
        if service_key in self.services:
            raise ValueError(f"Service with key '{service_key}' is already registered.")
        
        self.services[service_key] = service_instance
        custom_log(f"Service '{service_key}' registered successfully.")

    @log_function_call
    def initialize_services(self):
        """
        Initialize all registered services that have an 'initialize' method.
        """
        for service_key, service in self.services.items():
            if hasattr(service, "initialize") and callable(service.initialize):
                custom_log(f"Initializing service: {service_key}")
                service.initialize()
        custom_log("All services have been initialized.")

    @log_function_call
    def get_service(self, service_key):
        """
        Retrieve a registered service by its key.
        :param service_key: str - The unique key for the service.
        :return: object - The service instance or None if not found.
        """
        service = self.services.get(service_key)
        custom_log(f"Retrieved service '{service_key}': {service}")
        return service

    @log_function_call
    def call_service_method(self, service_key, method_name, *args, **kwargs):
        """
        Dynamically call a method on a registered service.
        :param service_key: str - The unique key for the service.
        :param method_name: str - The name of the method to call.
        :param args: list - Positional arguments for the method.
        :param kwargs: dict - Keyword arguments for the method.
        :return: Any - The return value of the method call.
        """
        service = self.get_service(service_key)
        if not service:
            raise ValueError(f"Service with key '{service_key}' is not registered.")
        if not hasattr(service, method_name):
            raise AttributeError(f"Service '{service_key}' has no method '{method_name}'.")

        result = getattr(service, method_name)(*args, **kwargs)
        custom_log(f"Called method '{method_name}' on service '{service_key}' with result: {result}")
        return result

    @log_function_call
    def dispose(self):
        """
        Dispose of all registered services, calling their cleanup methods if available.
        """
        for service_key, service in self.services.items():
            if hasattr(service, "dispose"):
                custom_log(f"Disposing service: {service_key}")
                service.dispose()
        
        self.services.clear()
        custom_log("All services have been disposed of.")

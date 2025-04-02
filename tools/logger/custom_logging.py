import logging
import os
import json
import functools
import inspect
import types
import re
# Flags to enable or disable specific logging functionalities
CUSTOM_LOGGING_ENABLED = True
GAMEPLAY_LOGGING_ENABLED = False
FUNCTION_LOGGING_ENABLED = False

def custom_serializer(obj):
    if isinstance(obj, (set, tuple)):
        return list(obj)
    return str(obj)

class CustomFormatter(logging.Formatter):
    def __init__(self):
        super().__init__("[%(asctime)s] - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)", "%Y-%m-%d %H:%M:%S")

    def format(self, record):
        if not isinstance(record.msg, str):
            record.msg = json.dumps(record.msg, default=custom_serializer, indent=4)
        else:
            try:
                obj = json.loads(record.msg)
                record.msg = json.dumps(obj, indent=4)
            except ValueError:
                pass
        return super(CustomFormatter, self).format(record)

class SimpleFormatter(logging.Formatter):
    def __init__(self):
        super().__init__("%(asctime)s - %(message)s", "%Y-%m-%d %H:%M:%S")

# Logger for custom_log
custom_log_file_name = 'server.log'
custom_log_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), custom_log_file_name)
custom_logger = logging.getLogger('custom_log')
custom_logger.setLevel(logging.DEBUG)
custom_handler = logging.FileHandler(custom_log_file_path, 'w')
custom_handler.setFormatter(CustomFormatter())
custom_logger.addHandler(custom_handler)

# Logger for game_play_log
game_play_log_file_name = 'game_play.log'
game_play_log_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), game_play_log_file_name)
game_play_logger = logging.getLogger('game_play_log')
game_play_logger.setLevel(logging.DEBUG)
game_play_handler = logging.FileHandler(game_play_log_file_path, 'w')
game_play_handler.setFormatter(SimpleFormatter())
game_play_logger.addHandler(game_play_handler)

# Logger for function_log
function_log_file_name = 'function.log'
function_log_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), function_log_file_name)
function_logger = logging.getLogger('function_log')
function_logger.setLevel(logging.DEBUG)
function_handler = logging.FileHandler(function_log_file_path, 'w')
function_handler.setFormatter(SimpleFormatter())
function_logger.addHandler(function_handler)



def sanitize_log_message(message):
    """Ensures UTF-8 encoding and removes non-ASCII characters if necessary."""
    if not isinstance(message, str):
        message = json.dumps(message, default=custom_serializer, indent=4)
    
    try:
        # ✅ Force UTF-8 encoding
        message = message.encode('utf-8').decode('utf-8')
    except UnicodeEncodeError:
        # ✅ Fallback: Remove non-ASCII characters
        message = message.encode('ascii', 'ignore').decode('ascii')

    # ✅ Strip emojis & non-ASCII characters if needed
    message = re.sub(r'[^\x00-\x7F]+', '', message)

    return message


def custom_log(message):
    if CUSTOM_LOGGING_ENABLED:
        message = sanitize_log_message(message)
        custom_logger.debug(message)


def game_play_log(message, action=None):
    if GAMEPLAY_LOGGING_ENABLED:
        message = sanitize_log_message(message)
        game_play_logger.debug(message)


def function_log(message):
    if FUNCTION_LOGGING_ENABLED:
        message = sanitize_log_message(message)
        function_logger.debug(message)


def log_function_call(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        custom_log(f"Wrapping function {func.__name__} with logging")
        custom_log(f"Function logging enabled: {FUNCTION_LOGGING_ENABLED}")
        if FUNCTION_LOGGING_ENABLED and not getattr(func, "_logging_in_progress", False):
            custom_log(f"Setting logging in progress for {func.__name__}")
            setattr(func, "_logging_in_progress", True)
            arg_names = func.__code__.co_varnames[:func.__code__.co_argcount]
            try:
                arg_list = ', '.join(f'{name}={value}' for name, value in zip(arg_names, args))
            except AttributeError as e:
                custom_log(f"Error while logging arguments for {func.__name__}: {e}")
                arg_list = 'Error logging arguments'

            function_log(f"Entering {func.__name__} with args: {arg_list}")
            custom_log(f"Entered {func.__name__}")

            initial_locals = {k: v for k, v in locals().items() if k != 'initial_locals'}
            try:
                result = func(*args, **kwargs)
            except Exception as e:
                custom_log(f"Error while executing {func.__name__}: {e}")
                raise
            final_locals = {k: v for k, v in locals().items() if k != 'final_locals'}

            changed_vars = {var: final_locals[var] for var in final_locals if var in initial_locals and final_locals[var] != initial_locals[var]}
            for var, val in changed_vars.items():
                function_log(f"Variable {var} changed to {val}")

            function_log(f"Exiting {func.__name__} with result: {result}\n")
            custom_log(f"Exiting {func.__name__}")
            setattr(func, "_logging_in_progress", False)
        else:
            result = func(*args, **kwargs)
        return result
    wrapper._is_logged = True
    return wrapper

def add_logging_to_plugin(plugin, exclude_instances=None, exclude_packages=None):
    custom_log(f"Adding logging to plugin: {plugin.__name__}")
    exclude_functions = {log_function_call, add_logging_to_plugin, custom_log, game_play_log, function_log}
    if exclude_instances is None:
        exclude_instances = []
    if exclude_packages is None:
        exclude_packages = []

    for name, obj in inspect.getmembers(plugin):
        if isinstance(obj, types.FunctionType) and not hasattr(obj, '_is_logged'):
            if obj not in exclude_functions and name != "__init__":
                if not any(obj.__plugin__.startswith(package) for package in exclude_packages):
                    custom_log(f"Adding logging to function: {name} in plugin: {plugin.__name__}")
                    setattr(plugin, name, log_function_call(obj))
                    custom_log(f"Function {name} is now decorated.")
        elif isinstance(obj, type):  # Check if obj is a class
            custom_log(f"Class {name} found in plugin: {plugin.__name__}")
            for cls_name, cls_member in inspect.getmembers(obj):
                if isinstance(cls_member, types.FunctionType) and not hasattr(cls_member, '_is_logged'):
                    if cls_member not in exclude_functions and cls_name != "__init__":
                        if not any(cls_member.__plugin__.startswith(package) for package in exclude_packages):
                            custom_log(f"Adding logging to method: {cls_name} in class {name}")
                            setattr(obj, cls_name, log_function_call(cls_member))
                            custom_log(f"Method {cls_name} in class {name} is now decorated.")
        elif any(isinstance(obj, cls) for cls in exclude_instances):  # Skip excluded instances
            custom_log(f"Skipping logging for excluded instance: {name}")
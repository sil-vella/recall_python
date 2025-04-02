import yaml
from flask import jsonify
from tools.logger.custom_logging import custom_log
from core.managers.module_manager import ModuleManager
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # ✅ Gets the directory of the current script
CATEGORIES_FILE = os.path.join(BASE_DIR, "data", "categories.yml")  # ✅ Full path


class FunctionHelperModule:
    def __init__(self, app_manager=None):
        """Initialize FunctionHelperModule and register routes."""
        self.app_manager = app_manager
        self.connection_module = self.get_connection_module()

        if not self.connection_module:
            raise RuntimeError("FunctionHelperModule: Failed to retrieve ConnectionModule from ModuleManager.")

        custom_log("✅ FunctionHelperModule initialized.")
        self.register_routes()

    def get_connection_module(self):
        """Retrieve ConnectionModule from ModuleManager."""
        module_manager = self.app_manager.module_manager if self.app_manager else ModuleManager()
        return module_manager.get_module("connection_api")

    def register_routes(self):
        """Register categories route."""
        if not self.connection_module:
            raise RuntimeError("ConnectionModule is not available yet.")

        self.connection_module.register_route('/get-categories', self.get_categories, methods=['GET'])
        custom_log("🌐 FunctionHelperModule: `/get-categories` route registered.")

    def _load_categories_data(self):
        """Loads categories from YAML as a dictionary (pure Python data)."""
        try:
            with open(CATEGORIES_FILE, "r", encoding="utf-8") as file:
                categories_data = yaml.safe_load(file)

            if not categories_data or "categories" not in categories_data:
                return {}

            # ✅ Extract and convert levels to integers
            return {
                category: {"levels": int(data["levels"])}
                for category, data in categories_data["categories"].items()
            }

        except Exception as e:
            custom_log(f"❌ Error loading categories: {e}")
            return {}

    def get_categories(self):
        """Flask route - Returns categories as a JSON response."""
        categories_response = self._load_categories_data()

        if not categories_response:
            return jsonify({"error": "No categories found"}), 404

        return jsonify({"categories": categories_response}), 200


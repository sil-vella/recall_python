import bcrypt
import hashlib
from flask import request, jsonify
from tools.logger.custom_logging import custom_log
from core.managers.module_manager import ModuleManager
from datetime import datetime, timedelta

class LoginModule:
    def __init__(self, app_manager=None):
        """Initialize the LoginModule."""
        self.app_manager = app_manager
        self.connection_module = self.get_connection_module()

        if not self.connection_module:
            raise RuntimeError("LoginModule: Failed to retrieve ConnectionModule from ModuleManager.")

        custom_log("✅ LoginModule initialized.")

    def get_connection_module(self):
        """Retrieve ConnectionModule from ModuleManager."""
        module_manager = self.app_manager.module_manager if self.app_manager else ModuleManager()
        connection_module = module_manager.get_module("connection_api")

        if not connection_module:
            custom_log("❌ ConnectionModule not found in ModuleManager.")
        
        return connection_module

    def register_routes(self):
        """Register authentication routes."""
        if not self.connection_module:
            raise RuntimeError("ConnectionModule is not available yet.")

        self.connection_module.register_route('/register', self.register_user, methods=['POST'])
        self.connection_module.register_route('/login', self.login_user, methods=['POST'])
        self.connection_module.register_route('/refresh-token', self.refresh_token, methods=['POST'])
        self.connection_module.register_route('/logout', self.logout_user, methods=['POST'])
        self.connection_module.register_route('/delete-user', self.delete_user_request, methods=['POST'])

        custom_log("🌐 LoginModule: Authentication routes registered successfully.")

    def delete_user_request(self):
        """API Endpoint to delete a user and their data."""
        try:
            data = request.get_json()
            user_id = data.get("user_id")

            if not user_id:
                return jsonify({"error": "User ID is required"}), 400

            # ✅ Call the proper delete method
            response, status_code = self.delete_user_data(user_id)
            return jsonify(response), status_code

        except Exception as e:
            custom_log(f"❌ Error in delete-user API: {e}")
            return jsonify({"error": "Server error"}), 500

    def hash_password(self, password):
        """Hash the password using bcrypt."""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode(), salt).decode()

    def check_password(self, password, hashed_password):
        """Check if a given password matches the stored hash."""
        return bcrypt.checkpw(password.encode(), hashed_password.encode())

    def delete_user_data(self, user_id):
        """Delete all data associated with a user."""
        try:
            if not self.connection_module:
                return {"error": "Database connection is unavailable"}, 500

            self.connection_module.delete_user(user_id)
            custom_log(f"✅ Successfully deleted all data for User ID {user_id}.")
            return {"message": f"User ID {user_id} and all associated data deleted successfully"}, 200

        except Exception as e:
            custom_log(f"❌ Error deleting user data: {e}")
            return {"error": f"Failed to delete user data: {str(e)}"}, 500

    def register_user(self):
        """Handles user registration."""
        try:
            custom_log("🟢 Registering user: Processing request...")

            data = request.get_json()
            username = data.get("username")
            email = data.get("email")
            password = data.get("password")

            if not username or not email or not password:
                custom_log("⚠️ Missing required fields in registration request.")
                return jsonify({"error": "Missing required fields"}), 400

            # Check if email already exists
            existing_user = self.connection_module.get_user_by_email(email)
            if existing_user:
                custom_log(f"⚠️ Registration failed: Email '{email}' already exists.")
                return jsonify({"error": "Email is already registered"}), 400

            # Create new user
            hashed_password = self.hash_password(password)
            user = self.connection_module.create_user(username, email, hashed_password)

            custom_log(f"✅ User '{username}' registered successfully.")
            return jsonify({"message": "User registered successfully"}), 200

        except Exception as e:
            custom_log(f"❌ Error registering user: {e}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    def login_user(self):
        """Handles user login."""
        try:
            custom_log("🟢 Login attempt received...")

            data = request.get_json()
            email = data.get("email")
            password = data.get("password")

            if not email or not password:
                custom_log("⚠️ Login failed: Missing email or password.")
                return jsonify({"error": "Missing email or password"}), 400

            user = self.connection_module.get_user_by_email(email)
            if not user:
                custom_log(f"⚠️ Login failed: Email '{email}' not found.")
                return jsonify({"error": "Invalid credentials"}), 401

            if not self.check_password(password, user[0]['password']):
                custom_log(f"⚠️ Login failed: Incorrect password for email '{email}'.")
                return jsonify({"error": "Invalid credentials"}), 401

            user_id = user[0]['id']
            custom_log(f"✅ User ID {user_id} authenticated successfully.")

            # Create user tokens using ConnectionAPI's JWT manager
            user_data = {
                'id': user_id,
                'username': user[0]['username'],
                'email': user[0]['email']
            }
            
            # Cache user data in Redis
            self.connection_module.cache_user_data(user_id, user_data)
            
            tokens = self.connection_module.create_user_tokens(user_data)

            return jsonify({
                "message": "Login successful",
                "user": {
                    "id": user_id,
                    "username": user[0]["username"],
                },
                "tokens": tokens
            }), 200

        except Exception as e:
            custom_log(f"❌ Error during login: {e}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    def refresh_token(self):
        """Handle token refresh requests."""
        try:
            data = request.get_json()
            refresh_token = data.get('refresh_token')
            
            if not refresh_token:
                return jsonify({"error": "Refresh token is required"}), 400
                
            new_tokens = self.connection_module.refresh_user_tokens(refresh_token)
            if not new_tokens:
                return jsonify({"error": "Invalid or expired refresh token"}), 401
                
            return jsonify(new_tokens), 200
            
        except Exception as e:
            custom_log(f"❌ Error refreshing token: {e}")
            return jsonify({"error": "Server error"}), 500

    def logout_user(self):
        """Handle user logout."""
        try:
            data = request.get_json()
            user_id = data.get('user_id')
            
            if not user_id:
                return jsonify({"error": "User ID is required"}), 400
                
            # Revoke all tokens for the user
            if self.connection_module.revoke_user_tokens(user_id):
                return jsonify({"message": "Logged out successfully"}), 200
            else:
                return jsonify({"error": "Failed to logout"}), 500
                
        except Exception as e:
            custom_log(f"❌ Error during logout: {e}")
            return jsonify({"error": "Server error"}), 500
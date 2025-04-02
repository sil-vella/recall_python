import os

def read_secret_file(file_path):
    """Read a secret from a file."""
    try:
        with open(file_path, 'r') as f:
            return f.read().strip()
    except FileNotFoundError:
        raise RuntimeError(f"Secret file not found: {file_path}")
    except PermissionError:
        raise RuntimeError(f"Permission denied reading secret file: {file_path}")

def get_secrets():
    """Get all required secrets."""
    secrets = {}
    
    # Define required secret files
    required_secrets = {
        'APP_SECRET_KEY': os.environ.get('APP_SECRET_KEY_FILE'),
        'JWT_SECRET_KEY': os.environ.get('JWT_SECRET_KEY_FILE'),
        'ENCRYPTION_KEY': os.environ.get('ENCRYPTION_KEY_FILE'),
        'POSTGRES_PASSWORD': os.environ.get('POSTGRES_PASSWORD_FILE')
    }
    
    # Read each secret
    for key, file_path in required_secrets.items():
        if not file_path:
            raise RuntimeError(f"Environment variable for {key}_FILE not set")
        secrets[key] = read_secret_file(file_path)
    
    return secrets 
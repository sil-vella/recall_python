# Flask Application Template with Docker

A production-ready Flask application template with Docker setup, featuring robust database connections, Redis caching, and a modular plugin architecture.

## Features

- 🐳 Docker and Docker Compose setup
- 🔐 Secure database connection pooling
- 📝 Modular plugin architecture
- 🚀 Redis caching support
- 🔒 Environment-based configuration
- 🛠️ Connection API module
- 🌐 WebSocket support
- 📊 Health checks for all services

## Prerequisites

- Docker and Docker Compose
- Python 3.8+
- Make (optional, for Makefile usage)

## Quick Start

1. Clone the repository:
```bash
git clone https://github.com/sil-vella/flask_base_03.git
cd flask_base_03
```

2. Create and configure your `.env` file:
```bash
# Database Configuration
POSTGRES_USER=your_db_user
POSTGRES_PASSWORD=your_db_password
POSTGRES_DB=your_db_name
DB_HOST=db

# Application Configuration
PYTHONPATH=/app
FLASK_PORT=5000
REDIS_PORT=6379
REDIS_HOST=redis

# Service Names
FLASK_SERVICE_NAME=flask_app
POSTGRES_SERVICE_NAME=db
REDIS_SERVICE_NAME=redis
```

3. Build and start the services:
```bash
docker-compose up --build
```

The application will be available at `http://localhost:5000`

## Project Structure

```
.
├── app.py                 # Main application entry point
├── core/                  # Core application logic
├── plugins/              # Plugin modules
│   ├── main_plugin/     # Main plugin with connection API
│   └── game_plugin/     # Game-related functionality
├── tools/                # Utility tools and helpers
├── utils/                # Utility functions and classes
├── static/              # Static files
├── docker-compose.yml   # Docker Compose configuration
├── Dockerfile           # Docker configuration
└── requirements.txt     # Python dependencies
```

## Configuration

### Environment Variables

All configuration is handled through environment variables. See the `.env` file for available options.

### Docker Services

- **Flask App**: Main application service
- **PostgreSQL**: Database service
- **Redis**: Caching service

## Development

### Adding New Plugins

1. Create a new directory in `plugins/`
2. Implement the plugin interface
3. Register the plugin in `plugins/plugin_registry.py`

### Database Migrations

Database migrations are handled through the connection API module.

## Production Deployment

For production deployment:

1. Update environment variables with production values
2. Configure proper security measures
3. Set up proper logging
4. Configure SSL/TLS
5. Set up proper monitoring

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 
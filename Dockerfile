# Base Image
FROM python:3.11-slim

# Install nano and required system dependencies
RUN apt update && apt install -y nano curl

# Set working directory
WORKDIR /app

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose the port
EXPOSE 5000

# Command to start the application
CMD ["sh", "-c", "gunicorn -w 4 -b 0.0.0.0:5000 app:app"]

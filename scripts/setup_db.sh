#!/bin/bash
# Setup database for development or testing

set -e

# Load environment variables
source .env 2>/dev/null || echo "No .env file found, using default values"

# Default values
DB_USER=${POSTGRES_USER:-postgres}
DB_PASSWORD=${POSTGRES_PASSWORD:-postgres}
DB_NAME=${POSTGRES_DB:-basic_auth}
DB_HOST=${POSTGRES_HOST:-localhost}
DB_PORT=${POSTGRES_PORT:-5432}

# Check if PostgreSQL is installed
if ! command -v psql &> /dev/null; then
    echo "PostgreSQL client not found. Please install PostgreSQL."
    exit 1
fi

# Check if diesel_cli is installed
if ! command -v diesel &> /dev/null; then
    echo "Installing diesel_cli..."
    cargo install diesel_cli --no-default-features --features postgres
fi

# Create database if it doesn't exist
echo "Creating database $DB_NAME if it doesn't exist..."
PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -tc "SELECT 1 FROM pg_database WHERE datname = '$DB_NAME'" | grep -q 1 || PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -p $DB_PORT -U $DB_USER -c "CREATE DATABASE $DB_NAME"

# Setup diesel
echo "Setting up diesel..."
diesel setup

# Run migrations
echo "Running migrations..."
diesel migration run

echo "Database setup completed successfully!"

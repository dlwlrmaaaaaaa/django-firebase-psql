#!/bin/bash
set -e

# Optional: Wait for DB to be ready
echo "Waiting for PostgreSQL..."
while ! nc -z db 5432; do
  sleep 0.1
done
echo "PostgreSQL started"

# Apply migrations
python manage.py makemigrations
python manage.py migrate

# Start Gunicorn
gunicorn app.wsgi:application --bind 0.0.0.0:8000

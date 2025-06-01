# Use Python 3.11 slim image as base
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        g++ \
        libpq-dev \
        curl \
        wget \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Make scripts executable and create entrypoint
RUN chmod +x init_db.py && \
    echo '#!/bin/bash\n\
echo "🚀 Starting Attack Surface Discovery..."\n\
echo "⏳ Waiting for database..."\n\
sleep 15\n\
echo "🔄 Initializing database..."\n\
python init_db.py\n\
echo "✅ Database initialized"\n\
echo "🌐 Starting web server..."\n\
exec gunicorn --bind 0.0.0.0:5000 --workers 4 --timeout 120 "app:create_app()"\n\
' > /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# Create non-root user for security
RUN adduser --disabled-password --gecos '' appuser \
    && chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/dashboard/stats || exit 1

# Run the application with database initialization
CMD ["/app/entrypoint.sh"]

# Use Python 3.11 slim image as base
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# Set work directory
WORKDIR /app

# Install system dependencies and security tools
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        g++ \
        libpq-dev \
        curl \
        wget \
        unzip \
        git \
    && rm -rf /var/lib/apt/lists/*

# Install Go (required for security tools)
RUN wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz \
    && rm go1.21.5.linux-amd64.tar.gz

# Set Go environment
ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"
ENV GOBIN="/go/bin"

# Install security tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Add Go bin to PATH
ENV PATH="/go/bin:${PATH}"

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
echo "🔧 Initializing security tools..."\n\
nuclei -update-templates -silent || echo "⚠️  Nuclei template update failed"\n\
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

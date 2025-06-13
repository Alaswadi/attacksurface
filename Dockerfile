# Use Python 3.11 slim image as base
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# Set work directory
WORKDIR /app

# Install system dependencies and security tools (SQLite instead of PostgreSQL)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        g++ \
        sqlite3 \
        libsqlite3-dev \
        curl \
        wget \
        unzip \
        git \
        build-essential \
        libpcap-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Go (required for security tools)
RUN wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz \
    && rm go1.21.5.linux-amd64.tar.gz

# Set Go environment
ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"
ENV GOBIN="/go/bin"
ENV PATH="/go/bin:${PATH}"

# Create Go workspace
RUN mkdir -p /go/bin /go/src /go/pkg

# Install security tools with proper error handling
RUN echo "Installing security tools..." \
    && export GOPROXY=https://proxy.golang.org,direct \
    && export GOSUMDB=sum.golang.org \
    && export CGO_ENABLED=1 \
    && echo "Installing Subfinder..." \
    && timeout 300 go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || (echo "Subfinder install failed, retrying..." && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest) \
    && echo "Installing Nmap..." \
    && apt-get update && apt-get install -y nmap \
    && echo "Installing Nuclei..." \
    && timeout 300 go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || (echo "Nuclei install failed, retrying..." && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest) \
    && echo "Installing Httpx..." \
    && timeout 300 go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest || (echo "Httpx install failed, retrying..." && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest) \
    && echo "All tools installed successfully"

# Verify installations and create symlinks for easier access
RUN echo "Verifying tool installations..." \
    && ls -la /go/bin/ \
    && /go/bin/subfinder -version || echo "Subfinder version check failed" \
    && nmap --version || echo "Nmap version check failed" \
    && /go/bin/nuclei -version || echo "Nuclei version check failed" \
    && /go/bin/httpx -version || echo "Httpx version check failed" \
    && cp /go/bin/subfinder /usr/local/bin/subfinder \
    && ln -s /usr/bin/nmap /usr/local/bin/nmap \
    && cp /go/bin/nuclei /usr/local/bin/nuclei \
    && cp /go/bin/httpx /usr/local/bin/httpx \
    && chmod +x /usr/local/bin/subfinder /usr/local/bin/nuclei /usr/local/bin/httpx \
    && echo "All tools copied to /usr/local/bin successfully"

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories and set permissions
RUN mkdir -p /app/data /app/logs && \
    chmod +x init_db.py && \
    chmod +x init_sqlite_docker.py && \
    chmod +x docker_migration_email_notifications.py

# Create entrypoint script for SQLite
RUN echo '#!/bin/bash\n\
echo "🚀 Starting Attack Surface Discovery with SQLite..."\n\
echo "📁 Creating data directory..."\n\
mkdir -p /app/data\n\
chmod 755 /app/data\n\
echo "🔧 Initializing security tools..."\n\
echo "📥 Downloading Nuclei templates..."\n\
nuclei -update-templates -silent || {\n\
    echo "⚠️  Nuclei template update failed, trying alternative method..."\n\
    nuclei -update -silent || {\n\
        echo "❌ All Nuclei update methods failed, continuing without templates"\n\
    }\n\
}\n\
echo "✅ Nuclei template download completed"\n\
echo "🔄 Initializing SQLite database..."\n\
python init_sqlite_docker.py || {\n\
    echo "⚠️  Database initialization failed, trying alternative..."\n\
    python init_db.py\n\
}\n\
echo "✅ Database initialized"\n\
echo "🌐 Starting web server..."\n\
exec gunicorn --bind 0.0.0.0:5000 --workers 4 --timeout 120 "app:create_app()"\n\
' > /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# Create non-root user but keep root for nmap (requires raw sockets)
RUN adduser --disabled-password --gecos '' appuser \
    && chown -R appuser:appuser /app \
    && chmod 755 /app/data \
    && chmod +s /usr/local/bin/nmap

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/dashboard/stats || exit 1

# Run the application with database initialization
CMD ["/app/entrypoint.sh"]

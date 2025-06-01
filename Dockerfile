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
    && echo "Installing Masscan..." \
    && apt-get update && apt-get install -y masscan \
    && echo "Installing Nuclei..." \
    && timeout 300 go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || (echo "Nuclei install failed, retrying..." && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest) \
    && echo "Installing Httpx..." \
    && timeout 300 go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest || (echo "Httpx install failed, retrying..." && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest) \
    && echo "All tools installed successfully"

# Verify installations and create symlinks for easier access
RUN echo "Verifying tool installations..." \
    && ls -la /go/bin/ \
    && /go/bin/subfinder -version || echo "Subfinder version check failed" \
    && masscan --version || echo "Masscan version check failed" \
    && /go/bin/nuclei -version || echo "Nuclei version check failed" \
    && /go/bin/httpx -version || echo "Httpx version check failed" \
    && cp /go/bin/subfinder /usr/local/bin/subfinder \
    && ln -s /usr/bin/masscan /usr/local/bin/masscan \
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

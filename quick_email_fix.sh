#!/bin/bash

# Quick fix for email_validator missing dependency in Docker

echo "🔄 Fixing email_validator dependency in Docker container..."

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "❌ docker-compose not found. Please install docker-compose first."
    exit 1
fi

# Check if container is running
if ! docker-compose ps | grep -q "attacksurface_web.*Up"; then
    echo "❌ Web container is not running. Please start it first with: docker-compose up -d"
    exit 1
fi

echo "📦 Installing email_validator in running container..."

# Install email_validator in the running container
docker-compose exec web pip install email-validator==2.1.0

if [ $? -eq 0 ]; then
    echo "✅ email_validator installed successfully"
else
    echo "❌ Failed to install email_validator"
    exit 1
fi

# Test the installation
echo "🧪 Testing email_validator installation..."
docker-compose exec web python -c "import email_validator; print(f'✅ email_validator version: {email_validator.__version__}')"

if [ $? -eq 0 ]; then
    echo "✅ email_validator is working correctly"
else
    echo "❌ email_validator test failed"
    exit 1
fi

# Restart the web service to ensure changes take effect
echo "🔄 Restarting web service..."
docker-compose restart web

# Wait for service to start
echo "⏳ Waiting for service to restart..."
sleep 10

# Test the application
echo "🧪 Testing application..."
if curl -f http://localhost:8077/auth/register &>/dev/null; then
    echo "✅ Registration page is now accessible"
else
    echo "⚠️  Registration page may still be starting up"
fi

echo ""
echo "🎉 Email validator fix completed!"
echo ""
echo "📋 Next steps:"
echo "1. Visit http://localhost:8077/auth/register to test user registration"
echo "2. The email validation error should now be resolved"
echo "3. You can register new users and access the enhanced settings"
echo ""
echo "📊 Useful commands:"
echo "  View logs: docker-compose logs -f web"
echo "  Restart:   docker-compose restart web"
echo ""
echo "✅ Your application should now work correctly!"

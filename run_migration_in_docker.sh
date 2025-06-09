#!/bin/bash

# Script to run the PostgreSQL migration inside the Docker container

echo "🚀 Running vulnerability validation migration in Docker container..."

# Find the container name/ID for the Flask app
CONTAINER_NAME=$(docker ps --format "table {{.Names}}" | grep -E "(app|flask|web)" | head -1)

if [ -z "$CONTAINER_NAME" ]; then
    echo "❌ Could not find Flask app container. Looking for any running container..."
    docker ps
    echo ""
    echo "Please run this command manually:"
    echo "docker exec -it <container_name> python /app/migrations/postgresql_add_vulnerability_validation_fields.py"
    exit 1
fi

echo "📦 Found container: $CONTAINER_NAME"

# Copy the migration script to the container
echo "📋 Copying migration script to container..."
docker cp migrations/postgresql_add_vulnerability_validation_fields.py $CONTAINER_NAME:/app/migrations/

# Run the migration
echo "🔄 Running migration inside container..."
docker exec -it $CONTAINER_NAME python /app/migrations/postgresql_add_vulnerability_validation_fields.py

# Check the result
if [ $? -eq 0 ]; then
    echo "✅ Migration completed successfully!"
    echo ""
    echo "🎉 The vulnerability validation functionality is now active!"
    echo "You can now:"
    echo "1. Run Nuclei scans to see both validated and unvalidated vulnerabilities"
    echo "2. Use the validation filter in the vulnerabilities page"
    echo "3. See confidence scores and validation status for all findings"
else
    echo "❌ Migration failed!"
    echo "Please check the error messages above and try running manually:"
    echo "docker exec -it $CONTAINER_NAME python /app/migrations/postgresql_add_vulnerability_validation_fields.py"
fi

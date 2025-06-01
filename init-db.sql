-- Attack Surface Discovery Database Initialization
-- This script sets up the initial database structure and sample data

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Set timezone
SET timezone = 'UTC';

-- Create indexes for better performance (will be created by SQLAlchemy migrations)
-- These are just placeholders for future optimization

-- Sample data will be created by the Flask application
-- This file ensures the database is properly initialized

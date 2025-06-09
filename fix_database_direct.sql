-- Direct PostgreSQL fix for vulnerability validation fields
-- Run this directly against your PostgreSQL database

-- Simplified vulnerability validation (no confidence scoring)

-- Add is_validated column
DO $$ 
BEGIN 
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'vulnerability' 
        AND column_name = 'is_validated'
        AND table_schema = 'public'
    ) THEN
        ALTER TABLE vulnerability ADD COLUMN is_validated BOOLEAN DEFAULT FALSE;
        RAISE NOTICE 'Added is_validated column';
    ELSE
        RAISE NOTICE 'is_validated column already exists';
    END IF;
END $$;

-- Add validation_notes column
DO $$ 
BEGIN 
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'vulnerability' 
        AND column_name = 'validation_notes'
        AND table_schema = 'public'
    ) THEN
        ALTER TABLE vulnerability ADD COLUMN validation_notes TEXT;
        RAISE NOTICE 'Added validation_notes column';
    ELSE
        RAISE NOTICE 'validation_notes column already exists';
    END IF;
END $$;

-- Add template_name column
DO $$ 
BEGIN 
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'vulnerability' 
        AND column_name = 'template_name'
        AND table_schema = 'public'
    ) THEN
        ALTER TABLE vulnerability ADD COLUMN template_name VARCHAR(255);
        RAISE NOTICE 'Added template_name column';
    ELSE
        RAISE NOTICE 'template_name column already exists';
    END IF;
END $$;

-- Add cvss_score column
DO $$ 
BEGIN 
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'vulnerability' 
        AND column_name = 'cvss_score'
        AND table_schema = 'public'
    ) THEN
        ALTER TABLE vulnerability ADD COLUMN cvss_score REAL;
        RAISE NOTICE 'Added cvss_score column';
    ELSE
        RAISE NOTICE 'cvss_score column already exists';
    END IF;
END $$;

-- Add asset_metadata column
DO $$ 
BEGIN 
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'vulnerability' 
        AND column_name = 'asset_metadata'
        AND table_schema = 'public'
    ) THEN
        ALTER TABLE vulnerability ADD COLUMN asset_metadata JSONB;
        RAISE NOTICE 'Added asset_metadata column';
    ELSE
        RAISE NOTICE 'asset_metadata column already exists';
    END IF;
END $$;

-- Update existing vulnerabilities with default values
UPDATE vulnerability
SET
    is_validated = COALESCE(is_validated, TRUE),
    template_name = COALESCE(template_name, title)
WHERE
    is_validated IS NULL
    OR template_name IS NULL;

-- Show final column structure
SELECT 'Migration completed. Current vulnerability table structure:' as status;
SELECT column_name, data_type, is_nullable, column_default
FROM information_schema.columns 
WHERE table_name = 'vulnerability' 
AND table_schema = 'public'
ORDER BY ordinal_position;

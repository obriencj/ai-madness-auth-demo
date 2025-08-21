-- Migration script to add scope field to existing oauth_provider tables
-- This script should be run on existing databases that don't have the scope field

-- Add scope column if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'oauth_provider' AND column_name = 'scope'
    ) THEN
        ALTER TABLE oauth_provider ADD COLUMN scope VARCHAR(500);
        
        -- Update existing providers with default scope values
        UPDATE oauth_provider 
        SET scope = 'openid email profile' 
        WHERE name = 'google';
        
        UPDATE oauth_provider 
        SET scope = 'read:user user:email' 
        WHERE name = 'github';
        
        -- Make scope column NOT NULL after setting default values
        ALTER TABLE oauth_provider ALTER COLUMN scope SET NOT NULL;
        
        RAISE NOTICE 'Added scope column to oauth_provider table';
    ELSE
        RAISE NOTICE 'Scope column already exists in oauth_provider table';
    END IF;
END $$;

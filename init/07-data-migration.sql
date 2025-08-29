-- Data Migration Script for Model Optimization
-- This script populates new fields with appropriate default values for existing data

-- Update existing users with default timestamps
UPDATE "user" 
SET 
    created_at = CURRENT_TIMESTAMP,
    updated_at = CURRENT_TIMESTAMP
WHERE created_at IS NULL;

-- Update existing OAuth providers with default timestamps
UPDATE oauth_provider 
SET 
    updated_at = CURRENT_TIMESTAMP
WHERE updated_at IS NULL;

-- Update existing OAuth accounts with default timestamps
UPDATE oauth_account 
SET 
    updated_at = CURRENT_TIMESTAMP
WHERE updated_at IS NULL;

-- Update existing JWT sessions with default timestamps
UPDATE jwt_session 
SET 
    last_activity_at = created_at
WHERE last_activity_at IS NULL;

-- Update existing GSSAPI realms with default timestamps
UPDATE gssapi_realm 
SET 
    updated_at = CURRENT_TIMESTAMP
WHERE updated_at IS NULL;

-- Update existing GSSAPI accounts with default timestamps
UPDATE gssapi_account 
SET 
    updated_at = CURRENT_TIMESTAMP
WHERE updated_at IS NULL;

-- Update existing app config versions with default timestamps
UPDATE app_config_version 
SET 
    created_at = CURRENT_TIMESTAMP
WHERE created_at IS NULL;

-- Set default values for new boolean fields
UPDATE oauth_provider 
SET 
    is_deleted = FALSE
WHERE is_deleted IS NULL;

UPDATE gssapi_realm 
SET 
    is_deleted = FALSE
WHERE is_deleted IS NULL;

-- Set default values for new integer fields
UPDATE "user" 
SET 
    login_attempts = 0
WHERE login_attempts IS NULL;

-- Ensure all existing users have valid usernames (minimum 3 characters)
-- This is a safety check - existing data should already be valid
UPDATE "user" 
SET username = CONCAT('user_', id)
WHERE length(username) < 3;

-- Ensure all existing OAuth providers have valid names (minimum 2 characters)
UPDATE oauth_provider 
SET name = CONCAT('provider_', id)
WHERE length(name) < 2;

-- Ensure all existing GSSAPI realms have valid names (minimum 2 characters)
UPDATE gssapi_realm 
SET name = CONCAT('realm_', id)
WHERE length(name) < 2;

-- Ensure all existing GSSAPI realms have valid realm domains (minimum 3 characters)
UPDATE gssapi_realm 
SET realm = CONCAT('realm', id, '.example.com')
WHERE length(realm) < 3;

-- Ensure all existing app config versions have positive version numbers
UPDATE app_config_version 
SET version = 1
WHERE version <= 0;

-- Create initial audit log entries for existing administrative actions
-- This provides a baseline audit trail
INSERT INTO audit_log (user_id, action, resource_type, resource_id, details, created_at)
SELECT 
    1, -- Assuming admin user has ID 1
    'system_migration',
    'system',
    NULL,
    '{"migration": "model_optimization", "description": "Initial migration to optimized models"}',
    CURRENT_TIMESTAMP
WHERE NOT EXISTS (
    SELECT 1 FROM audit_log WHERE action = 'system_migration'
);

-- The end.

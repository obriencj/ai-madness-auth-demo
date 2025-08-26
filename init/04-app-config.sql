-- Application Configuration Table Migration
-- This script creates the app_config_version table for versioned application configuration

CREATE TABLE IF NOT EXISTS app_config_version (
    id SERIAL PRIMARY KEY,
    version INTEGER NOT NULL,
    config_data JSONB NOT NULL,
    description TEXT,
    created_by INTEGER NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT FALSE NOT NULL,
    activated_at TIMESTAMP WITHOUT TIME ZONE,
    activated_by INTEGER REFERENCES "user"(id) ON DELETE SET NULL
);

-- Ensure only one active configuration at a time
CREATE UNIQUE INDEX IF NOT EXISTS idx_app_config_active ON app_config_version(is_active) WHERE is_active = TRUE;

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_app_config_version ON app_config_version(version);
CREATE INDEX IF NOT EXISTS idx_app_config_created_at ON app_config_version(created_at);
CREATE INDEX IF NOT EXISTS idx_app_config_created_by ON app_config_version(created_by);

-- Insert initial configuration version
INSERT INTO app_config_version (version, config_data, description, created_by, is_active, activated_at, activated_by) VALUES
(
    1,
    '{
        "auth": {
            "allow_registration": true,
            "allow_user_login": true,
            "jwt_lifetime_hours": 1,
            "max_login_attempts": 5
        },
        "app": {
            "maintenance_mode": false,
            "site_name": "Auth Demo",
            "contact_email": "admin@example.com"
        }
    }',
    'Initial configuration',
    1,
    true,
    CURRENT_TIMESTAMP,
    1
) ON CONFLICT DO NOTHING;

-- Add comment to table
COMMENT ON TABLE app_config_version IS 'Stores versioned application configuration with audit trail';

-- The end.

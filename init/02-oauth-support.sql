-- Add OAuth provider support to the auth_demo database
-- This script adds tables for OAuth accounts and providers with Phase 1.2 optimizations

-- Create OAuth providers table with optimizations
CREATE TABLE IF NOT EXISTS oauth_provider (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    client_secret VARCHAR(255) NOT NULL,
    authorize_url VARCHAR(500) NOT NULL,
    token_url VARCHAR(500) NOT NULL,
    userinfo_url VARCHAR(500) NOT NULL,
    scope VARCHAR(500) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    is_deleted BOOLEAN DEFAULT FALSE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    deleted_at TIMESTAMP,
    deleted_by INTEGER REFERENCES "user"(id)
);

-- Create OAuth accounts table with optimizations
CREATE TABLE IF NOT EXISTS oauth_account (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    provider_id INTEGER NOT NULL REFERENCES oauth_provider(id) ON DELETE CASCADE,
    provider_user_id VARCHAR(255) NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    token_expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_used_at TIMESTAMP,
    UNIQUE(provider_id, provider_user_id)
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_oauth_account_user_id ON oauth_account(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_account_provider_id ON oauth_account(provider_id);
CREATE INDEX IF NOT EXISTS idx_oauth_account_provider_user_id ON oauth_account(provider_user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_provider_active_name ON oauth_provider(is_active, name);
CREATE INDEX IF NOT EXISTS idx_oauth_provider_created_at ON oauth_provider(created_at);
CREATE INDEX IF NOT EXISTS idx_oauth_provider_deleted ON oauth_provider(is_deleted);
CREATE INDEX IF NOT EXISTS idx_oauth_account_user_provider ON oauth_account(user_id, provider_id);
CREATE INDEX IF NOT EXISTS idx_oauth_account_expires ON oauth_account(token_expires_at);
CREATE INDEX IF NOT EXISTS idx_oauth_account_last_used ON oauth_account(last_used_at);

-- Add database constraints for data validation
ALTER TABLE oauth_provider 
ADD CONSTRAINT provider_name_min_length CHECK (length(name) >= 2),
ADD CONSTRAINT provider_name_max_length CHECK (length(name) <= 50),
ADD CONSTRAINT client_id_min_length CHECK (length(client_id) >= 1),
ADD CONSTRAINT scope_min_length CHECK (length(scope) >= 1);

ALTER TABLE oauth_account 
ADD CONSTRAINT provider_user_id_min_length CHECK (length(provider_user_id) >= 1);

-- Insert default OAuth providers (Google and GitHub)
-- Note: These are placeholder values - you'll need to replace with actual credentials
-- Providers are disabled by default for security - enable only after configuring real credentials
INSERT INTO oauth_provider (name, client_id, client_secret, authorize_url, token_url, userinfo_url, scope, is_active) VALUES
(
    'google',
    'your-google-client-id',
    'your-google-client-secret',
    'https://accounts.google.com/o/oauth2/v2/auth',
    'https://oauth2.googleapis.com/token',
    'https://www.googleapis.com/oauth2/v2/userinfo',
    'openid email profile',
    FALSE
),
(
    'github',
    'your-github-client-id',
    'your-github-client-secret',
    'https://github.com/login/oauth/authorize',
    'https://github.com/login/oauth/access_token',
    'https://api.github.com/user',
    'read:user user:email',
    FALSE
) ON CONFLICT (name) DO NOTHING;

-- Add table comments
COMMENT ON TABLE oauth_provider IS 'OAuth provider configurations with soft delete support';
COMMENT ON TABLE oauth_account IS 'User OAuth account links with usage tracking';

-- The end.

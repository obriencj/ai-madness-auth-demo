-- Add OAuth provider support to the auth_demo database
-- This script adds tables for OAuth accounts and providers

-- Create OAuth providers table
CREATE TABLE IF NOT EXISTS oauth_provider (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    client_secret VARCHAR(255) NOT NULL,
    authorize_url VARCHAR(500) NOT NULL,
    token_url VARCHAR(500) NOT NULL,
    userinfo_url VARCHAR(500) NOT NULL,
    scope VARCHAR(500) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create OAuth accounts table
CREATE TABLE IF NOT EXISTS oauth_account (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    provider_id INTEGER NOT NULL REFERENCES oauth_provider(id) ON DELETE CASCADE,
    provider_user_id VARCHAR(255) NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    token_expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(provider_id, provider_user_id)
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_oauth_account_user_id ON oauth_account(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_account_provider_id ON oauth_account(provider_id);
CREATE INDEX IF NOT EXISTS idx_oauth_account_provider_user_id ON oauth_account(provider_user_id);

-- Insert default OAuth providers (Google and GitHub)
-- Note: These are placeholder values - you'll need to replace with actual credentials
INSERT INTO oauth_provider (name, client_id, client_secret, authorize_url, token_url, userinfo_url, scope) VALUES
(
    'google',
    'your-google-client-id',
    'your-google-client-secret',
    'https://accounts.google.com/o/oauth2/v2/auth',
    'https://oauth2.googleapis.com/token',
    'https://www.googleapis.com/oauth2/v2/userinfo',
    'openid email profile'
),
(
    'github',
    'your-github-client-id',
    'your-github-client-secret',
    'https://github.com/login/oauth/authorize',
    'https://github.com/login/oauth/access_token',
    'https://api.github.com/user',
    'read:user user:email'
) ON CONFLICT (name) DO NOTHING;

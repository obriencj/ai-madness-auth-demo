-- JWT Sessions Table Migration
-- This script creates the jwt_session table for tracking active JWT sessions

CREATE TABLE IF NOT EXISTS jwt_session (
    id SERIAL PRIMARY KEY,
    jti VARCHAR(255) UNIQUE NOT NULL,
    user_id INTEGER NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    auth_method VARCHAR(50) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    CONSTRAINT jwt_session_jti_unique UNIQUE (jti)
);

-- Create index for faster queries
CREATE INDEX IF NOT EXISTS idx_jwt_session_user_id ON jwt_session(user_id);
CREATE INDEX IF NOT EXISTS idx_jwt_session_jti ON jwt_session(jti);
CREATE INDEX IF NOT EXISTS idx_jwt_session_expires_at ON jwt_session(expires_at);
CREATE INDEX IF NOT EXISTS idx_jwt_session_is_active ON jwt_session(is_active);

-- Add comment to table
COMMENT ON TABLE jwt_session IS 'Tracks active JWT sessions for admin management';

-- The end.

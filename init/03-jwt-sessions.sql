-- JWT Sessions Table Migration with Phase 1.2 optimizations
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
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    last_activity_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_jwt_session_user_id ON jwt_session(user_id);
CREATE INDEX IF NOT EXISTS idx_jwt_session_jti ON jwt_session(jti);
CREATE INDEX IF NOT EXISTS idx_jwt_session_expires_at ON jwt_session(expires_at);
CREATE INDEX IF NOT EXISTS idx_jwt_session_is_active ON jwt_session(is_active);
CREATE INDEX IF NOT EXISTS idx_jwt_session_user_active ON jwt_session(user_id, is_active);
CREATE INDEX IF NOT EXISTS idx_jwt_session_expires_active ON jwt_session(expires_at, is_active);
CREATE INDEX IF NOT EXISTS idx_jwt_session_method_created ON jwt_session(auth_method, created_at);

-- Add database constraints for data validation
ALTER TABLE jwt_session 
ADD CONSTRAINT jwt_session_jti_unique UNIQUE (jti),
ADD CONSTRAINT jti_min_length CHECK (length(jti) >= 32),
ADD CONSTRAINT expires_after_created CHECK (expires_at > created_at),
ADD CONSTRAINT last_activity_after_created CHECK (last_activity_at >= created_at);

-- Add table comment
COMMENT ON TABLE jwt_session IS 'JWT session tracking with activity monitoring';

-- The end.

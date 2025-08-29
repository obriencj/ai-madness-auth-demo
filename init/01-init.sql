-- Initialize the auth_demo database
-- This script creates the users table and inserts the default admin user

-- Create users table with Phase 1.2 optimizations
CREATE TABLE IF NOT EXISTS "user" (
    id SERIAL PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    is_admin BOOLEAN DEFAULT FALSE NOT NULL,
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_login_at TIMESTAMP,
    login_attempts INTEGER DEFAULT 0 NOT NULL,
    locked_until TIMESTAMP
);

-- Insert default admin user (password: admin123)
-- Using bcrypt hash for 'admin123'
INSERT INTO "user" (username, email, password_hash, is_admin, is_active) 
VALUES (
    'admin',
    'admin@example.com',
    '$2b$12$qS6c0mpobRVHTmk6brL7JuOeGghuI6wC2DeUFkUVgBa6t1/mYy43q',
    TRUE,
    TRUE
) ON CONFLICT (username) DO NOTHING;

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_user_username ON "user"(username);
CREATE INDEX IF NOT EXISTS idx_user_email ON "user"(email);
CREATE INDEX IF NOT EXISTS idx_user_active_admin ON "user"(is_active, is_admin);
CREATE INDEX IF NOT EXISTS idx_user_created_at ON "user"(created_at);
CREATE INDEX IF NOT EXISTS idx_user_last_login ON "user"(last_login_at);

-- Add database constraints for data validation
ALTER TABLE "user" 
ADD CONSTRAINT username_min_length CHECK (length(username) >= 3),
ADD CONSTRAINT username_max_length CHECK (length(username) <= 80),
ADD CONSTRAINT login_attempts_non_negative CHECK (login_attempts >= 0);

-- Add table comment
COMMENT ON TABLE "user" IS 'User accounts with authentication and account management';

-- The end.

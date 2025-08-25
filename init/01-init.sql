-- Initialize the auth_demo database
-- This script creates the users table and inserts the default admin user

-- Create users table
CREATE TABLE IF NOT EXISTS "user" (
    id SERIAL PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE
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

-- Create index on username for faster lookups
CREATE INDEX IF NOT EXISTS idx_user_username ON "user"(username);

-- Create index on email for faster lookups
CREATE INDEX IF NOT EXISTS idx_user_email ON "user"(email);

-- The end.

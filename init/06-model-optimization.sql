-- Database Model Optimization Migration
-- This script adds new fields, constraints, and indexes for improved performance and data integrity

-- Add new fields to user table
ALTER TABLE "user" 
ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP,
ADD COLUMN IF NOT EXISTS login_attempts INTEGER DEFAULT 0 NOT NULL,
ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP;

-- Add new fields to oauth_provider table
ALTER TABLE oauth_provider 
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN DEFAULT FALSE NOT NULL,
ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP,
ADD COLUMN IF NOT EXISTS deleted_by INTEGER REFERENCES "user"(id);

-- Add new fields to oauth_account table
ALTER TABLE oauth_account 
ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMP;

-- Add new fields to jwt_session table
ALTER TABLE jwt_session 
ADD COLUMN IF NOT EXISTS last_activity_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL;

-- Add new fields to gssapi_realm table
ALTER TABLE gssapi_realm 
ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN DEFAULT FALSE NOT NULL,
ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP,
ADD COLUMN IF NOT EXISTS deleted_by INTEGER REFERENCES "user"(id);

-- Add new fields to gssapi_account table
ALTER TABLE gssapi_account 
ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMP;

-- Create audit_log table
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES "user"(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id INTEGER,
    details JSONB,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Add database constraints (using DO blocks to handle existing constraints safely)
-- User table constraints
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'username_min_length') THEN
        ALTER TABLE "user" ADD CONSTRAINT username_min_length CHECK (length(username) >= 3);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'username_max_length') THEN
        ALTER TABLE "user" ADD CONSTRAINT username_max_length CHECK (length(username) <= 80);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'login_attempts_non_negative') THEN
        ALTER TABLE "user" ADD CONSTRAINT login_attempts_non_negative CHECK (login_attempts >= 0);
    END IF;
END $$;

-- OAuth provider constraints
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'provider_name_min_length') THEN
        ALTER TABLE oauth_provider ADD CONSTRAINT provider_name_min_length CHECK (length(name) >= 2);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'provider_name_max_length') THEN
        ALTER TABLE oauth_provider ADD CONSTRAINT provider_name_max_length CHECK (length(name) <= 50);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'client_id_min_length') THEN
        ALTER TABLE oauth_provider ADD CONSTRAINT client_id_min_length CHECK (length(client_id) >= 1);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'scope_min_length') THEN
        ALTER TABLE oauth_provider ADD CONSTRAINT scope_min_length CHECK (length(scope) >= 1);
    END IF;
END $$;

-- OAuth account constraints
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'provider_user_id_min_length') THEN
        ALTER TABLE oauth_account ADD CONSTRAINT provider_user_id_min_length CHECK (length(provider_user_id) >= 1);
    END IF;
END $$;

-- JWT session constraints
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'jti_min_length') THEN
        ALTER TABLE jwt_session ADD CONSTRAINT jti_min_length CHECK (length(jti) >= 32);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'expires_after_created') THEN
        ALTER TABLE jwt_session ADD CONSTRAINT expires_after_created CHECK (expires_at > created_at);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'last_activity_after_created') THEN
        ALTER TABLE jwt_session ADD CONSTRAINT last_activity_after_created CHECK (last_activity_at >= created_at);
    END IF;
END $$;

-- GSSAPI realm constraints
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'realm_name_min_length') THEN
        ALTER TABLE gssapi_realm ADD CONSTRAINT realm_name_min_length CHECK (length(name) >= 2);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'realm_name_max_length') THEN
        ALTER TABLE gssapi_realm ADD CONSTRAINT realm_name_max_length CHECK (length(name) <= 100);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'realm_domain_min_length') THEN
        ALTER TABLE gssapi_realm ADD CONSTRAINT realm_domain_min_length CHECK (length(realm) >= 3);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'kdc_hosts_not_empty') THEN
        ALTER TABLE gssapi_realm ADD CONSTRAINT kdc_hosts_not_empty CHECK (array_length(kdc_hosts, 1) > 0);
    END IF;
END $$;

-- GSSAPI account constraints
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'principal_name_min_length') THEN
        ALTER TABLE gssapi_account ADD CONSTRAINT principal_name_min_length CHECK (length(principal_name) >= 3);
    END IF;
END $$;

-- App config constraints
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'version_positive') THEN
        ALTER TABLE app_config_version ADD CONSTRAINT version_positive CHECK (version > 0);
    END IF;
END $$;

-- Audit log constraints
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'action_min_length') THEN
        ALTER TABLE audit_log ADD CONSTRAINT action_min_length CHECK (length(action) >= 3);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'action_max_length') THEN
        ALTER TABLE audit_log ADD CONSTRAINT action_max_length CHECK (length(action) <= 100);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'resource_type_min_length') THEN
        ALTER TABLE audit_log ADD CONSTRAINT resource_type_min_length CHECK (length(resource_type) >= 2);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'resource_type_max_length') THEN
        ALTER TABLE audit_log ADD CONSTRAINT resource_type_max_length CHECK (length(resource_type) <= 50);
    END IF;
END $$;

-- Create performance indexes
-- User table indexes
CREATE INDEX IF NOT EXISTS idx_user_active_admin ON "user"(is_active, is_admin);
CREATE INDEX IF NOT EXISTS idx_user_created_at ON "user"(created_at);
CREATE INDEX IF NOT EXISTS idx_user_last_login ON "user"(last_login_at);

-- OAuth provider indexes
CREATE INDEX IF NOT EXISTS idx_oauth_provider_active_name ON oauth_provider(is_active, name);
CREATE INDEX IF NOT EXISTS idx_oauth_provider_created_at ON oauth_provider(created_at);
CREATE INDEX IF NOT EXISTS idx_oauth_provider_deleted ON oauth_provider(is_deleted);

-- OAuth account indexes
CREATE INDEX IF NOT EXISTS idx_oauth_account_user_provider ON oauth_account(user_id, provider_id);
CREATE INDEX IF NOT EXISTS idx_oauth_account_expires ON oauth_account(token_expires_at);
CREATE INDEX IF NOT EXISTS idx_oauth_account_last_used ON oauth_account(last_used_at);

-- JWT session indexes
CREATE INDEX IF NOT EXISTS idx_jwt_session_user_active ON jwt_session(user_id, is_active);
CREATE INDEX IF NOT EXISTS idx_jwt_session_expires_active ON jwt_session(expires_at, is_active);
CREATE INDEX IF NOT EXISTS idx_jwt_session_method_created ON jwt_session(auth_method, created_at);

-- GSSAPI realm indexes
CREATE INDEX IF NOT EXISTS idx_gssapi_realm_active_default ON gssapi_realm(is_active, default_realm);
CREATE INDEX IF NOT EXISTS idx_gssapi_realm_created_at ON gssapi_realm(created_at);
CREATE INDEX IF NOT EXISTS idx_gssapi_realm_deleted ON gssapi_realm(is_deleted);

-- GSSAPI account indexes
CREATE INDEX IF NOT EXISTS idx_gssapi_account_user_realm ON gssapi_account(user_id, realm_id);
CREATE INDEX IF NOT EXISTS idx_gssapi_account_principal ON gssapi_account(principal_name);
CREATE INDEX IF NOT EXISTS idx_gssapi_account_last_used ON gssapi_account(last_used_at);

-- App config indexes
CREATE INDEX IF NOT EXISTS idx_app_config_version_created ON app_config_version(version, created_at);

-- Audit log indexes
CREATE INDEX IF NOT EXISTS idx_audit_log_user_action ON audit_log(user_id, action);
CREATE INDEX IF NOT EXISTS idx_audit_log_resource ON audit_log(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);

-- Create unique partial index for active app config (PostgreSQL only)
-- This ensures only one active configuration at a time
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes 
        WHERE indexname = 'idx_app_config_active_unique' 
        AND tablename = 'app_config_version'
    ) THEN
        CREATE UNIQUE INDEX idx_app_config_active_unique ON app_config_version(is_active) WHERE is_active = TRUE;
    END IF;
END $$;

-- Add comments to tables
COMMENT ON TABLE "user" IS 'User accounts with authentication and account management';
COMMENT ON TABLE oauth_provider IS 'OAuth provider configurations with soft delete support';
COMMENT ON TABLE oauth_account IS 'User OAuth account links with usage tracking';
COMMENT ON TABLE jwt_session IS 'JWT session tracking with activity monitoring';
COMMENT ON TABLE gssapi_realm IS 'GSSAPI/Kerberos realm configurations with soft delete support';
COMMENT ON TABLE gssapi_account IS 'User GSSAPI account links with usage tracking';
COMMENT ON TABLE app_config_version IS 'Versioned application configuration with audit trail';
COMMENT ON TABLE audit_log IS 'Audit trail for administrative actions and system changes';

-- The end.

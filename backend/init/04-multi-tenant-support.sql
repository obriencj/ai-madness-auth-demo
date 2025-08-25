-- Multi-tenant support for authentication service
-- This migration adds tenant isolation and API key authentication

-- Create tenants table
CREATE TABLE IF NOT EXISTS tenant (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    domain VARCHAR(255) UNIQUE,
    api_key VARCHAR(255) UNIQUE NOT NULL,
    settings JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create webhooks table for tenant event notifications
CREATE TABLE IF NOT EXISTS webhook (
    id SERIAL PRIMARY KEY,
    tenant_id INTEGER NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    url VARCHAR(500) NOT NULL,
    events JSONB NOT NULL DEFAULT '[]',
    secret VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add tenant_id to existing user table
ALTER TABLE "user" ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenant(id) ON DELETE CASCADE;
ALTER TABLE "user" ADD COLUMN IF NOT EXISTS external_user_id VARCHAR(255);

-- Add tenant_id to existing oauth_provider table
ALTER TABLE oauth_provider ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenant(id) ON DELETE CASCADE;

-- Add tenant_id to existing oauth_account table
ALTER TABLE oauth_account ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenant(id) ON DELETE CASCADE;

-- Add tenant_id to existing jwt_session table
ALTER TABLE jwt_session ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenant(id) ON DELETE CASCADE;

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_user_tenant_id ON "user"(tenant_id);
CREATE INDEX IF NOT EXISTS idx_oauth_provider_tenant_id ON oauth_provider(tenant_id);
CREATE INDEX IF NOT EXISTS idx_oauth_account_tenant_id ON oauth_account(tenant_id);
CREATE INDEX IF NOT EXISTS idx_jwt_session_tenant_id ON jwt_session(tenant_id);
CREATE INDEX IF NOT EXISTS idx_webhook_tenant_id ON webhook(tenant_id);

-- Create default tenant for existing data
INSERT INTO tenant (name, domain, api_key, settings) 
VALUES (
    'default', 
    'localhost', 
    'default-api-key-change-in-production',
    '{"theme": {"primary_color": "#007bff", "secondary_color": "#6c757d", "logo_url": "/static/logo.png"}}'
) ON CONFLICT (name) DO NOTHING;

-- Update existing records to belong to default tenant
UPDATE "user" SET tenant_id = (SELECT id FROM tenant WHERE name = 'default') WHERE tenant_id IS NULL;
UPDATE oauth_provider SET tenant_id = (SELECT id FROM tenant WHERE name = 'default') WHERE tenant_id IS NULL;
UPDATE oauth_account SET tenant_id = (SELECT id FROM tenant WHERE name = 'default') WHERE tenant_id IS NULL;
UPDATE jwt_session SET tenant_id = (SELECT id FROM tenant WHERE name = 'default') WHERE tenant_id IS NULL;

-- Create audit log table for compliance
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    tenant_id INTEGER REFERENCES tenant(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES "user"(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(255),
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_id ON audit_log(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at
CREATE TRIGGER update_tenant_updated_at BEFORE UPDATE ON tenant FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_webhook_updated_at BEFORE UPDATE ON webhook FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- The end.

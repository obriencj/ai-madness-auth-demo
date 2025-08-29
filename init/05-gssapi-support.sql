-- Add GSSAPI/Kerberos authentication support to the auth_demo database with Phase 1.2 optimizations
-- This script adds tables for GSSAPI realms and accounts

-- Create GSSAPI realms table with optimizations
CREATE TABLE IF NOT EXISTS gssapi_realm (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    realm VARCHAR(255) NOT NULL,
    kdc_hosts TEXT[], -- Array of KDC hostnames
    admin_server VARCHAR(255), -- Admin server hostname
    service_principal VARCHAR(255) NOT NULL, -- Service principal (e.g., HTTP/hostname@REALM.COM)
    encrypted_keytab BYTEA NOT NULL, -- Encrypted keytab data
    keytab_encryption_iv BYTEA NOT NULL, -- Initialization vector for AES encryption
    keytab_encryption_salt BYTEA NOT NULL, -- Salt for key derivation
    default_realm BOOLEAN DEFAULT FALSE NOT NULL,
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    is_deleted BOOLEAN DEFAULT FALSE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    deleted_at TIMESTAMP,
    deleted_by INTEGER REFERENCES "user"(id)
);

-- Create GSSAPI accounts table with optimizations
CREATE TABLE IF NOT EXISTS gssapi_account (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    realm_id INTEGER NOT NULL REFERENCES gssapi_realm(id) ON DELETE CASCADE,
    principal_name VARCHAR(255) NOT NULL, -- Full Kerberos principal (e.g., user@REALM.COM)
    service_principal VARCHAR(255), -- Service principal if applicable
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_used_at TIMESTAMP,
    UNIQUE(realm_id, principal_name)
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_gssapi_account_user_id ON gssapi_account(user_id);
CREATE INDEX IF NOT EXISTS idx_gssapi_account_realm_id ON gssapi_account(realm_id);
CREATE INDEX IF NOT EXISTS idx_gssapi_account_principal_name ON gssapi_account(principal_name);
CREATE INDEX IF NOT EXISTS idx_gssapi_realm_name ON gssapi_realm(name);
CREATE INDEX IF NOT EXISTS idx_gssapi_realm_realm ON gssapi_realm(realm);
CREATE INDEX IF NOT EXISTS idx_gssapi_realm_active_default ON gssapi_realm(is_active, default_realm);
CREATE INDEX IF NOT EXISTS idx_gssapi_realm_created_at ON gssapi_realm(created_at);
CREATE INDEX IF NOT EXISTS idx_gssapi_realm_deleted ON gssapi_realm(is_deleted);
CREATE INDEX IF NOT EXISTS idx_gssapi_account_user_realm ON gssapi_account(user_id, realm_id);
CREATE INDEX IF NOT EXISTS idx_gssapi_account_principal ON gssapi_account(principal_name);
CREATE INDEX IF NOT EXISTS idx_gssapi_account_last_used ON gssapi_account(last_used_at);

-- Add database constraints for data validation
ALTER TABLE gssapi_realm 
ADD CONSTRAINT realm_name_min_length CHECK (length(name) >= 2),
ADD CONSTRAINT realm_name_max_length CHECK (length(name) <= 100),
ADD CONSTRAINT realm_domain_min_length CHECK (length(realm) >= 3),
ADD CONSTRAINT kdc_hosts_not_empty CHECK (array_length(kdc_hosts, 1) > 0);

ALTER TABLE gssapi_account 
ADD CONSTRAINT principal_name_min_length CHECK (length(principal_name) >= 3);

-- Add table comments
COMMENT ON TABLE gssapi_realm IS 'GSSAPI/Kerberos realm configurations with soft delete support';
COMMENT ON TABLE gssapi_account IS 'User GSSAPI account links with usage tracking';

-- The end.

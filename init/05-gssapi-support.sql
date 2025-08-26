-- Add GSSAPI/Kerberos authentication support to the auth_demo database
-- This script adds tables for GSSAPI realms and accounts

-- Create GSSAPI realms table
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
    default_realm BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create GSSAPI accounts table
CREATE TABLE IF NOT EXISTS gssapi_account (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    realm_id INTEGER NOT NULL REFERENCES gssapi_realm(id) ON DELETE CASCADE,
    principal_name VARCHAR(255) NOT NULL, -- Full Kerberos principal (e.g., user@REALM.COM)
    service_principal VARCHAR(255), -- Service principal if applicable
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(realm_id, principal_name)
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_gssapi_account_user_id ON gssapi_account(user_id);
CREATE INDEX IF NOT EXISTS idx_gssapi_account_realm_id ON gssapi_account(realm_id);
CREATE INDEX IF NOT EXISTS idx_gssapi_account_principal_name ON gssapi_account(principal_name);
CREATE INDEX IF NOT EXISTS idx_gssapi_realm_name ON gssapi_realm(name);
CREATE INDEX IF NOT EXISTS idx_gssapi_realm_realm ON gssapi_realm(realm);


-- The end.

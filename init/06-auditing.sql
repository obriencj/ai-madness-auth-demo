-- Audit Logging Table Creation
-- This script creates the audit_log table for tracking administrative actions and system changes

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

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_audit_log_user_action ON audit_log(user_id, action);
CREATE INDEX IF NOT EXISTS idx_audit_log_resource ON audit_log(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);

-- Add database constraints for data validation
ALTER TABLE audit_log 
ADD CONSTRAINT action_min_length CHECK (length(action) >= 3),
ADD CONSTRAINT action_max_length CHECK (length(action) <= 100),
ADD CONSTRAINT resource_type_min_length CHECK (length(resource_type) >= 2),
ADD CONSTRAINT resource_type_max_length CHECK (length(resource_type) <= 50);

-- Add table comment
COMMENT ON TABLE audit_log IS 'Audit trail for administrative actions and system changes';

-- The end.

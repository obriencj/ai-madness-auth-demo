# Database Initialization and Migration

This directory contains SQL scripts for initializing and migrating the Daft Gila authentication platform database.

## Script Execution Order

The scripts must be executed in the following order:

1. **01-init.sql** - Creates the base user table and admin user
2. **02-oauth-support.sql** - Adds OAuth provider and account tables
3. **03-jwt-sessions.sql** - Adds JWT session tracking table
4. **04-app-config.sql** - Adds application configuration versioning
5. **05-gssapi-support.sql** - Adds GSSAPI/Kerberos authentication support
6. **06-model-optimization.sql** - Adds new fields, constraints, and indexes

## Phase 1.2 Model Optimizations

### New Fields Added

#### User Table
- `created_at` - User account creation timestamp
- `updated_at` - Last update timestamp (auto-updated)
- `last_login_at` - Last successful login timestamp
- `login_attempts` - Failed login attempt counter
- `locked_until` - Account lock expiration timestamp

#### OAuth Provider Table
- `updated_at` - Last update timestamp (auto-updated)
- `is_deleted` - Soft delete flag
- `deleted_at` - Soft delete timestamp
- `deleted_by` - User who performed soft delete

#### OAuth Account Table
- `last_used_at` - Last OAuth token usage timestamp

#### JWT Session Table
- `last_activity_at` - Last session activity timestamp

#### GSSAPI Realm Table
- `is_deleted` - Soft delete flag
- `deleted_at` - Soft delete timestamp
- `deleted_by` - User who performed soft delete

#### GSSAPI Account Table
- `last_used_at` - Last GSSAPI authentication timestamp

#### New Audit Log Table
- `user_id` - User performing the action
- `action` - Description of the action
- `resource_type` - Type of resource being acted upon
- `resource_id` - ID of the specific resource
- `details` - JSON details about the action
- `ip_address` - Client IP address
- `user_agent` - Client user agent
- `created_at` - Action timestamp

### New Constraints Added

#### Data Validation
- Username length: 3-80 characters
- Provider name length: 2-50 characters
- Realm name length: 2-100 characters
- Realm domain length: minimum 3 characters
- JTI length: minimum 32 characters
- Login attempts: non-negative
- Version numbers: positive only

#### Business Logic
- Session expiration must be after creation
- Last activity must be after creation
- KDC hosts array must not be empty

### New Indexes Added

#### Performance Indexes
- Composite indexes for common query patterns
- Indexes on frequently filtered fields
- Indexes on timestamp fields for range queries
- Unique partial index for active app configuration

#### Soft Delete Indexes
- Indexes on `is_deleted` flags for efficient filtering
- Composite indexes combining active status with other fields

## Usage

### Fresh Installation
```bash
# Run all scripts in order
psql -d auth_demo -f 01-init.sql
psql -d auth_demo -f 02-oauth-support.sql
psql -d auth_demo -f 03-jwt-sessions.sql
psql -d auth_demo -f 04-app-config.sql
psql -d auth_demo -f 05-gssapi-support.sql
psql -d auth_demo -f 06-model-optimization.sql
```

### Upgrading Existing Database
```bash
# Run only the new optimization script
psql -d auth_demo -f 06-model-optimization.sql
```

### Verification
```bash
# Check that all tables exist
psql -d auth_demo -c "\dt"

# Check that new fields were added
psql -d auth_demo -c "\d user"
psql -d auth_demo -c "\d oauth_provider"
psql -d auth_demo -c "\d audit_log"

# Verify constraints
psql -d auth_demo -c "SELECT conname, contype, pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid = 'user'::regclass;"
```

## Benefits of Phase 1.2 Optimizations

### Performance Improvements
- **Faster Queries**: Strategic indexes on commonly filtered fields
- **Efficient Joins**: Composite indexes for multi-field lookups
- **Range Queries**: Indexes on timestamp fields for date-based filtering

### Data Integrity
- **Validation**: Database-level constraints prevent invalid data
- **Consistency**: Check constraints ensure business rule compliance
- **Referential Integrity**: Proper foreign key constraints with cascade options

### Security Enhancements
- **Audit Trail**: Complete logging of administrative actions
- **Soft Delete**: Preserve data while marking as deleted
- **Account Locking**: Brute force protection with configurable thresholds

### Maintainability
- **Standardized Timestamps**: Consistent created/updated tracking
- **Usage Tracking**: Monitor authentication method usage patterns
- **Migration Safety**: Non-destructive schema updates

## Rollback Plan

If issues arise during migration, the following rollback script can be used:

```sql
-- Remove new constraints (if needed)
ALTER TABLE "user" DROP CONSTRAINT IF EXISTS username_min_length;
ALTER TABLE "user" DROP CONSTRAINT IF EXISTS username_max_length;
-- ... (repeat for other constraints)

-- Remove new indexes (if needed)
DROP INDEX IF EXISTS idx_user_active_admin;
DROP INDEX IF EXISTS idx_user_created_at;
-- ... (repeat for other indexes)

-- Note: New fields can remain as they don't break existing functionality
```

## Troubleshooting

### Common Issues

1. **Constraint Violations**: Ensure existing data meets new constraints before migration
2. **Index Creation Failures**: Check available disk space and PostgreSQL configuration
3. **Permission Errors**: Ensure database user has ALTER TABLE and CREATE INDEX privileges

### Performance Considerations

- Run migrations during low-traffic periods
- Monitor database performance during migration
- Consider running ANALYZE after migration to update statistics

## The end.

# Database Initialization and Migration

This directory contains SQL scripts for initializing and migrating the Daft Gila authentication platform database.

## Script Execution Order

The scripts must be executed in the following order:

1. **01-init.sql** - Creates the base user table and admin user with Phase 1.2 optimizations
2. **02-oauth-support.sql** - Adds OAuth provider and account tables with Phase 1.2 optimizations
3. **03-jwt-sessions.sql** - Adds JWT session tracking table with Phase 1.2 optimizations
4. **04-app-config.sql** - Adds application configuration versioning with Phase 1.2 optimizations
5. **05-gssapi-support.sql** - Adds GSSAPI/Kerberos authentication support with Phase 1.2 optimizations
6. **06-auditing.sql** - Adds audit logging table for administrative actions

## Phase 1.2 Model Optimizations (Built-in)

All Phase 1.2 optimizations are now integrated directly into the table creation scripts, providing a clean, single-pass database setup.

### Enhanced User Table (01-init.sql)
- **New Fields**: `created_at`, `updated_at`, `last_login_at`, `login_attempts`, `locked_until`
- **Constraints**: Username length validation, login attempts validation
- **Indexes**: Performance indexes for common query patterns
- **Features**: Account locking, login attempt tracking, timestamp tracking

### Enhanced OAuth Tables (02-oauth-support.sql)
- **New Fields**: `updated_at`, `is_deleted`, `deleted_at`, `deleted_by`, `last_used_at`
- **Constraints**: Provider name validation, client ID validation, scope validation
- **Indexes**: Soft delete indexes, usage tracking indexes
- **Features**: Soft delete support, usage monitoring, audit trail

### Enhanced JWT Sessions Table (03-jwt-sessions.sql)
- **New Fields**: `last_activity_at`
- **Constraints**: JTI length validation, timestamp validation
- **Indexes**: Activity monitoring indexes, composite query indexes
- **Features**: Activity tracking, performance optimization

### Enhanced App Config Table (04-app-config.sql)
- **Constraints**: Version number validation
- **Indexes**: Version and creation date indexes
- **Features**: Enhanced query performance, data integrity

### Enhanced GSSAPI Tables (05-gssapi-support.sql)
- **New Fields**: `is_deleted`, `deleted_at`, `deleted_by`, `last_used_at`
- **Constraints**: Realm name validation, domain validation, KDC hosts validation
- **Indexes**: Soft delete indexes, usage tracking indexes
- **Features**: Soft delete support, usage monitoring

### New Audit Log Table (06-auditing.sql)
- **Purpose**: Complete audit trail for administrative actions
- **Fields**: User tracking, action logging, resource monitoring, IP tracking
- **Indexes**: Performance indexes for audit queries
- **Features**: Security compliance, administrative oversight

## Usage

### Fresh Installation
```bash
# Run all scripts in order for complete optimized schema
psql -d auth_demo -f 01-init.sql
psql -d auth_demo -f 02-oauth-support.sql
psql -d auth_demo -f 03-jwt-sessions.sql
psql -d auth_demo -f 04-app-config.sql
psql -d auth_demo -f 05-gssapi-support.sql
psql -d auth_demo -f 06-auditing.sql
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
- **Clean Setup**: Single-pass database initialization

## Development Workflow

Since this is a development environment, the database can be completely recreated at any time:

```bash
# Drop and recreate database
dropdb auth_demo
createdb auth_demo

# Run initialization scripts for fresh optimized schema
psql -d auth_demo -f 01-init.sql
psql -d auth_demo -f 02-oauth-support.sql
psql -d auth_demo -f 03-jwt-sessions.sql
psql -d auth_demo -f 04-app-config.sql
psql -d auth_demo -f 05-gssapi-support.sql
psql -d auth_demo -f 06-auditing.sql
```

This approach ensures:
- **Always Current Schema**: No migration complexity
- **Clean State**: Fresh database every time
- **Fast Development**: Immediate access to latest optimizations
- **No Data Loss Concerns**: Development data can be easily recreated

## The end.

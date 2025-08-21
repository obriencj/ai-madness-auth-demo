# OAuth Scope Field Migration

## Overview

This document describes the migration from hardcoded OAuth provider configuration to a fully database-driven approach, including the addition of the `scope` field.

## Changes Made

### 1. Database Schema Updates

#### New Migration Script: `init/03-add-scope-field.sql`
- Adds `scope` column to `oauth_provider` table
- Sets appropriate default scope values for Google and GitHub providers
- Makes the scope field NOT NULL after setting defaults

#### Updated OAuth Support Script: `init/02-oauth-support.sql`
- Now includes `scope` field in the `oauth_provider` table creation
- Default scope values are set during table creation

### 2. Backend Application Updates

#### Removed Hardcoded Configuration
- Eliminated `app.config['OAUTH_PROVIDERS']` configuration
- All OAuth provider data now comes from the database

#### Updated Models
- `OAuthProvider` model now includes `scope` field
- All CRUD operations handle the scope field

#### Updated Helper Functions
- `get_oauth_provider_config()` now returns scope from database
- OAuth authorization routes use scope from database instead of hardcoded values

#### Updated Admin API Routes
- Create, update, and get routes now handle the scope field
- Scope is included in all provider responses

### 3. Migration Tools

#### Migration Script: `migrate_scope.py`
- Standalone script to add scope field to existing databases
- Automatically sets appropriate default scope values
- Safe to run multiple times (idempotent)

#### Updated Setup Script: `setup_oauth.py`
- Now automatically adds scope field if missing
- Sets default scope values during OAuth provider updates

## Migration Process

### For New Installations
1. The scope field will be automatically created with the database initialization scripts
2. No additional steps required

### For Existing Installations
1. **Option 1**: Run the migration script
   ```bash
   python migrate_scope.py
   ```

2. **Option 2**: Use the updated setup script
   ```bash
   python setup_oauth.py
   ```
   This will automatically add the scope field when updating OAuth credentials

3. **Option 3**: Manual database migration
   ```sql
   -- Add scope column
   ALTER TABLE oauth_provider ADD COLUMN scope VARCHAR(500);
   
   -- Set default values
   UPDATE oauth_provider SET scope = 'openid email profile' WHERE name = 'google';
   UPDATE oauth_provider SET scope = 'read:user user:email' WHERE name = 'github';
   
   -- Make NOT NULL
   ALTER TABLE oauth_provider ALTER COLUMN scope SET NOT NULL;
   ```

## Benefits of This Migration

1. **Centralized Configuration**: All OAuth provider data is now in one place (the database)
2. **Dynamic Updates**: OAuth provider scopes can be updated without code changes
3. **Better Admin Control**: Admins can modify OAuth provider settings through the API
4. **Consistency**: No more split between database and application configuration
5. **Maintainability**: Easier to manage and update OAuth provider settings

## Default Scope Values

- **Google**: `openid email profile`
- **GitHub**: `read:user user:email`

These values can be customized through the admin API after migration.

## API Changes

### New Fields in Responses
- All OAuth provider endpoints now include the `scope` field
- Admin endpoints return scope information for better management

### No Breaking Changes
- Existing API consumers will continue to work
- New scope field is additive and doesn't affect existing functionality

## Testing

After migration, verify that:
1. OAuth login still works for both Google and GitHub
2. Admin can view and edit OAuth provider scopes
3. Scope values are correctly used during OAuth authorization
4. No errors in application logs related to missing scope configuration

## Rollback

If issues arise, the scope field can be removed:
```sql
ALTER TABLE oauth_provider DROP COLUMN scope;
```

However, this will require reverting the application code to the previous version that used hardcoded configuration.

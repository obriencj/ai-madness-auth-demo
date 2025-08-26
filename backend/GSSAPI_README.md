# GSSAPI/Kerberos Authentication Support

This document describes the GSSAPI authentication implementation added to the Gilla Auth system.

## Overview

GSSAPI (Generic Security Services Application Program Interface) authentication allows users to authenticate using Kerberos tickets, providing enterprise-grade single sign-on capabilities. The implementation follows the same pattern as the existing OAuth authentication system.

## Database Schema

### New Tables

#### `gssapi_realm`
Stores Kerberos realm configurations:
- `id`: Primary key
- `name`: Unique realm identifier (e.g., "corporate", "test")
- `realm`: Kerberos realm name (e.g., "CORPORATE.COM")
- `kdc_hosts`: Array of KDC (Key Distribution Center) hostnames
- `admin_server`: Kerberos admin server hostname
- `service_principal`: Service principal for the application (e.g., "HTTP/hostname@REALM.COM")
- `encrypted_keytab`: Encrypted keytab data stored securely in the database
- `keytab_encryption_iv`: Initialization vector for AES encryption
- `keytab_encryption_salt`: Salt for key derivation
- `default_realm`: Boolean flag for default realm
- `is_active`: Whether the realm is active
- `created_at`, `updated_at`: Timestamps

#### `gssapi_account`
Links users to their GSSAPI identities:
- `id`: Primary key
- `user_id`: Foreign key to user table
- `realm_id`: Foreign key to gssapi_realm table
- `principal_name`: Full Kerberos principal (e.g., "user@REALM.COM")
- `service_principal`: Service principal if applicable
- `created_at`, `updated_at`: Timestamps

## API Endpoints

### Authentication

#### `POST /api/v1/auth/gssapi/authenticate`
Authenticates a user via GSSAPI/Kerberos.

**Request Body:**
```json
{
    "principal_name": "user@REALM.COM",
    "realm_name": "corporate"  // Optional, uses default if not specified
}
```

**Response:**
```json
{
    "access_token": "jwt_token_here",
    "user": {
        "id": 123,
        "username": "user",
        "email": "user@gssapi.local",
        "is_admin": false
    }
}
```

### Realm Management (Admin Only)

#### `GET /api/v1/auth/gssapi/realms`
Lists all available GSSAPI realms.

#### `POST /api/v1/auth/gssapi/realms`
Creates a new GSSAPI realm.

**Request Body:**
```json
{
    "name": "corporate",
    "realm": "CORPORATE.COM",
    "kdc_hosts": ["kdc1.corporate.com", "kdc2.corporate.com"],
    "admin_server": "kadmin.corporate.com",
    "service_principal": "HTTP/auth.corporate.com@CORPORATE.COM",
    "keytab_data": "base64_encoded_keytab_content_here",
    "default_realm": true,
    "is_active": true
}
```

**Note**: The `keytab_data` field should contain the base64-encoded content of your keytab file. You can encode it using:
```bash
base64 -w 0 /path/to/your/keytab > keytab.b64
```

#### `PUT /api/v1/auth/gssapi/realms/<id>`
Updates an existing GSSAPI realm.

#### `DELETE /api/v1/auth/gssapi/realms/<id>`
Deletes a GSSAPI realm (only if no accounts are linked).

### Account Management

#### `GET /api/v1/auth/gssapi/accounts`
Gets GSSAPI accounts for the current authenticated user.

## Implementation Details

### User Creation and Linking

1. **New User**: When a user authenticates via GSSAPI for the first time, a new user account is created automatically.
2. **Existing User**: If a user with the same username exists, the GSSAPI account is linked to the existing user.
3. **Username Generation**: Usernames are extracted from the Kerberos principal (before the @ symbol).

### Authentication Flow

1. User provides their Kerberos principal name
2. System validates the realm configuration
3. System checks for existing GSSAPI account
4. If no account exists, creates/links user account
5. Generates JWT token and session record
6. Returns authentication response

### Security Considerations

- GSSAPI authentication requires valid Kerberos tickets
- Realm configurations are managed by admin users only
- Users cannot modify their own GSSAPI account links
- Deletion of realms is prevented if accounts are linked

## Configuration

### Database Setup

Run the new SQL initialization script:
```bash
psql -d auth_demo -f init/05-gssapi-support.sql
```

### Keytab Management

The GSSAPI implementation stores keytab files encrypted in the database for enhanced security and portability. Keytabs are:

1. **Encrypted at rest**: All keytab data is encrypted using AES-256-GCM with PBKDF2 key derivation
2. **Base64 encoded**: Keytabs are uploaded as base64-encoded strings in the API requests
3. **Automatically validated**: Keytab format and service principal compatibility are verified before storage
4. **Securely cached**: Decrypted keytabs are cached in memory and Redis for performance

#### Creating a Service Principal and Keytab

```bash
# On the KDC server, create a service principal
kadmin.local -q "addprinc -randkey HTTP/auth.example.com@EXAMPLE.COM"

# Extract the keytab
kadmin.local -q "ktadd -k /tmp/auth.keytab HTTP/auth.example.com@EXAMPLE.COM"

# Copy the keytab to the application server
scp /tmp/auth.keytab user@app-server:/etc/krb5.keytab

# Set proper permissions
chmod 600 /etc/krb5.keytab
```

### Dependencies

The following Python packages are required:
- `gssapi>=1.8.0` - GSSAPI bindings
- `cryptography>=41.0.0` - Cryptographic operations

### Environment Variables

The following environment variables are required for GSSAPI functionality:

- `GSSAPI_MASTER_KEY`: Strong encryption key for keytab encryption (32+ characters recommended)
- `REDIS_URL`: Redis connection URL for caching (optional, defaults to redis://localhost:6379)

**Important**: The `GSSAPI_MASTER_KEY` should be a strong, random string. You can generate one using:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

**Security Note**: Never commit the master key to version control. Store it securely in environment variables or a secrets management system.

### Configuration Validation

The GSSAPI implementation automatically validates realm configurations when they are created or updated:

1. **Keytab Format Validation**: Verifies the uploaded keytab data format
2. **Service Principal Validation**: Checks the service principal format
3. **GSSAPI Credential Acquisition**: Tests credentials using temporary keytab files
4. **Real-time Validation**: Configuration is validated before saving to prevent invalid setups

If validation fails, the realm creation/update will be rejected with a detailed error message.

### Caching System

The implementation uses a three-tier caching strategy for optimal performance:

1. **L1 Cache (Memory)**: Fastest access, stores decrypted keytabs in application memory
   - TTL: 4 hours (configurable)
   - Max size: 50 realms (configurable)
   - Automatic LRU eviction

2. **L2 Cache (Redis)**: Medium speed, stores encrypted keytabs in Redis
   - TTL: 24 hours (configurable)
   - Encrypted storage for security
   - Optional (gracefully degrades if Redis unavailable)

3. **L3 Cache (Database)**: Slowest but most secure, stores encrypted keytabs
   - Always available
   - Encrypted using AES-256-GCM
   - Master key stored in environment variables

#### Cache Management Endpoints

- `GET /api/v1/auth/gssapi/cache/stats` - View cache statistics (admin only)
- `POST /api/v1/auth/gssapi/cache/clear` - Clear all caches (admin only)

## Usage Examples

### Creating a Corporate Realm

```bash
# Login as admin first to get token
curl -X POST http://localhost:5000/api/v1/auth/gssapi/realms \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "corporate",
    "realm": "CORPORATE.COM",
    "kdc_hosts": ["kdc1.corporate.com", "kdc2.corporate.com"],
    "admin_server": "kadmin.corporate.com",
    "default_realm": true,
    "is_active": true
  }'
```

### Authenticating a User

```bash
curl -X POST http://localhost:5000/api/v1/auth/gssapi/authenticate \
  -H "Content-Type: application/json" \
  -d '{
    "principal_name": "john.doe@CORPORATE.COM"
  }'
```

## Testing

Use the provided test script to verify the implementation:
```bash
cd backend
python test_gssapi.py
```

## Integration with Existing System

The GSSAPI implementation integrates seamlessly with the existing authentication system:

- Uses the same JWT token system
- Follows the same session management pattern
- Integrates with the existing user model
- Maintains consistency with OAuth implementation patterns

## Future Enhancements

Potential improvements for future versions:
- Support for service principals
- Kerberos ticket validation
- Cross-realm authentication
- Integration with LDAP for user attributes
- Support for Kerberos delegation

## Troubleshooting

### Common Issues

1. **Realm not found**: Ensure the realm is created and active
2. **Authentication failed**: Verify Kerberos ticket validity
3. **Database errors**: Check that the new tables are created
4. **Permission denied**: Ensure admin privileges for realm management
5. **Keytab validation failed**: Check keytab file path, permissions, and service principal
6. **GSSAPI library not available**: Ensure the `gssapi` Python package is installed
7. **Service principal mismatch**: Verify the keytab contains keys for the specified service principal

### Debugging

Enable debug logging in the Flask application to see detailed authentication flow information.

## Support

For issues or questions regarding the GSSAPI implementation, refer to the main project documentation or contact the development team.

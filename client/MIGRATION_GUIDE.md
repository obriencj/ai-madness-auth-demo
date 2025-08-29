# Migration Guide: Frontend to DaftGilaClient

This guide shows how to migrate the current frontend code from direct `requests` calls to using the new `DaftGilaClient`.

## Current Frontend Implementation

The frontend currently makes direct HTTP requests like this:

```python
# In admin.py
headers = {'Authorization': f'Bearer {session["access_token"]}'}
response = requests.get(f'{BACKEND_URL}/api/v1/admin/users', headers=headers)
users = extract_api_data(response, 'users', default=[])

# In user.py
response = requests.post(f'{BACKEND_URL}/api/v1/auth/login', 
                        json={'username': username, 'password': password})
```

## New DaftGilaClient Implementation

Replace the direct requests with the client:

```python
# Initialize client once (e.g., in app factory or global scope)
from daftgila.client import DaftGilaClient

client = DaftGilaClient(base_url=BACKEND_URL)

# Set authentication token when user logs in
client.set_auth_token(session["access_token"])

# Use client methods instead of direct requests
users_response = client.admin.get_users()
if users_response.is_success:
    users = users_response.data['users']
else:
    users = []
    flash(f'Error: {users_response.message}', 'error')

# Authentication
login_response = client.auth.login(username, password)
if login_response.is_success:
    # Store token in session
    session["access_token"] = login_response.data['access_token']
    # Client automatically sets auth header
else:
    flash(f'Login failed: {login_response.message}', 'error')
```

## Migration Examples

### 1. User Authentication

**Before:**
```python
import requests
from .utils import BACKEND_URL, extract_api_data

def login_user(username, password):
    response = requests.post(f'{BACKEND_URL}/api/v1/auth/login', 
                           json={'username': username, 'password': password})
    
    if response.status_code == 200:
        data = extract_api_data(response, 'data')
        if data and 'access_token' in data:
            session["access_token"] = data['access_token']
            return True
    return False
```

**After:**
```python
from daftgila.client import DaftGilaClient

def login_user(username, password):
    client = DaftGilaClient(base_url=BACKEND_URL)
    
    try:
        response = client.auth.login(username, password)
        
        if response.is_success:
            session["access_token"] = response.data['access_token']
            # Store client in session for future use
            session["api_client"] = client
            return True
        else:
            flash(f'Login failed: {response.message}', 'error')
            return False
            
    except Exception as e:
        flash(f'Connection error: {str(e)}', 'error')
        return False
```

### 2. Admin User Management

**Before:**
```python
def get_users():
    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    response = requests.get(f'{BACKEND_URL}/api/v1/admin/users', headers=headers)
    return extract_api_data(response, 'users', default=[])

def create_user(user_data):
    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    response = requests.post(f'{BACKEND_URL}/api/v1/register', 
                           json=user_data, headers=headers)
    
    if response.status_code == 201:
        flash('User created successfully', 'success')
    else:
        error_message = extract_api_data(response, 'error', default='Unknown error')
        flash(f'Error: {error_message}', 'error')
```

**After:**
```python
def get_users():
    client = session.get("api_client")
    if not client:
        return []
    
    try:
        response = client.admin.get_users()
        if response.is_success:
            return response.data['users']
        else:
            flash(f'Error fetching users: {response.message}', 'error')
            return []
    except Exception as e:
        flash(f'Connection error: {str(e)}', 'error')
        return []

def create_user(user_data):
    client = session.get("api_client")
    if not client:
        flash('Not authenticated', 'error')
        return False
    
    try:
        response = client.admin.create_user(
            username=user_data['username'],
            email=user_data['email'],
            password=user_data['password'],
            is_admin=user_data.get('is_admin', False)
        )
        
        if response.is_success:
            flash('User created successfully', 'success')
            return True
        else:
            flash(f'Error: {response.message}', 'error')
            return False
            
    except Exception as e:
        flash(f'Connection error: {str(e)}', 'error')
        return False
```

### 3. OAuth Account Management

**Before:**
```python
def get_user_oauth_accounts(user_id):
    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    response = requests.get(
        f'{BACKEND_URL}/api/v1/admin/users/{user_id}/oauth-accounts',
        headers=headers
    )
    return extract_api_data(response, 'oauth_accounts', default=[])
```

**After:**
```python
def get_user_oauth_accounts(user_id):
    client = session.get("api_client")
    if not client:
        return []
    
    try:
        response = client.admin.get_user_oauth_accounts(user_id)
        if response.is_success:
            return response.data['oauth_accounts']
        else:
            flash(f'Error fetching OAuth accounts: {response.message}', 'error')
            return []
    except Exception as e:
        flash(f'Connection error: {str(e)}', 'error')
        return []
```

## Benefits of Migration

### 1. **Consistent Response Handling**
- No more manual JSON parsing
- Standardized error handling
- Type-safe response access

### 2. **Automatic Header Management**
- JWT tokens automatically included
- No more manual `Authorization` header setting
- Consistent header management across all requests

### 3. **Better Error Handling**
- Structured error responses
- Connection error handling
- Validation error handling

### 4. **Code Maintainability**
- Centralized API logic
- Easier to update API endpoints
- Better testing capabilities

### 5. **Type Safety**
- Full type hints
- Better IDE support
- Runtime validation

## Implementation Strategy

### Phase 1: Setup and Testing
1. Install the `daftgila.client` package
2. Create a test client instance
3. Test basic connectivity and authentication

### Phase 2: Authentication Migration
1. Replace login/logout endpoints
2. Update session management
3. Test authentication flow

### Phase 3: Admin Operations
1. Migrate user management endpoints
2. Update admin dashboard
3. Test admin functionality

### Phase 4: OAuth and Advanced Features
1. Migrate OAuth endpoints
2. Update OAuth management
3. Test OAuth flows

### Phase 5: Cleanup
1. Remove old `requests` code
2. Remove `extract_api_data` utility
3. Update error handling

## Testing the Migration

Use the provided test scripts:

```bash
# Test basic functionality
python3 test_client.py

# Test examples
python3 example_usage.py

# Test installation
python3 install.py
```

## Troubleshooting

### Common Issues

1. **Import Errors**: Ensure the package is installed correctly
2. **Authentication Failures**: Check token format and expiration
3. **Connection Errors**: Verify backend URL and network connectivity
4. **Response Parsing**: Use the standardized response format

### Debug Mode

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Client will show detailed request/response information
```

## Support

For issues or questions about the migration:
1. Check the example scripts
2. Review the client source code
3. Test with the provided test suite
4. Check backend API documentation

# The end.

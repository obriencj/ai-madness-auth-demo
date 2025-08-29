# Daft Gila Client

A Python client library for the Daft Gila authentication platform API. This package provides an object-oriented interface for interacting with Daft Gila API endpoints, handling authentication, and managing user sessions.

## Features

- **Object-oriented design**: Clean, intuitive API wrapper
- **Automatic authentication**: Handles JWT tokens and session management
- **Type safety**: Full type hints for better development experience
- **Error handling**: Consistent error handling and response parsing
- **Header management**: Automatic header setting and management
- **Response parsing**: Built-in JSON response parsing and validation

## Installation

```bash
pip install daftgila.client
```

## Quick Start

```python
from daftgila.client import DaftGilaClient

# Create client instance
client = DaftGilaClient(base_url="http://localhost:5000")

# Authenticate
response = client.auth.login(username="admin", password="admin123")
if response.success:
    print(f"Logged in as {response.data['user']['username']}")

# Use authenticated client
users = client.admin.get_users()
print(f"Found {len(users.data['users'])} users")

# Logout
client.auth.logout()
```

## API Reference

### Authentication

```python
# Login
response = client.auth.login(username="user", password="pass")

# Logout
response = client.auth.logout()

# Register new user
response = client.auth.register(username="newuser", email="user@example.com", password="pass")
```

### User Management

```python
# Get all users (admin only)
users = client.admin.get_users()

# Create user (admin only)
response = client.admin.create_user(username="newuser", email="user@example.com", password="pass", is_admin=False)

# Update user (admin only)
response = client.admin.update_user(user_id=1, email="newemail@example.com", is_admin=True)

# Delete user (admin only)
response = client.admin.delete_user(user_id=1)
```

### General API

```python
# Test endpoint
response = client.test()

# Protected hello endpoint
response = client.hello()
```

## Response Format

All API responses follow a consistent format:

```python
class APIResponse:
    success: bool
    message: str
    data: Optional[Dict[str, Any]]
    status_code: int
```

## Error Handling

The client automatically handles common HTTP errors and provides meaningful error messages:

```python
try:
    response = client.auth.login(username="user", password="wrong")
except DaftGilaClientError as e:
    print(f"Authentication failed: {e}")
```

## Configuration

The client can be configured with various options:

```python
client = DaftGilaClient(
    base_url="http://localhost:5000",
    timeout=30,
    verify_ssl=True,
    default_headers={"User-Agent": "DaftGilaClient/1.0"}
)
```

## Development

To set up the development environment:

```bash
git clone <repository>
cd client
pip install -e ".[dev]"
pytest
black .
flake8
mypy .
```

## License

GNU General Public License v3 (GPLv3)

## Author

Christopher O'Brien <obriencj@gmail.com>

import os
from datetime import timedelta
from flask import Flask, request, jsonify, redirect, url_for, session
from flask_cors import CORS
from flask_oauthlib.client import OAuth

# Import models and database instances
from .model import db, User, OAuthProvider, OAuthAccount

# Import JWT functionality
from .jwt import (
    redis_client, configure_jwt,
    jwt_required, create_access_token,
    get_jwt_identity, get_jwt
)

# Import OAuth functionality
from .oauth import (
    handle_oauth_authorize, handle_oauth_callback, 
    handle_oauth_link, get_oauth_providers_list
)

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL', 
    'postgresql://auth_user:auth_password@localhost:5432/auth_demo'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
configure_jwt(app)  # Configure JWT settings
CORS(app)
oauth = OAuth(app)

# Routes
@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Missing username or password'}), 400
    
    user = User.query.filter_by(username=data['username']).first()
    
    if user and user.check_password(data['password']) and user.is_active:
        access_token = create_access_token(identity=user.username)
        
        return jsonify({
            'access_token': access_token,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_admin': user.is_admin
            }
        }), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/v1/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    from jwt import blacklist_token
    blacklist_token(jti, timedelta(hours=1))
    return jsonify({'message': 'Successfully logged out'}), 200

@app.route('/api/v1/register', methods=['POST'])
@jwt_required()
def register_user():
    current_username = get_jwt_identity()
    current_user = User.query.filter_by(username=current_username).first()
    
    if not current_user or not current_user.is_admin:
        return jsonify({'error': 'Admin privileges required'}), 403
    
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Check if user already exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 400
    
    # Create new user
    new_user = User(
        username=data['username'],
        email=data['email'],
        is_admin=data.get('is_admin', False)
    )
    new_user.set_password(data['password'])
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({
        'message': 'User created successfully',
        'user': {
            'id': new_user.id,
            'username': new_user.username,
            'email': new_user.email,
            'is_admin': new_user.is_admin
        }
    }), 201


@app.route('/api/v1/auth/register', methods=['POST'])
def self_register():
    """Allow new users to register themselves"""
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Check if user already exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 400
    
    # Create new user (non-admin by default)
    new_user = User(
        username=data['username'],
        email=data['email'],
        is_admin=False
    )
    new_user.set_password(data['password'])
    
    try:
        db.session.add(new_user)
        db.session.commit()
        
        # Create JWT token for immediate login
        access_token = create_access_token(identity=new_user.username)
        
        return jsonify({
            'message': 'User registered successfully',
            'access_token': access_token,
            'user': {
                'id': new_user.id,
                'username': new_user.username,
                'email': new_user.email,
                'is_admin': new_user.is_admin
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to create user'}), 500

@app.route('/api/v1/users', methods=['GET'])
@jwt_required()
def get_users():
    try:
        current_username = get_jwt_identity()
        print(f"Users endpoint: Called by user: {current_username}")
        current_user = User.query.filter_by(username=current_username).first()
        
        if not current_user:
            print(f"Users endpoint: User not found for username: {current_username}")
            return jsonify({'error': 'User not found'}), 404
        
        if not current_user.is_admin:
            print(f"Users endpoint: User {current_user.username} is not admin")
            return jsonify({'error': 'Admin privileges required'}), 403
        
        users = User.query.all()
        print(f"Users endpoint: Returning {len(users)} users")
        return jsonify({
            'users': [{
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_admin': user.is_admin,
                'is_active': user.is_active
            } for user in users]
        }), 200
    except Exception as e:
        print(f"Users endpoint: Error - {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/v1/users/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    current_username = get_jwt_identity()
    current_user = User.query.filter_by(username=current_username).first()
    
    if not current_user or not current_user.is_admin:
        return jsonify({'error': 'Admin privileges required'}), 403
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    
    if 'email' in data:
        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user and existing_user.id != user_id:
            return jsonify({'error': 'Email already exists'}), 400
        user.email = data['email']
    
    if 'is_admin' in data:
        user.is_admin = data['is_admin']
    
    if 'is_active' in data:
        user.is_active = data['is_active']
    
    if 'password' in data and data['password']:
        user.set_password(data['password'])
    
    db.session.commit()
    
    return jsonify({
        'message': 'User updated successfully',
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_admin': user.is_admin,
            'is_active': user.is_active
        }
    }), 200

@app.route('/api/v1/test', methods=['GET'])
def test():
    return jsonify({'message': 'Backend is working'}), 200

@app.route('/api/v1/hello', methods=['GET'])
@jwt_required()
def hello():
    try:
        current_username = get_jwt_identity()
        print(f"Hello endpoint called by user: {current_username}")
        return jsonify({'message': 'hello world'}), 200
    except Exception as e:
        print(f"Error in hello endpoint: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/v1/me', methods=['GET'])
@jwt_required()
def get_current_user():
    current_username = get_jwt_identity()
    user = User.query.filter_by(username=current_username).first()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_admin': user.is_admin
        }
    }), 200





# OAuth Routes
@app.route('/api/v1/auth/oauth/<provider>/authorize', methods=['GET'])
def oauth_authorize(provider):
    """Redirect user to OAuth provider for authorization"""
    redirect_uri = request.args.get('redirect_uri')
    if not redirect_uri:
        return jsonify({'error': 'Missing redirect_uri parameter'}), 400
    
    return handle_oauth_authorize(provider, redirect_uri)


@app.route('/api/v1/auth/oauth/<provider>/callback', methods=['GET'])
def oauth_callback(provider):
    """Handle OAuth callback from provider"""
    code = request.args.get('code')
    error = request.args.get('error')
    
    return handle_oauth_callback(provider, code, error)


@app.route('/api/v1/auth/oauth/<provider>/link', methods=['GET'])
@jwt_required()
def oauth_link(provider):
    """Handle OAuth linking for existing users"""
    code = request.args.get('code')
    error = request.args.get('error')
    
    # Get current user from JWT
    current_username = get_jwt_identity()
    current_user = User.query.filter_by(username=current_username).first()
    
    if not current_user:
        return jsonify({'error': 'User not found'}), 404
    
    return handle_oauth_link(provider, code, error, current_user)





@app.route('/api/v1/auth/oauth/providers', methods=['GET'])
def get_oauth_providers():
    """Get list of available OAuth providers"""
    return get_oauth_providers_list()





@app.route('/api/v1/auth/oauth/connect/<provider>', methods=['POST'])
@jwt_required()
def connect_oauth_provider(provider):
    """Connect OAuth provider to existing user account"""
    current_username = get_jwt_identity()
    user = User.query.filter_by(username=current_username).first()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # This endpoint would handle connecting additional OAuth providers
    # For now, we'll return a message indicating it's not implemented
    return jsonify({'message': 'OAuth provider connection not yet implemented'}), 501


# User Account Management Routes
@app.route('/api/v1/auth/account', methods=['GET'])
@jwt_required()
def get_user_account():
    """Get current user's account information including OAuth accounts"""
    current_username = get_jwt_identity()
    user = User.query.filter_by(username=current_username).first()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Get OAuth accounts for this user
    oauth_accounts = []
    for oauth_account in user.oauth_accounts:
        oauth_accounts.append({
            'id': oauth_account.id,
            'provider': oauth_account.provider.name,
            'provider_user_id': oauth_account.provider_user_id,
            'connected_at': oauth_account.created_at.isoformat() if oauth_account.created_at else None
        })
    
    return jsonify({
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_admin': user.is_admin,
            'is_active': user.is_active,
            'has_password': user.password_hash is not None,
            'oauth_accounts': oauth_accounts
        }
    }), 200


@app.route('/api/v1/auth/account', methods=['PUT'])
@jwt_required()
def update_user_account():
    """Update current user's account information"""
    current_username = get_jwt_identity()
    user = User.query.filter_by(username=current_username).first()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    
    # Users can only update certain fields
    if 'email' in data:
        # Check if email is already taken by another user
        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user and existing_user.id != user.id:
            return jsonify({'error': 'Email already exists'}), 400
        user.email = data['email']
    
    if 'password' in data and data['password']:
        user.set_password(data['password'])
    
    try:
        db.session.commit()
        return jsonify({
            'message': 'Account updated successfully',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_admin': user.is_admin,
                'is_active': user.is_active
            }
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to update account'}), 500


@app.route('/api/v1/auth/account/oauth/<int:oauth_account_id>', methods=['DELETE'])
@jwt_required()
def remove_oauth_account(oauth_account_id):
    """Remove OAuth account from current user"""
    current_username = get_jwt_identity()
    user = User.query.filter_by(username=current_username).first()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Find the OAuth account and verify it belongs to the current user
    oauth_account = OAuthAccount.query.filter_by(
        id=oauth_account_id, user_id=user.id
    ).first()
    
    if not oauth_account:
        return jsonify({'error': 'OAuth account not found'}), 404
    
    # Check if user would be left without any authentication method
    if not user.password_hash and len(user.oauth_accounts) <= 1:
        return jsonify({
            'error': 'Cannot remove OAuth account. You must have at least one authentication method.'
        }), 400
    
    try:
        db.session.delete(oauth_account)
        db.session.commit()
        return jsonify({'message': 'OAuth account removed successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to remove OAuth account'}), 500


# Admin OAuth Management Routes
@app.route('/api/v1/users/<int:user_id>/oauth-accounts', methods=['GET'])
@jwt_required()
def get_user_oauth_accounts(user_id):
    """Get OAuth accounts for a specific user (admin only)"""
    current_username = get_jwt_identity()
    current_user = User.query.filter_by(username=current_username).first()
    
    if not current_user or not current_user.is_admin:
        return jsonify({'error': 'Admin privileges required'}), 403
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    oauth_accounts = []
    for oauth_account in user.oauth_accounts:
        oauth_accounts.append({
            'id': oauth_account.id,
            'provider': oauth_account.provider.name,
            'provider_user_id': oauth_account.provider_user_id,
            'connected_at': oauth_account.created_at.isoformat() if oauth_account.created_at else None
        })
    
    return jsonify({
        'user_id': user.id,
        'username': user.username,
        'oauth_accounts': oauth_accounts
    }), 200


@app.route('/api/v1/users/<int:user_id>/oauth-accounts/<int:oauth_account_id>', methods=['DELETE'])
@jwt_required()
def admin_remove_user_oauth_account(user_id, oauth_account_id):
    """Remove OAuth account from a user (admin only)"""
    current_username = get_jwt_identity()
    current_user = User.query.filter_by(username=current_username).first()
    
    if not current_user or not current_user.is_admin:
        return jsonify({'error': 'Admin privileges required'}), 403
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    oauth_account = OAuthAccount.query.filter_by(
        id=oauth_account_id, user_id=user.id
    ).first()
    
    if not oauth_account:
        return jsonify({'error': 'OAuth account not found'}), 404
    
    # Check if user would be left without any authentication method
    if not user.password_hash and len(user.oauth_accounts) <= 1:
        return jsonify({
            'error': 'Cannot remove OAuth account. User must have at least one authentication method.'
        }), 400
    
    try:
        db.session.delete(oauth_account)
        db.session.commit()
        return jsonify({'message': 'OAuth account removed successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to remove OAuth account'}), 500


# OAuth Provider Management Routes (Admin Only)
@app.route('/api/v1/admin/oauth-providers', methods=['GET'])
@jwt_required()
def get_oauth_providers_admin():
    """Get all OAuth providers (admin only)"""
    current_username = get_jwt_identity()
    current_user = User.query.filter_by(username=current_username).first()
    
    if not current_user or not current_user.is_admin:
        return jsonify({'error': 'Admin privileges required'}), 403
    
    providers = OAuthProvider.query.all()
    return jsonify({
        'providers': [{
            'id': provider.id,
            'name': provider.name,
            'client_id': provider.client_id,
            'client_secret': '***' if provider.client_secret else None,  # Hide secrets
            'authorize_url': provider.authorize_url,
            'token_url': provider.token_url,
            'userinfo_url': provider.userinfo_url,
            'scope': provider.scope,
            'is_active': provider.is_active,
            'created_at': provider.created_at.isoformat() if provider.created_at else None
        } for provider in providers]
    }), 200


@app.route('/api/v1/admin/oauth-providers', methods=['POST'])
@jwt_required()
def create_oauth_provider():
    """Create new OAuth provider (admin only)"""
    current_username = get_jwt_identity()
    current_user = User.query.filter_by(username=current_username).first()
    
    if not current_user or not current_user.is_admin:
        return jsonify({'error': 'Admin privileges required'}), 403
    
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['name', 'client_id', 'client_secret', 'authorize_url', 'token_url', 'userinfo_url', 'scope']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'error': f'Missing required field: {field}'}), 400
    
    # Check if provider name already exists
    if OAuthProvider.query.filter_by(name=data['name']).first():
        return jsonify({'error': 'Provider name already exists'}), 400
    
    # Create new provider
    new_provider = OAuthProvider(
        name=data['name'],
        client_id=data['client_id'],
        client_secret=data['client_secret'],
        authorize_url=data['authorize_url'],
        token_url=data['token_url'],
        userinfo_url=data['userinfo_url'],
        scope=data['scope'],
        is_active=data.get('is_active', True)
    )
    
    try:
        db.session.add(new_provider)
        db.session.commit()
        
        return jsonify({
            'message': 'OAuth provider created successfully',
            'provider': {
                'id': new_provider.id,
                'name': new_provider.name,
                'client_id': new_provider.client_id,
                'client_secret': '***',
                'authorize_url': new_provider.authorize_url,
                'token_url': new_provider.token_url,
                'userinfo_url': new_provider.userinfo_url,
                'scope': new_provider.scope,
                'is_active': new_provider.is_active
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to create provider: {str(e)}'}), 500


@app.route('/api/v1/admin/oauth-providers/<int:provider_id>', methods=['PUT'])
@jwt_required()
def update_oauth_provider(provider_id):
    """Update OAuth provider (admin only)"""
    current_username = get_jwt_identity()
    current_user = User.query.filter_by(username=current_username).first()
    
    if not current_user or not current_user.is_admin:
        return jsonify({'error': 'Admin privileges required'}), 403
    
    provider = OAuthProvider.query.get(provider_id)
    if not provider:
        return jsonify({'error': 'OAuth provider not found'}), 404
    
    data = request.get_json()
    
    # Update fields if provided
    if 'name' in data:
        # Check if new name conflicts with existing provider
        existing_provider = OAuthProvider.query.filter_by(name=data['name']).first()
        if existing_provider and existing_provider.id != provider_id:
            return jsonify({'error': 'Provider name already exists'}), 400
        provider.name = data['name']
    
    if 'client_id' in data:
        provider.client_id = data['client_id']
    
    if 'client_secret' in data and data['client_secret']:
        provider.client_secret = data['client_secret']
    
    if 'authorize_url' in data:
        provider.authorize_url = data['authorize_url']
    
    if 'token_url' in data:
        provider.token_url = data['token_url']
    
    if 'userinfo_url' in data:
        provider.userinfo_url = data['userinfo_url']
    
    if 'scope' in data:
        provider.scope = data['scope']
    
    if 'is_active' in data:
        provider.is_active = data['is_active']
    
    try:
        db.session.commit()
        
        return jsonify({
            'message': 'OAuth provider updated successfully',
            'provider': {
                'id': provider.id,
                'name': provider.name,
                'client_id': provider.client_id,
                'client_secret': '***',
                'authorize_url': provider.authorize_url,
                'token_url': provider.token_url,
                'userinfo_url': provider.userinfo_url,
                'scope': provider.scope,
                'is_active': provider.is_active
            }
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to update provider: {str(e)}'}), 500


@app.route('/api/v1/admin/oauth-providers/<int:provider_id>', methods=['DELETE'])
@jwt_required()
def delete_oauth_provider(provider_id):
    """Delete OAuth provider (admin only)"""
    current_username = get_jwt_identity()
    current_user = User.query.filter_by(username=current_username).first()
    
    if not current_user or not current_user.is_admin:
        return jsonify({'error': 'Admin privileges required'}), 403
    
    provider = OAuthProvider.query.get(provider_id)
    if not provider:
        return jsonify({'error': 'OAuth provider not found'}), 404
    
    # Check if provider has connected accounts
    connected_accounts = OAuthAccount.query.filter_by(provider_id=provider_id).count()
    if connected_accounts > 0:
        return jsonify({
            'error': f'Cannot delete provider. {connected_accounts} user(s) have connected accounts.'
        }), 400
    
    try:
        db.session.delete(provider)
        db.session.commit()
        
        return jsonify({'message': 'OAuth provider deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to delete provider: {str(e)}'}), 500


# Application entry point for Gunicorn
# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=5000, debug=True)

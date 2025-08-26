import os
from datetime import timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS

# Import models and database instances
from .model import db, User, OAuthProvider, OAuthAccount, JWTSession

# Import JWT functionality
from .jwt import (
    configure_jwt, expire_jwt_session,
    jwt_required, create_access_token, create_jwt_session,
    get_jwt_identity, get_jwt, jwt_bp
)

# Import blueprints
from .oauth import oauth_bp
from .config import config_bp, public_config_bp
from .user import user_bp


def create_app():
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

    # Register blueprints
    app.register_blueprint(oauth_bp)
    app.register_blueprint(jwt_bp)
    app.register_blueprint(config_bp)
    app.register_blueprint(public_config_bp)
    app.register_blueprint(user_bp)

    return app


app = create_app()


# Routes


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


# The end.

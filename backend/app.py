import os
import bcrypt
import redis
import requests
from datetime import timedelta
from flask import Flask, request, jsonify, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity, get_jwt
)
from flask_cors import CORS
from flask_oauthlib.client import OAuth

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL', 
    'postgresql://auth_user:auth_password@localhost:5432/auth_demo'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv(
    'JWT_SECRET_KEY', 
    'your-super-secret-jwt-key-change-in-production'
)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_ALGORITHM'] = 'HS256'
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'

# OAuth Configuration
app.config['OAUTH_PROVIDERS'] = {
    'google': {
        'client_id': os.getenv('GOOGLE_CLIENT_ID', ''),
        'client_secret': os.getenv('GOOGLE_CLIENT_SECRET', ''),
        'authorize_url': 'https://accounts.google.com/o/oauth2/v2/auth',
        'token_url': 'https://oauth2.googleapis.com/token',
        'userinfo_url': 'https://www.googleapis.com/oauth2/v2/userinfo',
        'scope': 'openid email profile'
    },
    'github': {
        'client_id': os.getenv('GITHUB_CLIENT_ID', ''),
        'client_secret': os.getenv('GITHUB_CLIENT_SECRET', ''),
        'authorize_url': 'https://github.com/login/oauth/authorize',
        'token_url': 'https://github.com/login/oauth/access_token',
        'userinfo_url': 'https://api.github.com/user',
        'scope': 'read:user user:email'
    }
}

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
CORS(app)
oauth = OAuth(app)


# JWT error handlers
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    print(f"JWT expired token callback: {jwt_payload}")
    return jsonify({'error': 'Token has expired'}), 401


@jwt.invalid_token_loader
def invalid_token_callback(error):
    print(f"JWT invalid token callback: {error}")
    return jsonify({'error': 'Invalid token'}), 401


@jwt.unauthorized_loader
def missing_token_callback(error):
    print(f"JWT missing token callback: {error}")
    return jsonify({'error': 'Missing authorization token'}), 401


# Redis connection
redis_client = redis.from_url(
    os.getenv('REDIS_URL', 'redis://localhost:6379')
)

# User model
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=True)  # Made nullable for OAuth users
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(
            password.encode('utf-8'), bcrypt.gensalt()
        ).decode('utf-8')

    def check_password(self, password):
        if not self.password_hash:
            return False
        return bcrypt.checkpw(
            password.encode('utf-8'), self.password_hash.encode('utf-8')
        )


# OAuth Provider model
class OAuthProvider(db.Model):
    __tablename__ = 'oauth_provider'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    client_id = db.Column(db.String(255), nullable=False)
    client_secret = db.Column(db.String(255), nullable=False)
    authorize_url = db.Column(db.String(500), nullable=False)
    token_url = db.Column(db.String(500), nullable=False)
    userinfo_url = db.Column(db.String(500), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())


# OAuth Account model
class OAuthAccount(db.Model):
    __tablename__ = 'oauth_account'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    provider_id = db.Column(
        db.Integer, db.ForeignKey('oauth_provider.id'), nullable=False
    )
    provider_user_id = db.Column(db.String(255), nullable=False)
    access_token = db.Column(db.Text)
    refresh_token = db.Column(db.Text)
    token_expires_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    user = db.relationship('User', backref='oauth_accounts')
    provider = db.relationship('OAuthProvider')

    __table_args__ = (
        db.UniqueConstraint('provider_id', 'provider_user_id'),
    )

# JWT token blocklist
@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(jwt_header, jwt_payload):
    try:
        jti = jwt_payload.get("jti")
        if not jti:
            return False
        token_in_redis = redis_client.get(jti)
        return token_in_redis is not None
    except Exception as e:
        print(f"Error checking token blocklist: {e}")
        return False

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
    redis_client.setex(jti, timedelta(hours=1), "true")
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


# OAuth Helper Functions
def get_oauth_provider_config(provider_name):
    """Get OAuth provider configuration from database"""
    provider = OAuthProvider.query.filter_by(
        name=provider_name, is_active=True
    ).first()
    if not provider:
        return None
    return {
        'client_id': provider.client_id,
        'client_secret': provider.client_secret,
        'authorize_url': provider.authorize_url,
        'token_url': provider.token_url,
        'userinfo_url': provider.userinfo_url
    }


def exchange_code_for_token(provider_name, code, redirect_uri):
    """Exchange authorization code for access token"""
    config = get_oauth_provider_config(provider_name)
    if not config:
        return None, "Provider not found or inactive"
    
    if provider_name == 'google':
        return _exchange_google_token(config, code, redirect_uri)
    elif provider_name == 'github':
        return _exchange_github_token(config, code, redirect_uri)
    else:
        return None, "Unsupported provider"


def _exchange_google_token(config, code, redirect_uri):
    """Exchange Google authorization code for token"""
    try:
        response = requests.post(config['token_url'], data={
            'client_id': config['client_id'],
            'client_secret': config['client_secret'],
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_uri
        })
        
        if response.status_code == 200:
            token_data = response.json()
            return token_data, None
        else:
            return None, f"Token exchange failed: {response.status_code}"
    except Exception as e:
        return None, f"Token exchange error: {str(e)}"


def _exchange_github_token(config, code, redirect_uri):
    """Exchange GitHub authorization code for token"""
    try:
        response = requests.post(config['token_url'], data={
            'client_id': config['client_id'],
            'client_secret': config['client_secret'],
            'code': code,
            'redirect_uri': redirect_uri
        }, headers={'Accept': 'application/json'})
        
        if response.status_code == 200:
            token_data = response.json()
            return token_data, None
        else:
            return None, f"Token exchange failed: {response.status_code}"
    except Exception as e:
        return None, f"Token exchange error: {str(e)}"


def get_user_info(provider_name, access_token):
    """Get user information from OAuth provider"""
    config = get_oauth_provider_config(provider_name)
    if not config:
        return None, "Provider not found or inactive"
    
    try:
        headers = {'Authorization': f'Bearer {access_token}'}
        if provider_name == 'github':
            headers['Accept'] = 'application/vnd.github.v3+json'
        
        response = requests.get(config['userinfo_url'], headers=headers)
        
        if response.status_code == 200:
            return response.json(), None
        else:
            return None, f"Failed to get user info: {response.status_code}"
    except Exception as e:
        return None, f"Error getting user info: {str(e)}"


# OAuth Routes
@app.route('/api/v1/auth/oauth/<provider>/authorize', methods=['GET'])
def oauth_authorize(provider):
    """Redirect user to OAuth provider for authorization"""
    config = get_oauth_provider_config(provider)
    if not config:
        return jsonify({'error': 'Provider not found or inactive'}), 404
    
    # Get redirect URI from query parameter
    redirect_uri = request.args.get('redirect_uri')
    if not redirect_uri:
        return jsonify({'error': 'Missing redirect_uri parameter'}), 400
    
    # Store redirect URI in session for later use
    session['oauth_redirect_uri'] = redirect_uri
    session['oauth_provider'] = provider
    
    # Build authorization URL
    auth_params = {
        'client_id': config['client_id'],
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': app.config['OAUTH_PROVIDERS'][provider]['scope']
    }
    
    if provider == 'github':
        auth_params['scope'] = 'read:user user:email'
    
    auth_url = f"{config['authorize_url']}?{'&'.join([f'{k}={v}' for k, v in auth_params.items()])}"
    
    return jsonify({'authorization_url': auth_url}), 200


@app.route('/api/v1/auth/oauth/<provider>/callback', methods=['GET'])
def oauth_callback(provider):
    """Handle OAuth callback from provider"""
    code = request.args.get('code')
    error = request.args.get('error')
    
    if error:
        return jsonify({'error': f'OAuth error: {error}'}), 400
    
    if not code:
        return jsonify({'error': 'Missing authorization code'}), 400
    
    # Get stored redirect URI from session
    redirect_uri = session.get('oauth_redirect_uri')
    if not redirect_uri:
        return jsonify({'error': 'Missing redirect URI'}), 400
    
    # Exchange code for token
    token_data, error_msg = exchange_code_for_token(provider, code, redirect_uri)
    if error_msg:
        return jsonify({'error': error_msg}), 400
    
    # Get user information from provider
    user_info, error_msg = get_user_info(provider, token_data['access_token'])
    if error_msg:
        return jsonify({'error': error_msg}), 400
    
    # Find or create user
    user = _find_or_create_oauth_user(provider, user_info, token_data)
    if not user:
        return jsonify({'error': 'Failed to create or find user'}), 500
    
    # Create JWT token
    access_token = create_access_token(identity=user.username)
    
    # Store OAuth account information
    _store_oauth_account(user.id, provider, user_info, token_data)
    
    # Clear session data
    session.pop('oauth_redirect_uri', None)
    session.pop('oauth_provider', None)
    
    return jsonify({
        'access_token': access_token,
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_admin': user.is_admin
        }
    }), 200


def _find_or_create_oauth_user(provider, user_info, token_data):
    """Find existing user or create new one from OAuth data"""
    # Try to find existing OAuth account
    oauth_account = OAuthAccount.query.filter_by(
        provider_id=OAuthProvider.query.filter_by(name=provider).first().id,
        provider_user_id=str(user_info.get('id', user_info.get('sub', '')))
    ).first()
    
    if oauth_account:
        return oauth_account.user
    
    # Try to find user by email
    email = user_info.get('email')
    if email:
        user = User.query.filter_by(email=email).first()
        if user:
            return user
    
    # Create new user
    username = _generate_unique_username(user_info)
    email = user_info.get('email', f"{username}@{provider}.oauth")
    
    new_user = User(
        username=username,
        email=email,
        password_hash=None,  # OAuth users don't have passwords
        is_admin=False,
        is_active=True
    )
    
    try:
        db.session.add(new_user)
        db.session.commit()
        return new_user
    except Exception as e:
        db.session.rollback()
        print(f"Error creating OAuth user: {e}")
        return None


def _generate_unique_username(user_info):
    """Generate unique username from OAuth user info"""
    base_username = user_info.get('login', user_info.get('name', 'user'))
    base_username = ''.join(c for c in base_username if c.isalnum() or c in '._-')
    
    counter = 1
    username = base_username
    while User.query.filter_by(username=username).first():
        username = f"{base_username}{counter}"
        counter += 1
    
    return username


def _store_oauth_account(user_id, provider, user_info, token_data):
    """Store OAuth account information"""
    provider_model = OAuthProvider.query.filter_by(name=provider).first()
    if not provider_model:
        return
    
    # Check if OAuth account already exists
    existing_account = OAuthAccount.query.filter_by(
        user_id=user_id,
        provider_id=provider_model.id
    ).first()
    
    if existing_account:
        # Update existing account
        existing_account.access_token = token_data.get('access_token')
        existing_account.refresh_token = token_data.get('refresh_token')
        existing_account.updated_at = db.func.current_timestamp()
    else:
        # Create new account
        new_account = OAuthAccount(
            user_id=user_id,
            provider_id=provider_model.id,
            provider_user_id=str(user_info.get('id', user_info.get('sub', ''))),
            access_token=token_data.get('access_token'),
            refresh_token=token_data.get('refresh_token')
        )
        db.session.add(new_account)
    
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error storing OAuth account: {e}")


@app.route('/api/v1/auth/oauth/providers', methods=['GET'])
def get_oauth_providers():
    """Get list of available OAuth providers"""
    providers = OAuthProvider.query.filter_by(is_active=True).all()
    return jsonify({
        'providers': [{
            'name': provider.name,
            'display_name': provider.name.title()
        } for provider in providers]
    }), 200


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


# Application entry point for Gunicorn
# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=5000, debug=True)

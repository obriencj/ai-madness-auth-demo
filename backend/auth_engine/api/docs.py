"""
API documentation using Flask-RESTX for OpenAPI/Swagger.
"""

from flask_restx import Api, Resource, fields, Namespace
from flask import current_app
from ..middleware.tenant import require_api_key, get_current_tenant

# Create API documentation
api = Api(
    title='Authentication Service API',
    version='1.0.0',
    description='Standalone authentication service for multiple applications',
    doc='/docs',
    authorizations={
        'apikey': {
            'type': 'apiKey',
            'in': 'header',
            'name': 'X-API-Key'
        },
        'bearer': {
            'type': 'apiKey',
            'in': 'header',
            'name': 'Authorization',
            'description': 'Bearer JWT token'
        }
    },
    security='apikey'
)

# Create namespaces
auth_ns = Namespace('auth', description='Authentication operations')
user_ns = Namespace('users', description='User management operations')
admin_ns = Namespace('admin', description='Admin operations')
oauth_ns = Namespace('oauth', description='OAuth operations')

# Add namespaces to API
api.add_namespace(auth_ns, path='/api/v1/auth')
api.add_namespace(user_ns, path='/api/v1/users')
api.add_namespace(admin_ns, path='/api/v1/admin')
api.add_namespace(oauth_ns, path='/api/v1/oauth')

# Define models for documentation
user_model = api.model('User', {
    'id': fields.Integer(required=True, description='User ID'),
    'username': fields.String(required=True, description='Username'),
    'email': fields.String(required=True, description='Email address'),
    'is_active': fields.Boolean(description='User active status'),
    'is_admin': fields.Boolean(description='Admin privileges'),
    'permissions': fields.List(fields.String, description='User permissions')
})

login_request = api.model('LoginRequest', {
    'username': fields.String(required=True, description='Username'),
    'password': fields.String(required=True, description='Password')
})

login_response = api.model('LoginResponse', {
    'access_token': fields.String(required=True, description='JWT access token'),
    'user': fields.Nested(user_model, description='User information')
})

register_request = api.model('RegisterRequest', {
    'username': fields.String(required=True, description='Username'),
    'email': fields.String(required=True, description='Email address'),
    'password': fields.String(required=True, description='Password')
})

register_response = api.model('RegisterResponse', {
    'message': fields.String(description='Success message'),
    'access_token': fields.String(description='JWT access token'),
    'user': fields.Nested(user_model, description='User information')
})

error_response = api.model('ErrorResponse', {
    'error': fields.String(required=True, description='Error message')
})

success_response = api.model('SuccessResponse', {
    'message': fields.String(required=True, description='Success message')
})

# Authentication endpoints documentation
@auth_ns.route('/login')
class LoginAPI(Resource):
    @auth_ns.doc('user_login')
    @auth_ns.expect(login_request)
    @auth_ns.response(200, 'Login successful', login_response)
    @auth_ns.response(401, 'Invalid credentials', error_response)
    @auth_ns.response(500, 'Server error', error_response)
    def post(self):
        """
        Authenticate user with username and password.
        
        Returns JWT access token and user information on successful authentication.
        """
        pass

@auth_ns.route('/logout')
class LogoutAPI(Resource):
    @auth_ns.doc('user_logout', security='bearer')
    @auth_ns.response(200, 'Logout successful', success_response)
    @auth_ns.response(401, 'Unauthorized', error_response)
    def post(self):
        """
        Logout user and invalidate JWT token.
        
        Requires valid JWT token in Authorization header.
        """
        pass

@auth_ns.route('/register')
class RegisterAPI(Resource):
    @auth_ns.doc('user_register')
    @auth_ns.expect(register_request)
    @auth_ns.response(201, 'Registration successful', register_response)
    @auth_ns.response(400, 'Invalid data', error_response)
    @auth_ns.response(409, 'User already exists', error_response)
    def post(self):
        """
        Register new user account.
        
        Creates new user account and returns JWT access token.
        """
        pass

@auth_ns.route('/me')
class MeAPI(Resource):
    @auth_ns.doc('get_current_user', security='bearer')
    @auth_ns.response(200, 'User information retrieved', user_model)
    @auth_ns.response(401, 'Unauthorized', error_response)
    @auth_ns.response(404, 'User not found', error_response)
    def get(self):
        """
        Get current user information.
        
        Requires valid JWT token in Authorization header.
        Returns current user's information.
        """
        pass

# User management endpoints documentation
@user_ns.route('/')
class UsersAPI(Resource):
    @user_ns.doc('list_users', security=['apikey', 'bearer'])
    @user_ns.response(200, 'Users list retrieved', fields.List(fields.Nested(user_model)))
    @user_ns.response(401, 'Unauthorized', error_response)
    @user_ns.response(403, 'Forbidden', error_response)
    def get(self):
        """
        List all users (Admin only).
        
        Requires admin privileges and valid authentication.
        """
        pass

@user_ns.route('/<int:user_id>')
class UserAPI(Resource):
    @user_ns.doc('get_user', security=['apikey', 'bearer'])
    @user_ns.response(200, 'User retrieved', user_model)
    @user_ns.response(401, 'Unauthorized', error_response)
    @user_ns.response(404, 'User not found', error_response)
    def get(self, user_id):
        """
        Get user by ID.
        
        Requires valid authentication.
        """
        pass

    @user_ns.doc('update_user', security=['apikey', 'bearer'])
    @user_ns.expect(user_model)
    @user_ns.response(200, 'User updated', user_model)
    @user_ns.response(401, 'Unauthorized', error_response)
    @user_ns.response(404, 'User not found', error_response)
    def put(self, user_id):
        """
        Update user information (Admin only).
        
        Requires admin privileges and valid authentication.
        """
        pass

# OAuth endpoints documentation
@oauth_ns.route('/providers')
class OAuthProvidersAPI(Resource):
    @oauth_ns.doc('list_oauth_providers')
    @oauth_ns.response(200, 'OAuth providers list retrieved')
    def get(self):
        """
        List available OAuth providers.
        
        Returns list of configured OAuth providers.
        """
        pass

@oauth_ns.route('/<provider>/authorize')
class OAuthAuthorizeAPI(Resource):
    @oauth_ns.doc('oauth_authorize')
    @oauth_ns.response(302, 'Redirect to OAuth provider')
    def get(self, provider):
        """
        Initiate OAuth authorization.
        
        Redirects user to OAuth provider for authorization.
        """
        pass

@oauth_ns.route('/<provider>/callback')
class OAuthCallbackAPI(Resource):
    @oauth_ns.doc('oauth_callback')
    @oauth_ns.response(200, 'OAuth successful', login_response)
    @oauth_ns.response(400, 'OAuth failed', error_response)
    def get(self, provider):
        """
        Handle OAuth callback.
        
        Processes OAuth provider callback and authenticates user.
        """
        pass

# Admin endpoints documentation
@admin_ns.route('/stats')
class AdminStatsAPI(Resource):
    @admin_ns.doc('admin_stats', security=['apikey', 'bearer'])
    @admin_ns.response(200, 'Statistics retrieved')
    @admin_ns.response(401, 'Unauthorized', error_response)
    @admin_ns.response(403, 'Forbidden', error_response)
    def get(self):
        """
        Get system statistics (Admin only).
        
        Requires admin privileges and valid authentication.
        """
        pass

@admin_ns.route('/sessions')
class AdminSessionsAPI(Resource):
    @admin_ns.doc('admin_sessions', security=['apikey', 'bearer'])
    @admin_ns.response(200, 'Sessions list retrieved')
    @admin_ns.response(401, 'Unauthorized', error_response)
    @admin_ns.response(403, 'Forbidden', error_response)
    def get(self):
        """
        List active sessions (Admin only).
        
        Requires admin privileges and valid authentication.
        """
        pass

# Health check endpoint
@api.route('/health')
class HealthAPI(Resource):
    @api.doc('health_check')
    @api.response(200, 'Service healthy')
    def get(self):
        """
        Health check endpoint.
        
        Returns service health status.
        """
        return {'status': 'healthy', 'service': 'auth-service'}

# The end.

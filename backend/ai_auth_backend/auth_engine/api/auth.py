"""
Core authentication API blueprint.
"""

from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import get_jwt_identity, get_jwt

from ..middleware import auth_required
from ..exceptions import AuthError


def create_auth_blueprint(auth_service):
    """Create authentication blueprint."""
    auth_bp = Blueprint('auth', __name__)
    
    @auth_bp.route('/login', methods=['POST'])
    def login():
        """Authenticate user with password."""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            result = auth_service.authenticate_with_password(
                data.get('username'), 
                data.get('password')
            )
            return jsonify(result), 200
        except AuthError as e:
            return jsonify({'error': str(e)}), 401
        except Exception as e:
            return jsonify({'error': 'Login failed'}), 500
    
    @auth_bp.route('/logout', methods=['POST'])
    @auth_required
    def logout():
        """Logout user."""
        try:
            jti = get_jwt()["jti"]
            auth_service.logout(jti)
            return jsonify({'message': 'Successfully logged out'}), 200
        except Exception as e:
            return jsonify({'error': 'Logout failed'}), 500
    
    @auth_bp.route('/register', methods=['POST'])
    def register():
        """Register new user."""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            # Validate required fields
            required_fields = ['username', 'email', 'password']
            for field in required_fields:
                if not data.get(field):
                    return jsonify({'error': f'Missing {field}'}), 400
            
            # Create user
            user = auth_service.user_service.create_user({
                'username': data['username'],
                'email': data['email'],
                'is_active': True
            })
            user.set_password(data['password'])
            
            # Authenticate the new user
            result = auth_service.authenticate_with_password(
                data['username'], 
                data['password']
            )
            
            return jsonify({
                'message': 'User registered successfully',
                **result
            }), 201
        except AuthError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            return jsonify({'error': 'Registration failed'}), 500
    
    @auth_bp.route('/me', methods=['GET'])
    @auth_required
    def get_current_user():
        """Get current user information."""
        try:
            username = get_jwt_identity()
            user = auth_service.user_service.get_user_by_username(username)
            
            if not user:
                return jsonify({'error': 'User not found'}), 404
            
            return jsonify({
                'user': auth_service.user_service.serialize_user(user)
            }), 200
        except Exception as e:
            return jsonify({'error': 'Failed to get user info'}), 500
    
    return auth_bp


# The end.

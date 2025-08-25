"""
Admin API blueprint.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import get_jwt_identity

from ..middleware import auth_required, permission_required


def create_admin_blueprint(services):
    """Create admin blueprint."""
    admin_bp = Blueprint('admin', __name__)
    
    @admin_bp.route('/users', methods=['GET'])
    @permission_required('admin')
    def get_users():
        """Get all users (admin only)."""
        try:
            user_service = services['user']
            users = user_service.get_all_users()
            
            return jsonify({
                'users': [user_service.serialize_user(user) for user in users]
            }), 200
        except Exception:
            return jsonify({'error': 'Failed to get users'}), 500
    
    @admin_bp.route('/users', methods=['POST'])
    @permission_required('admin')
    def create_user():
        """Create new user (admin only)."""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            # Validate required fields
            required_fields = ['username', 'email', 'password']
            for field in required_fields:
                if not data.get(field):
                    return jsonify({'error': f'Missing {field}'}), 400
            
            user_service = services['user']
            user = user_service.create_user({
                'username': data['username'],
                'email': data['email'],
                'is_active': data.get('is_active', True)
            })
            user.set_password(data['password'])
            
            return jsonify({
                'message': 'User created successfully',
                'user': user_service.serialize_user(user)
            }), 201
        except Exception:
            return jsonify({'error': 'Failed to create user'}), 500
    
    @admin_bp.route('/users/<int:user_id>', methods=['PUT'])
    @permission_required('admin')
    def update_user(user_id):
        """Update user (admin only)."""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            user_service = services['user']
            user = user_service.update_user(user_id, data)
            
            return jsonify({
                'message': 'User updated successfully',
                'user': user_service.serialize_user(user)
            }), 200
        except Exception:
            return jsonify({'error': 'Failed to update user'}), 500
    
    @admin_bp.route('/sessions', methods=['GET'])
    @permission_required('admin')
    def get_sessions():
        """Get active sessions (admin only)."""
        try:
            session_service = services['session']
            sessions = session_service.get_active_sessions()
            
            return jsonify({
                'sessions': [
                    {
                        'id': session.id,
                        'user_id': session.user_id,
                        'auth_method': session.auth_method,
                        'ip_address': session.ip_address,
                        'created_at': session.created_at.isoformat(),
                        'expires_at': session.expires_at.isoformat()
                    }
                    for session in sessions
                ]
            }), 200
        except Exception:
            return jsonify({'error': 'Failed to get sessions'}), 500
    
    return admin_bp


# The end.

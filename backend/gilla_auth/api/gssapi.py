"""
GSSAPI/Kerberos authentication for the Auth Demo application.

This module handles GSSAPI authentication flow, including:
- Realm configuration retrieval
- GSSAPI authentication initiation
- User authentication via Kerberos
- User creation and linking
- GSSAPI account management

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

import os
import base64
import tempfile
from flask import jsonify, request, Blueprint
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from .model import db, User, GSSAPIRealm, GSSAPIAccount
from .crypto import KeytabEncryption
from .keytab_cache import get_keytab_cache
from .utils import generate_unique_username

try:
    import gssapi
    GSSAPI_AVAILABLE = True
except ImportError:
    GSSAPI_AVAILABLE = False


def validate_gssapi_realm_config(realm_config):
    """Validate GSSAPI realm configuration including keytab and service principal"""
    if not GSSAPI_AVAILABLE:
        return False, "GSSAPI library not available"
    
    try:
        # Get decrypted keytab data from cache or decrypt from database
        cache = get_keytab_cache()
        keytab_data = cache.get_keytab(
            realm_config['id'],
            realm_config['encrypted_keytab'],
            realm_config['keytab_encryption_iv'],
            realm_config['keytab_encryption_salt']
        )
        
        if not keytab_data:
            return False, "Failed to decrypt keytab data"
        
        # Create temporary keytab file for GSSAPI validation
        with tempfile.NamedTemporaryFile(delete=False) as temp_keytab:
            temp_keytab.write(keytab_data)
            temp_keytab_path = temp_keytab.name
        
        try:
            # Try to create a GSSAPI name from the service principal
            service_name = gssapi.Name(realm_config['service_principal'], name_type=gssapi.NameType.kerberos_principal)
            
            # Try to acquire credentials from the temporary keytab
            creds = gssapi.Credentials(name=service_name, usage='accept', store={'keytab': temp_keytab_path})
            
            if not creds:
                return False, f"Failed to acquire credentials from keytab for {realm_config['service_principal']}"
            
            return True, "Configuration validated successfully"
            
        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_keytab_path)
            except OSError:
                pass  # File might already be deleted
                
    except Exception as e:
        return False, f"GSSAPI configuration validation failed: {str(e)}"


def create_temp_keytab_file(realm_config):
    """Create a temporary keytab file for GSSAPI operations."""
    cache = get_keytab_cache()
    keytab_data = cache.get_keytab(
        realm_config['id'],
        realm_config['encrypted_keytab'],
        realm_config['keytab_encryption_iv'],
        realm_config['keytab_encryption_salt']
    )
    
    if not keytab_data:
        raise ValueError("Failed to decrypt keytab data")
    
    # Create temporary file
    temp_keytab = tempfile.NamedTemporaryFile(delete=False)
    temp_keytab.write(keytab_data)
    temp_keytab.close()
    
    return temp_keytab.name


def get_gssapi_realm_config(realm_name=None):
    """Get GSSAPI realm configuration from database"""
    print(f"GSSAPI Realm Config: Looking for realm: {realm_name}")
    
    if realm_name:
        realm = GSSAPIRealm.query.filter_by(
            name=realm_name, is_active=True
        ).first()
        print(f"GSSAPI Realm Config: Found realm by name '{realm_name}': {realm.name if realm else 'None'}")
    else:
        # Get default realm
        realm = GSSAPIRealm.query.filter_by(
            default_realm=True, is_active=True
        ).first()
        print(f"GSSAPI Realm Config: Found default realm: {realm.name if realm else 'None'}")
    
    if not realm:
        print(f"GSSAPI Realm Config: No realm found")
        return None
    
    print(f"GSSAPI Realm Config: Returning realm: {realm.name} (ID: {realm.id})")
    return {
        'id': realm.id,
        'name': realm.name,
        'realm': realm.realm,
        'kdc_hosts': realm.kdc_hosts,
        'admin_server': realm.admin_server,
        'service_principal': realm.service_principal,
        'encrypted_keytab': realm.encrypted_keytab,
        'keytab_encryption_iv': realm.keytab_encryption_iv,
        'keytab_encryption_salt': realm.keytab_encryption_salt
    }


def authenticate_gssapi_user(principal_name, realm_name=None):
    """Authenticate user via GSSAPI/Kerberos"""
    try:
        print(f"GSSAPI Auth User: Starting authentication for principal: {principal_name}, realm: {realm_name}")
        
        # Get realm configuration
        realm_config = get_gssapi_realm_config(realm_name)
        if not realm_config:
            print(f"GSSAPI Auth User: No realm config found for realm: {realm_name}")
            return None, "GSSAPI realm not found or inactive"

        print(f"GSSAPI Auth User: Found realm config: {realm_config['name']} (ID: {realm_config['id']})")

        # Find existing GSSAPI account
        gssapi_account = GSSAPIAccount.query.filter_by(
            realm_id=realm_config['id'],
            principal_name=principal_name
        ).first()

        if gssapi_account:
            print(f"GSSAPI Auth User: Found existing GSSAPI account for user: {gssapi_account.user.username}")
            return gssapi_account.user, None

        print(f"GSSAPI Auth User: No existing GSSAPI account found")

        # Try to find user by extracting username from principal
        username = principal_name.split('@')[0] if '@' in principal_name else principal_name
        user = User.query.filter_by(username=username).first()
        
        if user:
            print(f"GSSAPI Auth User: Found existing user: {user.username}, linking GSSAPI account")
            # Link existing user to GSSAPI account
            _link_gssapi_account(user.id, realm_config['id'], principal_name)
            return user, None

        print(f"GSSAPI Auth User: No existing user found, creating new user")
        # Create new user from GSSAPI principal
        user = _create_gssapi_user(principal_name, realm_config['id'])
        return user, None

    except Exception as e:
        print(f"GSSAPI Auth User: Exception: {e}")
        return None, f"GSSAPI authentication error: {str(e)}"


def _create_gssapi_user(principal_name, realm_id):
    """Create new user from GSSAPI principal"""
    # Extract username and email from principal
    username = principal_name.split('@')[0] if '@' in principal_name else principal_name
    email = f"{username}@gssapi.local"  # Placeholder email for GSSAPI users
    
    # Generate unique username if needed
    username = generate_unique_username(username)
    
    new_user = User(
        username=username,
        email=email,
        password_hash=None,  # GSSAPI users don't have passwords
        is_admin=False,
        is_active=True
    )

    try:
        db.session.add(new_user)
        db.session.commit()
        
        # Link GSSAPI account
        _link_gssapi_account(new_user.id, realm_id, principal_name)
        
        return new_user
    except Exception as e:
        db.session.rollback()
        print(f"Error creating GSSAPI user: {e}")
        return None


def _link_gssapi_account(user_id, realm_id, principal_name):
    """Link GSSAPI account to user"""
    # Check if account already exists
    existing_account = GSSAPIAccount.query.filter_by(
        user_id=user_id,
        realm_id=realm_id
    ).first()

    if existing_account:
        # Update existing account
        existing_account.principal_name = principal_name
        existing_account.updated_at = db.func.current_timestamp()
    else:
        # Create new account
        new_account = GSSAPIAccount(
            user_id=user_id,
            realm_id=realm_id,
            principal_name=principal_name
        )
        db.session.add(new_account)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error linking GSSAPI account: {e}")
        return None


def validate_gssapi_token(gssapi_token, realm_name=None):
    """Validate GSSAPI token and extract principal name"""
    if not GSSAPI_AVAILABLE:
        return None, "GSSAPI library not available"
    
    try:
        # Get realm configuration
        realm_config = get_gssapi_realm_config(realm_name)
        if not realm_config:
            return None, "GSSAPI realm not found or inactive"

        print(f"GSSAPI Token Validation: Using realm: {realm_config['name']}")

        # Create temporary keytab file for GSSAPI operations
        temp_keytab_path = create_temp_keytab_file(realm_config)
        
        try:
            # Decode the GSSAPI token (assuming it's base64 encoded)
            try:
                token_data = base64.b64decode(gssapi_token)
            except Exception:
                return None, "Invalid GSSAPI token format (not base64 encoded)"

            # Create GSSAPI acceptor credentials from keytab
            service_name = gssapi.Name(
                realm_config['service_principal'], 
                name_type=gssapi.NameType.kerberos_principal
            )
            
            acceptor_creds = gssapi.Credentials(
                name=service_name, 
                usage='accept', 
                store={'keytab': temp_keytab_path}
            )
            
            if not acceptor_creds:
                return None, f"Failed to acquire acceptor credentials from keytab for {realm_config['service_principal']}"

            # Create GSSAPI security context
            ctx = gssapi.SecurityContext(
                creds=acceptor_creds,
                usage='accept'
            )

            # Process the GSSAPI token
            try:
                # Accept the security context using the client's token
                ctx.step(token_data)
                
                if not ctx.complete:
                    return None, "GSSAPI security context negotiation incomplete"
                
                # Extract the client's principal name
                client_name = ctx.initiator_name
                if not client_name:
                    return None, "Could not extract client principal from GSSAPI context"
                
                # Convert to string format
                principal_name = str(client_name)
                print(f"GSSAPI Token Validation: Successfully validated token for principal: {principal_name}")
                
                return principal_name, None
                
            except gssapi.exceptions.GSSError as e:
                return None, f"GSSAPI token validation failed: {str(e)}"
                
        finally:
            # Clean up temporary keytab file
            try:
                os.unlink(temp_keytab_path)
            except OSError:
                pass  # File might already be deleted
                
    except Exception as e:
        print(f"GSSAPI Token Validation: Exception: {e}")
        return None, f"GSSAPI token validation error: {str(e)}"








def get_gssapi_realms_list():
    """Get list of available GSSAPI realms"""
    realms = GSSAPIRealm.query.filter_by(is_active=True).all()
    return jsonify({
        'realms': [{
            'id': realm.id,
            'name': realm.name,
            'realm': realm.realm,
            'kdc_hosts': realm.kdc_hosts,
            'admin_server': realm.admin_server,
            'service_principal': realm.service_principal,
            'has_keytab': bool(realm.encrypted_keytab),  # Don't expose encrypted data
            'default_realm': realm.default_realm,
            'is_active': realm.is_active,
            'created_at': realm.created_at.isoformat() if realm.created_at else None
        } for realm in realms]
    }), 200


# GSSAPI Blueprint
gssapi_bp = Blueprint('gssapi', __name__, url_prefix='/api/v1/auth/gssapi')


@gssapi_bp.route('/authenticate', methods=['POST'])
def gssapi_authenticate():
    """Handle GSSAPI authentication request from frontend or API clients"""
    try:
        data = request.get_json()
        print(f"Backend GSSAPI Auth: Received data: {data}")
        
        if not data or not data.get('gssapi_token'):
            return jsonify({'error': 'Missing gssapi_token parameter'}), 400

        gssapi_token = data['gssapi_token']
        realm_name = data.get('realm_name')  # Optional, will use default if not specified

        print(f"Backend GSSAPI Auth: Authenticating with GSSAPI token, realm: {realm_name}")

        # Validate GSSAPI token and extract principal
        principal_name, error_msg = validate_gssapi_token(gssapi_token, realm_name)
        if error_msg:
            print(f"Backend GSSAPI Auth: GSSAPI token validation failed: {error_msg}")
            return jsonify({'error': error_msg}), 400

        if not principal_name:
            print(f"Backend GSSAPI Auth: No principal extracted from GSSAPI token")
            return jsonify({'error': 'Failed to extract principal from GSSAPI token'}), 500

        print(f"Backend GSSAPI Auth: Principal extracted: {principal_name}")

        # Authenticate user based on verified principal
        user, error_msg = authenticate_gssapi_user(principal_name, realm_name)
        if error_msg:
            print(f"Backend GSSAPI Auth: User authentication failed: {error_msg}")
            return jsonify({'error': error_msg}), 400

        if not user:
            print(f"Backend GSSAPI Auth: No user returned from authentication")
            return jsonify({'error': 'Failed to authenticate user'}), 500

        print(f"Backend GSSAPI Auth: User authenticated: {user.username} (ID: {user.id})")

        # Create JWT token
        access_token = create_access_token(identity=user.username)
        
        # Get JTI from the token and create session record
        from flask_jwt_extended import decode_token
        token_data_jwt = decode_token(access_token)
        jti = token_data_jwt['jti']
        
        # Create session record
        from .jwt import create_jwt_session
        create_jwt_session(jti, user.id, 'gssapi')

        print(f"Backend GSSAPI Auth: JWT token created and session recorded")

        return jsonify({
            'access_token': access_token,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_admin': user.is_admin
            }
        }), 200

    except Exception as e:
        print(f"Backend GSSAPI Auth: Exception: {e}")
        return jsonify({'error': f'GSSAPI authentication error: {str(e)}'}), 500


@gssapi_bp.route('/negotiate', methods=['GET', 'POST'])
def gssapi_negotiate():
    """Handle direct GSSAPI negotiation for CLI clients"""
    try:
        # Check for Authorization header with Negotiate scheme
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Negotiate '):
            # Return 401 with WWW-Authenticate header to initiate negotiation
            return jsonify({'error': 'GSSAPI negotiation required'}), 401, {'WWW-Authenticate': 'Negotiate'}
            
        # Extract the GSSAPI token from the Authorization header
        gssapi_token = auth_header[10:]  # Remove 'Negotiate ' prefix
        
        print(f"Backend GSSAPI Negotiate: Received token from Authorization header")
        
        # Validate GSSAPI token and extract principal
        principal_name, error_msg = validate_gssapi_token(gssapi_token)
        if error_msg:
            print(f"Backend GSSAPI Negotiate: GSSAPI token validation failed: {error_msg}")
            return jsonify({'error': error_msg}), 401, {'WWW-Authenticate': 'Negotiate'}

        if not principal_name:
            print(f"Backend GSSAPI Negotiate: No principal extracted from GSSAPI token")
            return jsonify({'error': 'Failed to extract principal from GSSAPI token'}), 401, {'WWW-Authenticate': 'Negotiate'}

        print(f"Backend GSSAPI Negotiate: Principal extracted: {principal_name}")

        # Authenticate user based on verified principal
        user, error_msg = authenticate_gssapi_user(principal_name)
        if error_msg:
            print(f"Backend GSSAPI Negotiate: User authentication failed: {error_msg}")
            return jsonify({'error': error_msg}), 401, {'WWW-Authenticate': 'Negotiate'}

        if not user:
            print(f"Backend GSSAPI Negotiate: No user returned from authentication")
            return jsonify({'error': 'Failed to authenticate user'}), 401, {'WWW-Authenticate': 'Negotiate'}

        print(f"Backend GSSAPI Negotiate: User authenticated: {user.username} (ID: {user.id})")

        # Create JWT token
        access_token = create_access_token(identity=user.username)
        
        # Get JTI from the token and create session record
        from flask_jwt_extended import decode_token
        token_data_jwt = decode_token(access_token)
        jti = token_data_jwt['jti']
        
        # Create session record
        from .jwt import create_jwt_session
        create_jwt_session(jti, user.id, 'gssapi_negotiate')

        print(f"Backend GSSAPI Negotiate: JWT token created and session recorded")

        return jsonify({
            'access_token': access_token,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_admin': user.is_admin
            }
        }), 200

    except Exception as e:
        print(f"Backend GSSAPI Negotiate: Exception: {e}")
        return jsonify({'error': f'GSSAPI negotiation error: {str(e)}'}), 500, {'WWW-Authenticate': 'Negotiate'}


@gssapi_bp.route('/realms', methods=['GET'])
def get_gssapi_realms():
    """Get list of available GSSAPI realms"""
    print(f"GSSAPI Realms: Listing all realms")
    realms = GSSAPIRealm.query.all()
    print(f"GSSAPI Realms: Found {len(realms)} total realms")
    for realm in realms:
        print(f"GSSAPI Realms: - {realm.name} (active: {realm.is_active}, default: {realm.default_realm})")
    return get_gssapi_realms_list()


@gssapi_bp.route('/realms', methods=['POST'])
@jwt_required()
def create_gssapi_realm():
    """Create new GSSAPI realm (admin only)"""
    try:
        current_username = get_jwt_identity()
        current_user = User.query.filter_by(username=current_username).first()

        if not current_user or not current_user.is_admin:
            return jsonify({'error': 'Admin privileges required'}), 403

        data = request.get_json()
        if not data or not data.get('name') or not data.get('realm') or not data.get('kdc_hosts') or not data.get('service_principal') or not data.get('keytab_data'):
            return jsonify({'error': 'Missing required fields: name, realm, kdc_hosts, service_principal, keytab_data'}), 400

        # Check if realm already exists
        if GSSAPIRealm.query.filter_by(name=data['name']).first():
            return jsonify({'error': 'Realm name already exists'}), 400

        # Decode and validate keytab data
        try:
            keytab_data = base64.b64decode(data['keytab_data'])
        except Exception:
            return jsonify({'error': 'Invalid keytab_data format. Must be base64 encoded.'}), 400
        
        
        # Encrypt the keytab
        crypto = KeytabEncryption()
        
        # Validate keytab format
        is_valid_format, format_msg = crypto.validate_keytab_format(keytab_data)
        if not is_valid_format:
            return jsonify({'error': f'Keytab validation failed: {format_msg}'}), 400

        encrypted_result = crypto.encrypt_keytab(keytab_data)
        
        new_realm = GSSAPIRealm(
            name=data['name'],
            realm=data['realm'],
            kdc_hosts=data['kdc_hosts'],
            admin_server=data.get('admin_server'),
            service_principal=data['service_principal'],
            encrypted_keytab=encrypted_result['encrypted_data'],
            keytab_encryption_iv=encrypted_result['iv'],
            keytab_encryption_salt=encrypted_result['salt'],
            default_realm=data.get('default_realm', False),
            is_active=data.get('is_active', True)
        )

        # Validate the GSSAPI configuration before saving
        realm_config = {
            'id': 0,  # Temporary ID for validation
            'service_principal': new_realm.service_principal,
            'encrypted_keytab': new_realm.encrypted_keytab,
            'keytab_encryption_iv': new_realm.keytab_encryption_iv,
            'keytab_encryption_salt': new_realm.keytab_encryption_salt
        }
        
        is_valid, validation_msg = validate_gssapi_realm_config(realm_config)
        if not is_valid:
            return jsonify({'error': f'GSSAPI configuration validation failed: {validation_msg}'}), 400

        # If this is set as default, unset other defaults
        if new_realm.default_realm:
            GSSAPIRealm.query.filter_by(default_realm=True).update({'default_realm': False})

        db.session.add(new_realm)
        db.session.commit()

        return jsonify({
            'message': 'GSSAPI realm created successfully',
            'realm': {
                'id': new_realm.id,
                'name': new_realm.name,
                'realm': new_realm.realm,
                'kdc_hosts': new_realm.kdc_hosts,
                'admin_server': new_realm.admin_server,
                'service_principal': new_realm.service_principal,
                'has_keytab': True,
                'default_realm': new_realm.default_realm,
                'is_active': new_realm.is_active
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error creating GSSAPI realm: {str(e)}'}), 500


@gssapi_bp.route('/realms/<int:realm_id>', methods=['PUT'])
@jwt_required()
def update_gssapi_realm(realm_id):
    """Update GSSAPI realm (admin only)"""
    try:
        current_username = get_jwt_identity()
        current_user = User.query.filter_by(username=current_username).first()

        if not current_user or not current_user.is_admin:
            return jsonify({'error': 'Admin privileges required'}), 403

        realm = GSSAPIRealm.query.get(realm_id)
        if not realm:
            return jsonify({'error': 'GSSAPI realm not found'}), 404

        data = request.get_json()

        if 'name' in data:
            # Check if new name conflicts with existing realm
            existing_realm = GSSAPIRealm.query.filter_by(name=data['name']).first()
            if existing_realm and existing_realm.id != realm_id:
                return jsonify({'error': 'Realm name already exists'}), 400
            realm.name = data['name']

        if 'realm' in data:
            realm.realm = data['realm']

        if 'kdc_hosts' in data:
            realm.kdc_hosts = data['kdc_hosts']

        if 'admin_server' in data:
            realm.admin_server = data['admin_server']

        if 'service_principal' in data:
            realm.service_principal = data['service_principal']

        if 'keytab_data' in data:
            # Decode and validate new keytab data
            try:
                keytab_data = base64.b64decode(data['keytab_data'])
            except Exception:
                return jsonify({'error': 'Invalid keytab_data format. Must be base64 encoded.'}), 400
            
            # Validate keytab format
            crypto = KeytabEncryption()
            is_valid_format, format_msg = crypto.validate_keytab_format(keytab_data)
            if not is_valid_format:
                return jsonify({'error': f'Keytab validation failed: {format_msg}'}), 400
            
            # Encrypt the new keytab
            encrypted_result = crypto.encrypt_keytab(keytab_data)
            
            realm.encrypted_keytab = encrypted_result['encrypted_data']
            realm.keytab_encryption_iv = encrypted_result['iv']
            realm.keytab_encryption_salt = encrypted_result['salt']
            
            # Invalidate cache for this realm
            cache = get_keytab_cache()
            cache.invalidate_realm(realm.id)

        if 'default_realm' in data:
            # If setting as default, unset other defaults
            if data['default_realm']:
                GSSAPIRealm.query.filter_by(default_realm=True).update({'default_realm': False})
            realm.default_realm = data['default_realm']

        if 'is_active' in data:
            realm.is_active = data['is_active']

        # Validate the updated GSSAPI configuration
        realm_config = {
            'id': realm.id,
            'service_principal': realm.service_principal,
            'encrypted_keytab': realm.encrypted_keytab,
            'keytab_encryption_iv': realm.keytab_encryption_iv,
            'keytab_encryption_salt': realm.keytab_encryption_salt
        }
        
        is_valid, validation_msg = validate_gssapi_realm_config(realm_config)
        if not is_valid:
            return jsonify({'error': f'GSSAPI configuration validation failed: {validation_msg}'}), 400

        realm.updated_at = db.func.current_timestamp()
        db.session.commit()

        return jsonify({
            'message': 'GSSAPI realm updated successfully',
            'realm': {
                'id': realm.id,
                'name': realm.name,
                'realm': realm.realm,
                'kdc_hosts': realm.kdc_hosts,
                'admin_server': realm.admin_server,
                'service_principal': realm.service_principal,
                'has_keytab': bool(realm.encrypted_keytab),
                'default_realm': realm.default_realm,
                'is_active': realm.is_active
            }
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error updating GSSAPI realm: {str(e)}'}), 500


@gssapi_bp.route('/realms/<int:realm_id>', methods=['DELETE'])
@jwt_required()
def delete_gssapi_realm(realm_id):
    """Delete GSSAPI realm (admin only)"""
    try:
        current_username = get_jwt_identity()
        current_user = User.query.filter_by(username=current_username).first()

        if not current_user or not current_user.is_admin:
            return jsonify({'error': 'Admin privileges required'}), 403

        realm = GSSAPIRealm.query.get(realm_id)
        if not realm:
            return jsonify({'error': 'GSSAPI realm not found'}), 404

        # Check if realm has linked accounts
        if GSSAPIAccount.query.filter_by(realm_id=realm_id).first():
            return jsonify({'error': 'Cannot delete realm with linked accounts'}), 400

        # Invalidate cache before deletion
        cache = get_keytab_cache()
        cache.invalidate_realm(realm.id)
        
        db.session.delete(realm)
        db.session.commit()

        return jsonify({'message': 'GSSAPI realm deleted successfully'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error deleting GSSAPI realm: {str(e)}'}), 500


@gssapi_bp.route('/accounts', methods=['GET'])
@jwt_required()
def get_gssapi_accounts():
    """Get GSSAPI accounts for current user"""
    try:
        current_username = get_jwt_identity()
        current_user = User.query.filter_by(username=current_username).first()

        if not current_user:
            return jsonify({'error': 'User not found'}), 404

        accounts = GSSAPIAccount.query.filter_by(user_id=current_user.id).all()
        
        return jsonify({
            'accounts': [{
                'id': account.id,
                'principal_name': account.principal_name,
                'service_principal': account.service_principal,
                'realm': {
                    'id': account.realm.id,
                    'name': account.realm.name,
                    'realm': account.realm.realm
                },
                'created_at': account.created_at.isoformat() if account.created_at else None
            } for account in accounts]
        }), 200

    except Exception as e:
        return jsonify({'error': f'Error retrieving GSSAPI accounts: {str(e)}'}), 500


@gssapi_bp.route('/cache/stats', methods=['GET'])
@jwt_required()
def get_cache_stats():
    """Get keytab cache statistics (admin only)"""
    try:
        current_username = get_jwt_identity()
        current_user = User.query.filter_by(username=current_username).first()

        if not current_user or not current_user.is_admin:
            return jsonify({'error': 'Admin privileges required'}), 403

        cache = get_keytab_cache()
        stats = cache.get_cache_stats()
        
        return jsonify({
            'cache_stats': stats
        }), 200

    except Exception as e:
        return jsonify({'error': f'Error retrieving cache stats: {str(e)}'}), 500


@gssapi_bp.route('/cache/clear', methods=['POST'])
@jwt_required()
def clear_cache():
    """Clear all keytab caches (admin only)"""
    try:
        current_username = get_jwt_identity()
        current_user = User.query.filter_by(username=current_username).first()

        if not current_user or not current_user.is_admin:
            return jsonify({'error': 'Admin privileges required'}), 403

        cache = get_keytab_cache()
        cache.clear_all()
        
        return jsonify({
            'message': 'All keytab caches cleared successfully'
        }), 200

    except Exception as e:
        return jsonify({'error': f'Error clearing cache: {str(e)}'}), 500


# The end.

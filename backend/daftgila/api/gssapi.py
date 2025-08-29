"""
GSSAPI/Kerberos authentication for the Auth Demo application.

This module handles GSSAPI authentication, including:
- GSSAPI token negotiation
- Principal extraction and validation
- User creation and linking
- GSSAPI account management

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

import os
import base64
import gssapi
from flask import request, Blueprint
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from .model import db, User, GSSAPIRealm, GSSAPIAccount
from .jwt import create_jwt_session
from .utils import success_response, error_response, format_user_response, generate_unique_username
from .audit import log_gssapi_action, AuditActions

# Create GSSAPI blueprint
gssapi_bp = Blueprint('gssapi', __name__, url_prefix='/api/v1/auth/gssapi')

# GSSAPI configuration
GSSAPI_SERVICE_NAME = os.getenv('GSSAPI_SERVICE_NAME', 'HTTP')
GSSAPI_KEYTAB_PATH = os.getenv('GSSAPI_KEYTAB_PATH', '/etc/krb5.keytab')


def _extract_principal_from_token(gssapi_token):
    """Extract principal name from GSSAPI token."""
    try:
        # Decode base64 token
        token_bytes = base64.b64decode(gssapi_token)
        
        # Create GSSAPI name from token
        server_name = gssapi.Name(GSSAPI_SERVICE_NAME, name_type=gssapi.NameType.service)
        server_creds = gssapi.Credentials(name=server_name, usage='accept')
        
        # Accept the security context
        ctx = gssapi.SecurityContext(creds=server_creds, usage='accept')
        ctx.step(token_bytes)
        
        if ctx.complete:
            # Extract the client principal
            client_name = ctx.initiator_name
            return str(client_name), None
        else:
            return None, "GSSAPI context not complete"
    except Exception as e:
        return None, f"Failed to extract principal: {str(e)}"


def _find_or_create_gssapi_user(principal_name, realm_name):
    """Find existing user or create new one from GSSAPI principal."""
    # Try to find user by GSSAPI account first
    realm = GSSAPIRealm.query.filter_by(name=realm_name, is_active=True).first()
    if realm:
        gssapi_account = GSSAPIAccount.query.filter_by(
            principal_name=principal_name,
            realm_id=realm.id
        ).first()
        if gssapi_account:
            return gssapi_account.user
    
    # Try to find user by email (if principal contains email)
    if '@' in principal_name:
        email = principal_name
        user = User.query.filter_by(email=email).first()
        if user:
            return user
    
    # Create new user
    username = principal_name.split('@')[0] if '@' in principal_name else principal_name
    if not username:
        username = generate_unique_username()
    
    # Ensure username is unique
    while User.query.filter_by(username=username).first():
        username = generate_unique_username()
    
    # Create user with email if available
    email = principal_name if '@' in principal_name else f"{username}@{realm_name}"
    
    new_user = User(
        username=username,
        email=email,
        is_admin=False
    )
    
    try:
        db.session.add(new_user)
        db.session.commit()
        return new_user
    except Exception as e:
        db.session.rollback()
        return None


def _store_gssapi_account(user_id, principal_name, realm_name):
    """Store GSSAPI account information."""
    realm = GSSAPIRealm.query.filter_by(name=realm_name, is_active=True).first()
    if not realm:
        return False
    
    # Check if account already exists
    existing_account = GSSAPIAccount.query.filter_by(
        user_id=user_id,
        realm_id=realm.id
    ).first()
    
    if existing_account:
        # Update existing account
        existing_account.principal_name = principal_name
        existing_account.last_used_at = db.func.current_timestamp()
    else:
        # Create new account
        new_account = GSSAPIAccount(
            user_id=user_id,
            realm_id=realm.id,
            principal_name=principal_name
        )
        db.session.add(new_account)
    
    try:
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        return False


# GSSAPI Blueprint Routes

@gssapi_bp.route('/authenticate', methods=['POST'])
def gssapi_authenticate():
    """Authenticate user using GSSAPI/Kerberos."""
    data = request.get_json()
    
    if not data or 'gssapi_token' not in data:
        return error_response('Missing gssapi_token parameter', 400)
    
    gssapi_token = data['gssapi_token']
    
    # Extract principal from token
    principal_name, error_msg = _extract_principal_from_token(gssapi_token)
    if error_msg:
        return error_response(error_msg, 400)
    
    if not principal_name:
        return error_response('Failed to extract principal from GSSAPI token', 500)
    
    # Parse realm from principal
    if '@' in principal_name:
        username_part, realm_name = principal_name.split('@', 1)
    else:
        username_part = principal_name
        realm_name = 'DEFAULT.REALM'
    
    # Find or create user
    user = _find_or_create_gssapi_user(principal_name, realm_name)
    if not user:
        return error_response('Failed to authenticate user', 500)
    
    # Store GSSAPI account information
    if not _store_gssapi_account(user.id, principal_name, realm_name):
        return error_response('Failed to store GSSAPI account', 500)
    
    # Create JWT token
    access_token = create_access_token(identity=user.username)
    
    # Get JTI from the token and create session record
    from flask_jwt_extended import decode_token
    token_data = decode_token(access_token)
    jti = token_data['jti']
    
    # Create session record
    create_jwt_session(jti, user.id, 'gssapi')
    
    return success_response(
        'GSSAPI authentication successful',
        {
            'access_token': access_token,
            'user': format_user_response(user)
        }
    )


@gssapi_bp.route('/negotiate', methods=['GET'])
def gssapi_negotiate():
    """Initiate GSSAPI negotiation."""
    try:
        # Create GSSAPI server name
        server_name = gssapi.Name(GSSAPI_SERVICE_NAME, name_type=gssapi.NameType.service)
        server_creds = gssapi.Credentials(name=server_name, usage='accept')
        
        # Create security context
        ctx = gssapi.SecurityContext(creds=server_creds, usage='accept')
        
        # Generate initial token
        token = ctx.step()
        
        if token:
            # Encode token for transmission
            encoded_token = base64.b64encode(token).decode('utf-8')
            
            return success_response(
                'GSSAPI negotiation initiated',
                {
                    'token': encoded_token,
                    'complete': ctx.complete
                }
            )
        else:
            return error_response('Failed to generate GSSAPI token', 500)
    except Exception as e:
        return error_response(f'GSSAPI negotiation error: {str(e)}', 500)


@gssapi_bp.route('/negotiate', methods=['POST'])
def gssapi_negotiate_step():
    """Continue GSSAPI negotiation."""
    data = request.get_json()
    
    if not data or 'token' not in data:
        return error_response('Missing token parameter', 400)
    
    try:
        # Decode token
        token_bytes = base64.b64decode(data['token'])
        
        # Create GSSAPI server name
        server_name = gssapi.Name(GSSAPI_SERVICE_NAME, name_type=gssapi.NameType.service)
        server_creds = gssapi.Credentials(name=server_name, usage='accept')
        
        # Continue security context
        ctx = gssapi.SecurityContext(creds=server_creds, usage='accept')
        token = ctx.step(token_bytes)
        
        if token:
            # Encode response token
            encoded_token = base64.b64encode(token).decode('utf-8')
            
            return success_response(
                'GSSAPI negotiation step completed',
                {
                    'token': encoded_token,
                    'complete': ctx.complete
                }
            )
        else:
            return success_response(
                'GSSAPI negotiation step completed',
                {'complete': ctx.complete}
            )
    except Exception as e:
        return error_response(f'GSSAPI negotiation error: {str(e)}', 500)


@gssapi_bp.route('/realms', methods=['GET'])
def get_gssapi_realms():
    """Get list of available GSSAPI realms."""
    try:
        realms = GSSAPIRealm.query.filter_by(is_active=True).all()
        realm_list = []
        
        for realm in realms:
            realm_list.append({
                'id': realm.id,
                'name': realm.name,
                'display_name': realm.display_name,
                'default_realm': realm.default_realm,
                'kdc_hosts': realm.kdc_hosts
            })
        
        return success_response(
            'GSSAPI realms retrieved successfully',
            {'realms': realm_list}
        )
    except Exception as e:
        return error_response(f'Failed to retrieve GSSAPI realms: {str(e)}', 500)


@gssapi_bp.route('/accounts', methods=['GET'])
@jwt_required()
def get_user_gssapi_accounts():
    """Get GSSAPI accounts for the current user."""
    try:
        current_username = get_jwt_identity()
        user = User.query.filter_by(username=current_username).first()
        
        if not user:
            return error_response('User not found', 404)
        
        # Get GSSAPI accounts
        gssapi_accounts = []
        for gssapi_account in user.gssapi_accounts:
            gssapi_accounts.append({
                'id': gssapi_account.id,
                'realm': gssapi_account.realm.name,
                'realm_display_name': gssapi_account.realm.display_name,
                'principal_name': gssapi_account.principal_name,
                'created_at': gssapi_account.created_at.isoformat() if gssapi_account.created_at else None,
                'last_used_at': gssapi_account.last_used_at.isoformat() if gssapi_account.last_used_at else None
            })
        
        return success_response(
            'GSSAPI accounts retrieved successfully',
            {'gssapi_accounts': gssapi_accounts}
        )
    except Exception as e:
        return error_response(f'Failed to retrieve GSSAPI accounts: {str(e)}', 500)


# The end.

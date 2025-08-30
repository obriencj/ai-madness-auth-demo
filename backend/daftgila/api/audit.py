"""
Audit logging utilities for the Auth Demo application.

This module provides functions for logging administrative actions and system changes
to maintain an audit trail for security and compliance purposes.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

from flask import request
from .model import db, AuditLog, User


def log_action(user_id, action, resource_type, resource_id=None, details=None):
    """
    Log an administrative action to the audit trail.
    
    Args:
        user_id (int): ID of the user performing the action
        action (str): Description of the action performed
        resource_type (str): Type of resource being acted upon
        resource_id (int, optional): ID of the specific resource
        details (dict, optional): Additional details about the action
    """
    try:
        audit_entry = AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=_get_client_ip(),
            user_agent=request.headers.get('User-Agent')
        )
        
        db.session.add(audit_entry)
        db.session.commit()
        
    except Exception as e:
        # Don't let audit logging failures break the main application
        print(f"Audit logging failed: {e}")
        db.session.rollback()


def log_user_action(user_id, action, target_user_id=None, details=None):
    """
    Log user-related administrative actions.
    
    Args:
        user_id (int): ID of the admin user performing the action
        action (str): Description of the action
        target_user_id (int, optional): ID of the user being acted upon
        details (dict, optional): Additional details
    """
    log_action(
        user_id=user_id,
        action=action,
        resource_type='user',
        resource_id=target_user_id,
        details=details
    )


def log_oauth_action(user_id, action, provider_id=None, details=None):
    """
    Log OAuth provider-related administrative actions.
    
    Args:
        user_id (int): ID of the admin user performing the action
        action (str): Description of the action
        provider_id (int, optional): ID of the OAuth provider
        details (dict, optional): Additional details
    """
    log_action(
        user_id=user_id,
        action=action,
        resource_type='oauth_provider',
        resource_id=provider_id,
        details=details
    )


def log_gssapi_action(user_id, action, realm_id=None, details=None):
    """
    Log GSSAPI realm-related administrative actions.
    
    Args:
        user_id (int): ID of the admin user performing the action
        action (str): Description of the action
        realm_id (int, optional): ID of the GSSAPI realm
        details (dict, optional): Additional details
    """
    log_action(
        user_id=user_id,
        action=action,
        resource_type='gssapi_realm',
        resource_id=realm_id,
        details=details
    )


def log_config_action(user_id, action, config_version_id=None, details=None):
    """
    Log configuration-related administrative actions.
    
    Args:
        user_id (int): ID of the admin user performing the action
        action (str): Description of the action
        config_version_id (int, optional): ID of the configuration version
        details (dict, optional): Additional details
    """
    log_action(
        user_id=user_id,
        action=action,
        resource_type='app_config',
        resource_id=config_version_id,
        details=details
    )


def log_session_action(user_id, action, session_id=None, details=None):
    """
    Log JWT session-related administrative actions.
    
    Args:
        user_id (int): ID of the admin user performing the action
        action (str): Description of the action
        session_id (int, optional): ID of the JWT session
        details (dict, optional): Additional details
    """
    log_action(
        user_id=user_id,
        action=action,
        resource_type='jwt_session',
        resource_id=session_id,
        details=details
    )


def log_security_event(user_id, event_type, details=None):
    """
    Log security-related events.
    
    Args:
        user_id (int): ID of the user involved in the security event
        event_type (str): Type of security event
        details (dict, optional): Additional details about the event
    """
    log_action(
        user_id=user_id,
        action=f"security_event:{event_type}",
        resource_type='security',
        details=details
    )


def get_audit_logs(filters=None, limit=100, offset=0):
    """
    Retrieve audit logs with optional filtering.
    
    Args:
        filters (dict, optional): Filter criteria
        limit (int): Maximum number of logs to return
        offset (int): Number of logs to skip
        
    Returns:
        list: List of audit log entries
    """
    query = AuditLog.query
    
    if filters:
        if filters.get('user_id'):
            query = query.filter(AuditLog.user_id == filters['user_id'])
        if filters.get('action'):
            query = query.filter(AuditLog.action == filters['action'])
        if filters.get('resource_type'):
            query = query.filter(AuditLog.resource_type == filters['resource_type'])
        if filters.get('resource_id'):
            query = query.filter(AuditLog.resource_id == filters['resource_id'])
        if filters.get('start_date'):
            query = query.filter(AuditLog.created_at >= filters['start_date'])
        if filters.get('end_date'):
            query = query.filter(AuditLog.created_at <= filters['end_date'])
    
    return query.order_by(AuditLog.created_at.desc()).limit(limit).offset(offset).all()


def _get_client_ip():
    """Get the client's IP address, handling proxy headers."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr


# Predefined action constants for consistency
class AuditActions:
    # User actions
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DEACTIVATED = "user_deactivated"
    USER_ACTIVATED = "user_activated"
    USER_PASSWORD_CHANGED = "user_password_changed"
    USER_LOGIN_FAILED = "user_login_failed"
    USER_ACCOUNT_LOCKED = "user_account_locked"
    USER_ACCOUNT_UNLOCKED = "user_account_unlocked"
    
    # OAuth actions
    OAUTH_PROVIDER_CREATED = "oauth_provider_created"
    OAUTH_PROVIDER_UPDATED = "oauth_provider_updated"
    OAUTH_PROVIDER_DELETED = "oauth_provider_deleted"
    OAUTH_PROVIDER_RESTORED = "oauth_provider_restored"
    OAUTH_ACCOUNT_LINKED = "oauth_account_linked"
    OAUTH_ACCOUNT_UNLINKED = "oauth_account_unlinked"
    
    # GSSAPI actions
    GSSAPI_REALM_CREATED = "gssapi_realm_created"
    GSSAPI_REALM_UPDATED = "gssapi_realm_updated"
    GSSAPI_REALM_DELETED = "gssapi_realm_deleted"
    GSSAPI_REALM_RESTORED = "gssapi_realm_restored"
    GSSAPI_ACCOUNT_LINKED = "gssapi_account_linked"
    GSSAPI_ACCOUNT_UNLINKED = "gssapi_account_unlinked"
    
    # Configuration actions
    CONFIG_CREATED = "config_created"
    CONFIG_ACTIVATED = "config_activated"
    CONFIG_DELETED = "config_deleted"
    
    # Session actions
    SESSION_EXPIRED = "session_expired"
    SESSION_EXPIRED_ALL = "session_expired_all"
    
    # Security events
    SECURITY_LOGIN_SUCCESS = "security_login_success"
    SECURITY_LOGIN_FAILED = "security_login_failed"
    SECURITY_LOGOUT = "security_logout"
    SECURITY_ACCOUNT_LOCKED = "security_account_locked"
    SECURITY_ACCOUNT_UNLOCKED = "security_account_unlocked"


# The end.

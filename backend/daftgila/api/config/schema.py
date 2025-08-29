"""
Configuration schema definitions for the Auth Demo application.

This module defines Pydantic models for configuration validation,
ensuring type safety and business rule enforcement.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

from typing import Optional
from pydantic import BaseModel, Field


class AuthConfig(BaseModel):
    """Authentication configuration settings."""
    jwt_lifetime_hours: int = Field(
        default=1, 
        ge=1, 
        le=24, 
        description="JWT token lifetime in hours"
    )
    allow_user_registration: bool = Field(
        default=True, 
        description="Allow new user registration"
    )
    allow_user_login: bool = Field(
        default=True, 
        description="Allow user login"
    )
    require_email_verification: bool = Field(
        default=False, 
        description="Require email verification"
    )


class OAuthConfig(BaseModel):
    """OAuth authentication configuration settings."""
    enabled: bool = Field(
        default=True, 
        description="Enable OAuth authentication"
    )
    auto_link_accounts: bool = Field(
        default=True, 
        description="Automatically link OAuth accounts to existing users"
    )


class GSSAPIConfig(BaseModel):
    """GSSAPI authentication configuration settings."""
    enabled: bool = Field(
        default=True, 
        description="Enable GSSAPI authentication"
    )
    auto_link_accounts: bool = Field(
        default=True, 
        description="Automatically link GSSAPI accounts to existing users"
    )


class SecurityConfig(BaseModel):
    """Security configuration settings."""
    max_login_attempts: int = Field(
        default=5, 
        ge=1, 
        le=20, 
        description="Maximum login attempts before lockout"
    )
    lockout_duration_minutes: int = Field(
        default=30, 
        ge=1, 
        le=1440, 
        description="Lockout duration in minutes (max 24 hours)"
    )
    password_min_length: int = Field(
        default=8, 
        ge=6, 
        le=128, 
        description="Minimum password length"
    )
    require_strong_password: bool = Field(
        default=False, 
        description="Require strong password (complexity rules)"
    )


class SystemConfig(BaseModel):
    """Complete system configuration schema."""
    auth: AuthConfig
    oauth: OAuthConfig
    gssapi: GSSAPIConfig
    security: SecurityConfig

    class Config:
        """Pydantic configuration."""
        extra = "forbid"  # Reject any fields not defined in the schema
        validate_assignment = True  # Validate when attributes are set


def validate_config(config_data: dict) -> tuple[bool, Optional[str], Optional[SystemConfig]]:
    """
    Validate configuration data against the schema.
    
    Args:
        config_data: Dictionary containing configuration data
        
    Returns:
        Tuple of (is_valid, error_message, validated_config)
    """
    try:
        validated_config = SystemConfig(**config_data)
        return True, None, validated_config
    except Exception as e:
        return False, f"Configuration validation failed: {str(e)}", None


def get_schema_info() -> dict:
    """
    Get schema information for API documentation.
    
    Returns:
        Dictionary containing schema field information
    """
    config = SystemConfig()
    schema_info = {}
    
    for field_name, field in config.__fields__.items():
        field_info = {
            'type': str(field.type_),
            'default': field.default,
            'description': field.field_info.description if field.field_info.description else '',
            'required': field.required
        }
        
        # Add validation constraints
        if hasattr(field.field_info, 'ge'):
            field_info['min_value'] = field.field_info.ge
        if hasattr(field.field_info, 'le'):
            field_info['max_value'] = field.field_info.le
            
        schema_info[field_name] = field_info
    
    return schema_info


# The end.

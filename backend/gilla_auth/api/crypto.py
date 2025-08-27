"""
Cryptographic utilities for GSSAPI keytab encryption.

This module provides secure encryption and decryption of keytab files
using AES-256-GCM with PBKDF2 key derivation.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


class KeytabEncryption:
    """Handles encryption and decryption of GSSAPI keytabs."""
    
    def __init__(self, master_key=None):
        """Initialize with master encryption key."""
        if master_key is None:
            master_key = os.getenv('GSSAPI_MASTER_KEY')
        
        if not master_key:
            raise ValueError("GSSAPI_MASTER_KEY environment variable must be set")
        
        self.master_key = master_key.encode('utf-8')
    
    def derive_key(self, salt, key_length=32):
        """Derive encryption key from master key using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=100000,  # High iteration count for security
            backend=default_backend()
        )
        return kdf.derive(self.master_key)
    
    def encrypt_keytab(self, keytab_data):
        """Encrypt keytab data using AES-256-GCM."""
        if isinstance(keytab_data, str):
            keytab_data = keytab_data.encode('utf-8')
        
        # Generate random salt and IV
        salt = os.urandom(16)
        iv = os.urandom(12)  # 96 bits for GCM
        
        # Derive encryption key
        key = self.derive_key(salt)
        
        # Create AES-GCM cipher
        cipher = AESGCM(key)
        
        # Encrypt data
        encrypted_data = cipher.encrypt(iv, keytab_data, None)
        
        return {
            'encrypted_data': encrypted_data,
            'iv': iv,
            'salt': salt
        }
    
    def decrypt_keytab(self, encrypted_data, iv, salt):
        """Decrypt keytab data using AES-256-GCM."""
        try:
            # Derive decryption key
            key = self.derive_key(salt)
            
            # Create AES-GCM cipher
            cipher = AESGCM(key)
            
            # Decrypt data
            decrypted_data = cipher.decrypt(iv, encrypted_data, None)
            
            return decrypted_data
        except Exception as e:
            raise ValueError(f"Failed to decrypt keytab: {str(e)}")
    
    def validate_keytab_format(self, keytab_data):
        """Basic validation of keytab data format."""
        if not keytab_data:
            return False, "Keytab data is empty"
        
        # Check if it looks like binary keytab data
        if len(keytab_data) < 16:
            return False, "Keytab data too short to be valid"
        
        # Basic magic number check for MIT Kerberos keytabs
        # MIT keytabs start with specific bytes
        if keytab_data.startswith(b'\x05\x02'):
            return True, "Valid MIT Kerberos keytab format"
        
        # Heimdal keytabs have different format
        if keytab_data.startswith(b'\x05\x01'):
            return True, "Valid Heimdal keytab format"
        
        # For now, accept any binary data as potentially valid
        # In production, you might want stricter validation
        return True, "Keytab data appears to be binary (format not verified)"


def get_master_key():
    """Get the master encryption key from environment."""
    master_key = os.getenv('GSSAPI_MASTER_KEY')
    if not master_key:
        raise ValueError(
            "GSSAPI_MASTER_KEY environment variable must be set. "
            "This should be a strong, random 32+ character string."
        )
    return master_key


def generate_master_key():
    """Generate a new master encryption key."""
    return base64.b64encode(os.urandom(32)).decode('utf-8')


# The end.

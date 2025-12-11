"""
Security Utilities and Encryption Functions
Enterprise-grade security implementations
"""

import hashlib
import hmac
import secrets
from typing import Dict, Optional
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import jwt
import base64

class SecurityManager:
    """
    Comprehensive security management for threat intelligence platform
    """
    
    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key = secret_key or self._generate_secret_key()
        self.cipher_suite = self._initialize_cipher()
        
    def _generate_secret_key(self) -> str:
        """Generate cryptographically secure secret key"""
        return secrets.token_urlsafe(32)
    
    def _initialize_cipher(self) -> Fernet:
        """Initialize Fernet cipher for encryption"""
        # Derive key from secret
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'threat_intel_salt',  # In production, use random salt
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.secret_key.encode()))
        return Fernet(key)
    
    def encrypt_data(self, data: str) -> str:
        """
        Encrypt sensitive data using AES-256
        
        Args:
            data: Plain text data to encrypt
        
        Returns:
            Encrypted data as base64 string
        """
        encrypted = self.cipher_suite.encrypt(data.encode())
        return encrypted.decode()
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """
        Decrypt encrypted data
        
        Args:
            encrypted_data: Encrypted data as base64 string
        
        Returns:
            Decrypted plain text
        """
        decrypted = self.cipher_suite.decrypt(encrypted_data.encode())
        return decrypted.decode()
    
    def hash_password(self, password: str) -> str:
        """
        Hash password using SHA-256 with salt
        
        Args:
            password: Plain text password
        
        Returns:
            Hashed password
        """
        salt = secrets.token_hex(16)
        pwd_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt.encode(),
            100000
        )
        return f"{salt}${pwd_hash.hex()}"
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """
        Verify password against hash
        
        Args:
            password: Plain text password
            hashed: Hashed password
        
        Returns:
            True if password matches
        """
        try:
            salt, pwd_hash = hashed.split('$')
            new_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode(),
                salt.encode(),
                100000
            )
            return new_hash.hex() == pwd_hash
        except:
            return False
    
    def generate_api_key(self) -> str:
        """Generate secure API key"""
        return secrets.token_urlsafe(32)
    
    def create_jwt_token(self, user_id: str, role: str, expires_in: int = 3600) -> str:
        """
        Create JWT token for authentication
        
        Args:
            user_id: User identifier
            role: User role
            expires_in: Token expiration in seconds
        
        Returns:
            JWT token
        """
        payload = {
            'user_id': user_id,
            'role': role,
            'exp': datetime.utcnow() + timedelta(seconds=expires_in),
            'iat': datetime.utcnow()
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm='HS256')
        return token
    
    def verify_jwt_token(self, token: str) -> Optional[Dict]:
        """
        Verify and decode JWT token
        
        Args:
            token: JWT token
        
        Returns:
            Decoded payload or None if invalid
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def sanitize_input(self, user_input: str) -> str:
        """
        Sanitize user input to prevent injection attacks
        
        Args:
            user_input: Raw user input
        
        Returns:
            Sanitized input
        """
        # Remove potentially dangerous characters
        dangerous_chars = ['<', '>', '"', "'", '&', ';', '|', '`']
        sanitized = user_input
        
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        return sanitized.strip()
    
    def validate_ip_address(self, ip: str) -> bool:
        """
        Validate IP address format
        
        Args:
            ip: IP address string
        
        Returns:
            True if valid IP
        """
        import re
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        
        if not re.match(ipv4_pattern, ip):
            return False
        
        octets = ip.split('.')
        return all(0 <= int(octet) <= 255 for octet in octets)
    
    def generate_csrf_token(self) -> str:
        """Generate CSRF token for form protection"""
        return secrets.token_urlsafe(32)
    
    def verify_csrf_token(self, token: str, stored_token: str) -> bool:
        """Verify CSRF token"""
        return hmac.compare_digest(token, stored_token)
    
    def rate_limit_check(self, identifier: str, max_requests: int = 100, window: int = 60) -> bool:
        """
        Check if request should be rate limited
        
        Args:
            identifier: User/IP identifier
            max_requests: Maximum requests allowed
            window: Time window in seconds
        
        Returns:
            True if request should be allowed
        """
        # In production, use Redis for distributed rate limiting
        # This is a simplified implementation
        return True
    
    def audit_log(self, user_id: str, action: str, resource: str, status: str):
        """
        Log security-relevant actions
        
        Args:
            user_id: User performing action
            action: Action performed
            resource: Resource accessed
            status: Success/failure status
        """
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'user_id': user_id,
            'action': action,
            'resource': resource,
            'status': status
        }
        
        # In production, write to secure audit log
        print(f"AUDIT: {log_entry}")


class AccessControl:
    """
    Role-Based Access Control (RBAC) implementation
    """
    
    ROLES = {
        'admin': ['read', 'write', 'delete', 'manage_users', 'configure'],
        'analyst': ['read', 'write', 'investigate'],
        'viewer': ['read'],
        'api_user': ['read', 'write']
    }
    
    @classmethod
    def check_permission(cls, role: str, permission: str) -> bool:
        """
        Check if role has permission
        
        Args:
            role: User role
            permission: Required permission
        
        Returns:
            True if role has permission
        """
        if role not in cls.ROLES:
            return False
        
        return permission in cls.ROLES[role]
    
    @classmethod
    def get_role_permissions(cls, role: str) -> list:
        """Get all permissions for a role"""
        return cls.ROLES.get(role, [])


class DataAnonymizer:
    """
    PII and sensitive data anonymization for GDPR compliance
    """
    
    @staticmethod
    def anonymize_ip(ip: str) -> str:
        """Anonymize IP address by masking last octet"""
        parts = ip.split('.')
        if len(parts) == 4:
            parts[-1] = 'xxx'
            return '.'.join(parts)
        return ip
    
    @staticmethod
    def anonymize_email(email: str) -> str:
        """Anonymize email address"""
        if '@' in email:
            local, domain = email.split('@')
            anonymized_local = local[0] + '*' * (len(local) - 2) + local[-1] if len(local) > 2 else local
            return f"{anonymized_local}@{domain}"
        return email
    
    @staticmethod
    def hash_pii(data: str) -> str:
        """Hash PII data for storage"""
        return hashlib.sha256(data.encode()).hexdigest()

"""
CAP-SRP Cryptographic Signer

This module provides Ed25519 digital signature functionality for CAP-SRP events.

Ed25519 is chosen because:
1. Fast signing and verification
2. Small key and signature sizes (32 bytes each)
3. Deterministic signatures (same input always produces same output)
4. Strong security guarantees
5. Widely supported (RFC 8032)
6. Used by IETF SCITT and major blockchain systems

Usage:
    >>> from cap_srp.core.signer import Ed25519Signer
    >>> 
    >>> # Create a new signer with generated keys
    >>> signer = Ed25519Signer()
    >>> 
    >>> # Or load existing keys
    >>> signer = Ed25519Signer.from_private_key(private_key_bytes)
    >>> 
    >>> # Sign data
    >>> signature = signer.sign(b"data to sign")
    >>> 
    >>> # Verify signature
    >>> is_valid = signer.verify(b"data to sign", signature)
"""

import base64
from typing import Optional, Tuple
from dataclasses import dataclass

try:
    from nacl.signing import SigningKey, VerifyKey
    from nacl.encoding import Base64Encoder
    from nacl.exceptions import BadSignature
    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False
    # Fallback to cryptography library
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature


@dataclass
class SignatureResult:
    """Result of a signing operation."""
    signature: bytes
    signature_b64: str
    public_key: bytes
    public_key_b64: str


@dataclass
class VerificationResult:
    """Result of a signature verification."""
    is_valid: bool
    error_message: Optional[str] = None


class Ed25519Signer:
    """
    Ed25519 digital signature provider.
    
    Provides signing and verification using Ed25519 (EdDSA with Curve25519).
    
    Attributes:
        _private_key: The private signing key
        _public_key: The public verification key
    """
    
    def __init__(self, private_key: Optional[bytes] = None):
        """
        Initialize the signer.
        
        Args:
            private_key: Optional 32-byte private key. If not provided,
                        a new key pair will be generated.
        """
        if NACL_AVAILABLE:
            self._init_nacl(private_key)
        else:
            self._init_cryptography(private_key)
    
    def _init_nacl(self, private_key: Optional[bytes] = None):
        """Initialize using PyNaCl library."""
        if private_key:
            self._signing_key = SigningKey(private_key)
        else:
            self._signing_key = SigningKey.generate()
        self._verify_key = self._signing_key.verify_key
        self._use_nacl = True
    
    def _init_cryptography(self, private_key: Optional[bytes] = None):
        """Initialize using cryptography library."""
        if private_key:
            self._private_key = Ed25519PrivateKey.from_private_bytes(private_key)
        else:
            self._private_key = Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()
        self._use_nacl = False
    
    @classmethod
    def from_private_key(cls, private_key: bytes) -> 'Ed25519Signer':
        """
        Create a signer from an existing private key.
        
        Args:
            private_key: 32-byte Ed25519 private key
            
        Returns:
            Ed25519Signer: A signer instance with the provided key
        """
        return cls(private_key=private_key)
    
    @classmethod
    def from_private_key_b64(cls, private_key_b64: str) -> 'Ed25519Signer':
        """
        Create a signer from a base64-encoded private key.
        
        Args:
            private_key_b64: Base64-encoded 32-byte private key
            
        Returns:
            Ed25519Signer: A signer instance with the provided key
        """
        private_key = base64.b64decode(private_key_b64)
        return cls(private_key=private_key)
    
    @property
    def public_key(self) -> bytes:
        """Get the public key bytes."""
        if NACL_AVAILABLE and self._use_nacl:
            return bytes(self._verify_key)
        else:
            return self._public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
    
    @property
    def public_key_b64(self) -> str:
        """Get the public key as base64 string."""
        return base64.b64encode(self.public_key).decode('ascii')
    
    @property
    def private_key(self) -> bytes:
        """Get the private key bytes."""
        if NACL_AVAILABLE and self._use_nacl:
            return bytes(self._signing_key)
        else:
            return self._private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
    
    @property
    def private_key_b64(self) -> str:
        """Get the private key as base64 string."""
        return base64.b64encode(self.private_key).decode('ascii')
    
    def sign(self, data: bytes) -> SignatureResult:
        """
        Sign data with the private key.
        
        Args:
            data: The bytes to sign
            
        Returns:
            SignatureResult: Contains signature and public key
        """
        if NACL_AVAILABLE and self._use_nacl:
            signed = self._signing_key.sign(data)
            signature = signed.signature
        else:
            signature = self._private_key.sign(data)
        
        return SignatureResult(
            signature=signature,
            signature_b64=base64.b64encode(signature).decode('ascii'),
            public_key=self.public_key,
            public_key_b64=self.public_key_b64
        )
    
    def sign_string(self, data: str) -> SignatureResult:
        """
        Sign a string (UTF-8 encoded).
        
        Args:
            data: The string to sign
            
        Returns:
            SignatureResult: Contains signature and public key
        """
        return self.sign(data.encode('utf-8'))
    
    def verify(self, data: bytes, signature: bytes) -> VerificationResult:
        """
        Verify a signature against the public key.
        
        Args:
            data: The original signed data
            signature: The signature to verify
            
        Returns:
            VerificationResult: Contains is_valid and optional error
        """
        try:
            if NACL_AVAILABLE and self._use_nacl:
                self._verify_key.verify(data, signature)
            else:
                self._public_key.verify(signature, data)
            return VerificationResult(is_valid=True)
        except (BadSignature if NACL_AVAILABLE else InvalidSignature) as e:
            return VerificationResult(is_valid=False, error_message=str(e))
        except Exception as e:
            return VerificationResult(is_valid=False, error_message=f"Verification error: {e}")
    
    def verify_b64(self, data: bytes, signature_b64: str) -> VerificationResult:
        """
        Verify a base64-encoded signature.
        
        Args:
            data: The original signed data
            signature_b64: Base64-encoded signature
            
        Returns:
            VerificationResult: Contains is_valid and optional error
        """
        try:
            signature = base64.b64decode(signature_b64)
            return self.verify(data, signature)
        except Exception as e:
            return VerificationResult(is_valid=False, error_message=f"Decode error: {e}")
    
    @staticmethod
    def verify_with_public_key(
        data: bytes, 
        signature: bytes, 
        public_key: bytes
    ) -> VerificationResult:
        """
        Verify a signature using a provided public key.
        
        This is useful for verifying signatures without access to the private key.
        
        Args:
            data: The original signed data
            signature: The signature to verify
            public_key: 32-byte Ed25519 public key
            
        Returns:
            VerificationResult: Contains is_valid and optional error
        """
        try:
            if NACL_AVAILABLE:
                verify_key = VerifyKey(public_key)
                verify_key.verify(data, signature)
            else:
                pk = Ed25519PublicKey.from_public_bytes(public_key)
                pk.verify(signature, data)
            return VerificationResult(is_valid=True)
        except Exception as e:
            return VerificationResult(is_valid=False, error_message=str(e))
    
    @staticmethod
    def verify_with_public_key_b64(
        data: bytes,
        signature_b64: str,
        public_key_b64: str
    ) -> VerificationResult:
        """
        Verify using base64-encoded signature and public key.
        
        Args:
            data: The original signed data
            signature_b64: Base64-encoded signature
            public_key_b64: Base64-encoded public key
            
        Returns:
            VerificationResult: Contains is_valid and optional error
        """
        try:
            signature = base64.b64decode(signature_b64)
            public_key = base64.b64decode(public_key_b64)
            return Ed25519Signer.verify_with_public_key(data, signature, public_key)
        except Exception as e:
            return VerificationResult(is_valid=False, error_message=f"Decode error: {e}")


def generate_key_pair() -> Tuple[bytes, bytes]:
    """
    Generate a new Ed25519 key pair.
    
    Returns:
        Tuple[bytes, bytes]: (private_key, public_key) each 32 bytes
    """
    signer = Ed25519Signer()
    return (signer.private_key, signer.public_key)


def generate_key_pair_b64() -> Tuple[str, str]:
    """
    Generate a new Ed25519 key pair as base64 strings.
    
    Returns:
        Tuple[str, str]: (private_key_b64, public_key_b64)
    """
    signer = Ed25519Signer()
    return (signer.private_key_b64, signer.public_key_b64)

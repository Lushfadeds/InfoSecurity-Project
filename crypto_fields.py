"""
crypto_fields.py - Envelope Encryption Module for PHI Fields

This module implements AES-256-GCM envelope encryption for protecting
Protected Health Information (PHI) fields in the application.

Architecture:
- DEK (Data Encryption Key): Per-user 32-byte random key for encrypting PHI fields
- KEK (Key Encryption Key): Master key used to wrap/unwrap DEKs
  - Offline mode: Uses APP_KEK (Fernet) from environment
  - Optional: AWS KMS for production environments

Supabase Schema (profiles table):
    -- SQL to add encrypted columns (run in Supabase SQL editor):
    -- ALTER TABLE profiles ADD COLUMN IF NOT EXISTS nric_encrypted TEXT;
    -- ALTER TABLE profiles ADD COLUMN IF NOT EXISTS address_encrypted TEXT;
    -- ALTER TABLE profiles ADD COLUMN IF NOT EXISTS dob_encrypted TEXT;
    -- ALTER TABLE profiles ADD COLUMN IF NOT EXISTS phone_encrypted TEXT;
    -- ALTER TABLE profiles ADD COLUMN IF NOT EXISTS dek_encrypted TEXT;
    -- 
    -- Optional: Remove plaintext columns after migration
    -- ALTER TABLE profiles DROP COLUMN IF EXISTS nric;
    -- ALTER TABLE profiles DROP COLUMN IF EXISTS address;
    -- ALTER TABLE profiles DROP COLUMN IF EXISTS dob;
    -- ALTER TABLE profiles DROP COLUMN IF EXISTS mobile_number;
"""

import os
import secrets
import base64
import logging
from typing import Dict, Optional, Tuple

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Optional AWS KMS support
try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
    HAS_BOTO3 = True
except ImportError:
    boto3 = None
    HAS_BOTO3 = False

logger = logging.getLogger(__name__)

# ============================================================================
# Configuration
# ============================================================================

def get_app_kek() -> Optional[bytes]:
    """
    Get the Application KEK (Fernet key) from environment.
    
    The APP_KEK should be a 32-byte URL-safe base64-encoded key.
    Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    """
    kek_str = os.environ.get('APP_KEK')
    if kek_str:
        return kek_str.encode('utf-8')
    return None


def get_kms_key_id() -> Optional[str]:
    """Get AWS KMS Key ID from environment if configured."""
    return os.environ.get('AWS_KMS_KEY_ID')


def is_kms_available() -> bool:
    """Check if AWS KMS is configured and available."""
    return HAS_BOTO3 and get_kms_key_id() is not None


# ============================================================================
# DEK Generation and Wrapping
# ============================================================================

def generate_data_key() -> Tuple[bytes, str]:
    """
    Generate a new Data Encryption Key (DEK) for a user.
    
    Returns:
        Tuple of (plaintext_dek, wrapped_dek_base64)
        - plaintext_dek: 32-byte raw key for encryption operations
        - wrapped_dek_base64: Base64-encoded wrapped key for storage in Supabase
    
    Uses AWS KMS if available, otherwise falls back to APP_KEK (Fernet).
    """
    if is_kms_available():
        return _generate_data_key_kms()
    else:
        return _generate_data_key_offline()


def _generate_data_key_offline() -> Tuple[bytes, str]:
    """
    Generate DEK using offline mode (APP_KEK with Fernet).
    
    The DEK is wrapped using Fernet symmetric encryption.
    """
    app_kek = get_app_kek()
    if not app_kek:
        raise ValueError(
            "APP_KEK environment variable not set. "
            "Generate with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    
    # Generate 32-byte random DEK for AES-256
    plaintext_dek = secrets.token_bytes(32)
    
    # Wrap DEK using Fernet
    fernet = Fernet(app_kek)
    wrapped_dek = fernet.encrypt(plaintext_dek)
    
    # Return plaintext DEK and base64-encoded wrapped DEK for storage
    wrapped_dek_base64 = base64.b64encode(wrapped_dek).decode('utf-8')
    
    logger.debug("Generated new DEK using offline mode (Fernet)")
    return plaintext_dek, wrapped_dek_base64


def _generate_data_key_kms() -> Tuple[bytes, str]:
    """
    Generate DEK using AWS KMS.
    
    Uses KMS GenerateDataKey API for envelope encryption.
    """
    kms_key_id = get_kms_key_id()
    region = os.environ.get('AWS_REGION', 'ap-southeast-2')
    
    try:
        kms_client = boto3.client('kms', region_name=region)
        response = kms_client.generate_data_key(
            KeyId=kms_key_id,
            KeySpec='AES_256'
        )
        
        plaintext_dek = response['Plaintext']
        wrapped_dek = response['CiphertextBlob']
        wrapped_dek_base64 = base64.b64encode(wrapped_dek).decode('utf-8')
        
        logger.debug("Generated new DEK using AWS KMS")
        return plaintext_dek, wrapped_dek_base64
        
    except (BotoCoreError, ClientError) as e:
        logger.warning(f"KMS GenerateDataKey failed, falling back to offline: {e}")
        return _generate_data_key_offline()


def decrypt_data_key(wrapped_dek_base64: str) -> Optional[bytes]:
    """
    Decrypt/unwrap a stored DEK.
    
    Args:
        wrapped_dek_base64: Base64-encoded wrapped DEK from Supabase
    
    Returns:
        32-byte plaintext DEK, or None if decryption fails
    
    Attempts KMS first if available, then falls back to Fernet.
    """
    if not wrapped_dek_base64:
        return None
    
    try:
        wrapped_dek = base64.b64decode(wrapped_dek_base64)
    except Exception as e:
        logger.error(f"Failed to decode wrapped DEK: {e}")
        return None
    
    # Try KMS first if available
    if is_kms_available():
        result = _decrypt_data_key_kms(wrapped_dek)
        if result:
            return result
        # Fall through to offline mode
    
    # Offline mode with Fernet
    return _decrypt_data_key_offline(wrapped_dek)


def _decrypt_data_key_offline(wrapped_dek: bytes) -> Optional[bytes]:
    """Decrypt DEK using Fernet (offline mode)."""
    app_kek = get_app_kek()
    if not app_kek:
        logger.error("APP_KEK not configured for DEK decryption")
        return None
    
    try:
        fernet = Fernet(app_kek)
        plaintext_dek = fernet.decrypt(wrapped_dek)
        return plaintext_dek
    except InvalidToken as e:
        logger.error(f"Fernet decryption failed (invalid token/key mismatch): {e}")
        return None
    except Exception as e:
        logger.error(f"DEK decryption failed: {e}")
        return None


def _decrypt_data_key_kms(wrapped_dek: bytes) -> Optional[bytes]:
    """Decrypt DEK using AWS KMS."""
    region = os.environ.get('AWS_REGION', 'ap-southeast-2')
    try:
        kms_client = boto3.client('kms', region_name=region)
        response = kms_client.decrypt(CiphertextBlob=wrapped_dek)
        return response['Plaintext']
    except ClientError as e:
        # InvalidCiphertextException means data is not KMS-encrypted (likely Fernet format)
        # Don't log as warning - just silently fall back to offline mode
        if e.response['Error']['Code'] == 'InvalidCiphertextException':
            return None
        logger.warning(f"KMS decrypt failed: {e}")
        return None
    except BotoCoreError:
        # Network/credential errors - silently fall back to offline mode
        return None


# ============================================================================
# AES-GCM Field Encryption/Decryption
# ============================================================================

def aesgcm_encrypt(plaintext: str, dek: bytes) -> str:
    """
    Encrypt a plaintext string using AES-256-GCM.
    
    Args:
        plaintext: String to encrypt
        dek: 32-byte Data Encryption Key
    
    Returns:
        Base64-encoded string: base64(nonce + ciphertext + tag)
        - nonce: 12 bytes
        - ciphertext: variable length
        - tag: 16 bytes (appended by AESGCM)
    """
    if not plaintext:
        return ""
    
    # Generate 12-byte random nonce (96 bits, recommended for GCM)
    nonce = secrets.token_bytes(12)
    
    # Create AESGCM cipher with 256-bit key
    aesgcm = AESGCM(dek)
    
    # Encrypt (returns ciphertext + 16-byte auth tag)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    
    # Combine nonce + ciphertext+tag and encode as base64
    combined = nonce + ciphertext_with_tag
    return base64.b64encode(combined).decode('utf-8')


def aesgcm_decrypt(ciphertext_b64: str, dek: bytes) -> Optional[str]:
    """
    Decrypt a ciphertext encrypted with aesgcm_encrypt.
    
    Args:
        ciphertext_b64: Base64-encoded string from aesgcm_encrypt
        dek: 32-byte Data Encryption Key
    
    Returns:
        Decrypted plaintext string, or None if decryption fails
    """
    if not ciphertext_b64:
        return None
    
    try:
        # Decode base64
        combined = base64.b64decode(ciphertext_b64)
        
        # Extract nonce (first 12 bytes) and ciphertext+tag (rest)
        if len(combined) < 12 + 16:  # nonce + minimum tag
            logger.error("Ciphertext too short")
            return None
        
        nonce = combined[:12]
        ciphertext_with_tag = combined[12:]
        
        # Decrypt
        aesgcm = AESGCM(dek)
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
        
        return plaintext.decode('utf-8')
        
    except Exception as e:
        logger.error(f"AESGCM decryption failed: {e}")
        return None


# ============================================================================
# Envelope Encryption for Multiple Fields
# ============================================================================

def envelope_encrypt_fields(
    existing_dek_encrypted: Optional[str],
    fields_dict: Dict[str, str]
) -> Tuple[str, Dict[str, str]]:
    """
    Encrypt multiple PHI fields using envelope encryption.
    
    This function handles the complete envelope encryption workflow:
    1. Reuses existing DEK if provided, or generates a new one
    2. Encrypts each field in fields_dict using AES-256-GCM
    3. Returns the wrapped DEK and encrypted fields for storage
    
    Args:
        existing_dek_encrypted: Base64 wrapped DEK from existing profile (or None for new user)
        fields_dict: Dictionary of field_name -> plaintext_value
            Example: {'nric': 'S1234567A', 'phone': '+6591234567'}
    
    Returns:
        Tuple of (dek_encrypted, encrypted_dict)
        - dek_encrypted: Base64 wrapped DEK for storage in profiles.dek_encrypted
        - encrypted_dict: Dictionary of field_name -> encrypted_value
            Example: {'nric_encrypted': 'base64...', 'phone_encrypted': 'base64...'}
    
    Usage:
        dek_encrypted, encrypted = envelope_encrypt_fields(
            profile.get('dek_encrypted'),
            {'nric': 'S1234567A', 'address': '123 Main St', 'phone': '+6591234567'}
        )
        # Store encrypted values in Supabase:
        # UPDATE profiles SET dek_encrypted=?, nric_encrypted=?, address_encrypted=?, phone_encrypted=?
    """
    # Get or generate DEK
    if existing_dek_encrypted:
        # Reuse existing DEK for this user
        plaintext_dek = decrypt_data_key(existing_dek_encrypted)
        if not plaintext_dek:
            raise ValueError("Failed to decrypt existing DEK - key may be corrupted or APP_KEK changed")
        dek_encrypted = existing_dek_encrypted
    else:
        # Generate new DEK for new user
        plaintext_dek, dek_encrypted = generate_data_key()
    
    # Encrypt each field
    encrypted_dict = {}
    for field_name, plaintext_value in fields_dict.items():
        if plaintext_value:
            encrypted_value = aesgcm_encrypt(plaintext_value, plaintext_dek)
            # Add '_encrypted' suffix to field name for storage
            encrypted_field_name = f"{field_name}_encrypted"
            encrypted_dict[encrypted_field_name] = encrypted_value
        else:
            # Store empty string for null/empty values
            encrypted_dict[f"{field_name}_encrypted"] = ""
    
    return dek_encrypted, encrypted_dict


def envelope_decrypt_field(dek_encrypted: str, ciphertext: str) -> Optional[str]:
    """
    Decrypt a single encrypted field using envelope decryption.
    
    Args:
        dek_encrypted: Base64 wrapped DEK from profiles.dek_encrypted
        ciphertext: Base64 encrypted field value (e.g., profiles.nric_encrypted)
    
    Returns:
        Decrypted plaintext string, or None if decryption fails
    
    Usage:
        nric = envelope_decrypt_field(profile['dek_encrypted'], profile['nric_encrypted'])
    """
    if not dek_encrypted or not ciphertext:
        return None
    
    plaintext_dek = decrypt_data_key(dek_encrypted)
    if not plaintext_dek:
        return None
    
    return aesgcm_decrypt(ciphertext, plaintext_dek)


def envelope_decrypt_fields(
    dek_encrypted: str,
    encrypted_fields: Dict[str, str]
) -> Dict[str, Optional[str]]:
    """
    Decrypt multiple encrypted fields at once.
    
    Args:
        dek_encrypted: Base64 wrapped DEK from profiles.dek_encrypted
        encrypted_fields: Dictionary of field_name -> encrypted_value
            Example: {'nric_encrypted': 'base64...', 'phone_encrypted': 'base64...'}
    
    Returns:
        Dictionary of field_name (without _encrypted suffix) -> plaintext or None
            Example: {'nric': 'S1234567A', 'phone': '+6591234567'}
    """
    if not dek_encrypted:
        return {k.replace('_encrypted', ''): None for k in encrypted_fields}
    
    plaintext_dek = decrypt_data_key(dek_encrypted)
    if not plaintext_dek:
        return {k.replace('_encrypted', ''): None for k in encrypted_fields}
    
    result = {}
    for field_name, encrypted_value in encrypted_fields.items():
        # Remove '_encrypted' suffix for output key
        output_key = field_name.replace('_encrypted', '')
        if encrypted_value:
            result[output_key] = aesgcm_decrypt(encrypted_value, plaintext_dek)
        else:
            result[output_key] = None
    
    return result


# ============================================================================
# JSON Encryption for Structured Data (e.g., prescriptions.medications)
# ============================================================================

import json

def encrypt_json_field(data: any, existing_dek_encrypted: Optional[str] = None) -> Tuple[str, str]:
    """
    Encrypt a JSON-serializable field (list, dict, etc.) using envelope encryption.
    
    This is used for fields like prescriptions.medications that contain structured
    PHI data (drug names, dosages, instructions).
    
    Args:
        data: Any JSON-serializable data (list, dict, string, etc.)
        existing_dek_encrypted: Reuse existing DEK if provided, or generate new one
    
    Returns:
        Tuple of (dek_encrypted, encrypted_json_base64)
        - dek_encrypted: Base64 wrapped DEK for storage
        - encrypted_json_base64: Encrypted JSON string
    
    Usage:
        dek, encrypted_meds = encrypt_json_field(medications_list)
        # Store in prescriptions table:
        # INSERT INTO prescriptions (medications_encrypted, dek_encrypted) VALUES (?, ?)
    """
    # Serialize to JSON string
    json_str = json.dumps(data, ensure_ascii=False)
    
    # Use envelope encryption
    dek_encrypted, encrypted_dict = envelope_encrypt_fields(
        existing_dek_encrypted,
        {'json': json_str}
    )
    
    return dek_encrypted, encrypted_dict.get('json_encrypted', '')


def decrypt_json_field(dek_encrypted: str, encrypted_data: str) -> Optional[any]:
    """
    Decrypt a JSON field that was encrypted with encrypt_json_field.
    
    Args:
        dek_encrypted: Base64 wrapped DEK from the record
        encrypted_data: Encrypted JSON string
    
    Returns:
        Original data (parsed from JSON), or None if decryption fails
    
    Usage:
        medications = decrypt_json_field(rx['dek_encrypted'], rx['medications_encrypted'])
    """
    if not dek_encrypted or not encrypted_data:
        return None
    
    decrypted_str = envelope_decrypt_field(dek_encrypted, encrypted_data)
    if not decrypted_str:
        return None
    
    try:
        return json.loads(decrypted_str)
    except json.JSONDecodeError:
        logger.error("Failed to parse decrypted JSON")
        return None


# ============================================================================
# Utility Functions
# ============================================================================

def mask_nric(nric: str) -> str:
    """
    Mask NRIC for display (S1234567A -> S****567A).
    
    Used when user doesn't have access to view full NRIC.
    """
    if not nric or len(nric) < 9:
        return "****"
    return f"{nric[0]}****{nric[-4:]}"


def can_access_record(user_session: dict, record_owner_id: str) -> bool:
    """
    Check if user has access to decrypt a record's PHI fields.
    
    Access rules:
    - Patients can only access their own records
    - Doctors can access patient records in their clinic
    - Admins/clinic_managers can access all records in their clinic
    - Pharmacy/counter staff get masked data only
    
    Args:
        user_session: Session data with user_id, role, clinic_id
        record_owner_id: The user_id who owns the record
    
    Returns:
        True if user can decrypt PHI fields, False otherwise
    """
    if not user_session:
        return False
    
    role = user_session.get('role')
    user_id = user_session.get('user_id')
    user_clinic_id = user_session.get('clinic_id')
    
    # Patients can only access their own records
    if role == 'patient':
        return user_id == record_owner_id
    
    # Doctors and admin can access records (additional clinic check could be added)
    if role in ('doctor', 'admin', 'clinic_manager'):
        return True
    
    # Pharmacy and counter staff cannot decrypt - they get masked data
    if role in ('pharmacy', 'counter', 'staff'):
        return False
    
    return False


def get_profile_with_decryption(
    profile_data: dict,
    user_session: dict
) -> dict:
    """
    Get profile data with appropriate decryption based on access control.
    
    If user has access: decrypt PHI fields
    If user doesn't have access: return masked values
    
    Args:
        profile_data: Raw profile from Supabase with encrypted fields
        user_session: Current user's session data
    
    Returns:
        Profile dict with decrypted or masked PHI fields
    """
    result = profile_data.copy()
    record_owner_id = profile_data.get('id')
    
    # Extract encrypted fields
    encrypted_fields = {
        'nric_encrypted': profile_data.get('nric_encrypted', ''),
        'address_encrypted': profile_data.get('address_encrypted', ''),
        'dob_encrypted': profile_data.get('dob_encrypted', ''),
        'phone_encrypted': profile_data.get('phone_encrypted', ''),
    }
    
    dek_encrypted = profile_data.get('dek_encrypted', '')
    
    if can_access_record(user_session, record_owner_id):
        # User has access - decrypt fields
        decrypted = envelope_decrypt_fields(dek_encrypted, encrypted_fields)
        result['nric'] = decrypted.get('nric') or ''
        result['address'] = decrypted.get('address') or ''
        result['dob'] = decrypted.get('dob') or ''
        result['phone'] = decrypted.get('phone') or ''
    else:
        # No access - return masked values
        # Decrypt NRIC just to mask it (or use stored masked version if available)
        nric_decrypted = envelope_decrypt_field(dek_encrypted, encrypted_fields.get('nric_encrypted', ''))
        result['nric'] = mask_nric(nric_decrypted) if nric_decrypted else '****'
        result['address'] = None
        result['dob'] = None
        result['phone'] = None
    
    # Remove encrypted fields from output (don't expose to templates)
    for key in list(result.keys()):
        if key.endswith('_encrypted'):
            del result[key]
    
    return result


# ============================================================================
# File Encryption/Decryption (AES-256-GCM)
# ============================================================================

def encrypt_file(file_data: bytes, existing_dek_encrypted: str = None) -> tuple[bytes, str]:
    """
    Encrypt file data using AES-256-GCM envelope encryption.
    
    This uses the same envelope encryption pattern as field encryption:
    - Generate or reuse a DEK (Data Encryption Key)
    - Encrypt file with DEK using AES-256-GCM
    - Return encrypted data + wrapped DEK for storage
    
    Args:
        file_data: Raw file bytes to encrypt
        existing_dek_encrypted: Optional existing wrapped DEK to reuse
    
    Returns:
        Tuple of (encrypted_file_bytes, dek_encrypted)
        - encrypted_file_bytes: nonce (12 bytes) + ciphertext + auth tag
        - dek_encrypted: Base64 wrapped DEK for storage in database
    
    File format:
        [12-byte nonce][ciphertext][16-byte auth tag]
    """
    if not file_data:
        raise ValueError("No file data provided")
    
    # Get or generate DEK
    if existing_dek_encrypted:
        plaintext_dek = decrypt_data_key(existing_dek_encrypted)
        if not plaintext_dek:
            raise ValueError("Failed to decrypt existing DEK")
        dek_encrypted = existing_dek_encrypted
    else:
        plaintext_dek, dek_encrypted = generate_data_key()
    
    # Generate 12-byte random nonce
    nonce = secrets.token_bytes(12)
    
    # Encrypt file data with AES-256-GCM
    aesgcm = AESGCM(plaintext_dek)
    ciphertext_with_tag = aesgcm.encrypt(nonce, file_data, None)
    
    # Combine nonce + ciphertext + tag
    encrypted_data = nonce + ciphertext_with_tag
    
    logger.debug(f"Encrypted file: {len(file_data)} bytes -> {len(encrypted_data)} bytes")
    return encrypted_data, dek_encrypted


def decrypt_file(encrypted_data: bytes, dek_encrypted: str) -> bytes:
    """
    Decrypt file data that was encrypted with encrypt_file.
    
    Args:
        encrypted_data: Encrypted file bytes (nonce + ciphertext + tag)
        dek_encrypted: Base64 wrapped DEK from database
    
    Returns:
        Decrypted file bytes
    
    Raises:
        ValueError: If decryption fails (corrupted data or wrong key)
    """
    if not encrypted_data:
        raise ValueError("No encrypted data provided")
    
    if not dek_encrypted:
        raise ValueError("No DEK provided for decryption")
    
    # Minimum size: 12 (nonce) + 16 (auth tag) = 28 bytes
    if len(encrypted_data) < 28:
        raise ValueError("Encrypted data too short")
    
    # Unwrap DEK
    plaintext_dek = decrypt_data_key(dek_encrypted)
    if not plaintext_dek:
        raise ValueError("Failed to decrypt DEK - key may be corrupted or APP_KEK changed")
    
    # Extract nonce and ciphertext
    nonce = encrypted_data[:12]
    ciphertext_with_tag = encrypted_data[12:]
    
    # Decrypt with AES-256-GCM
    try:
        aesgcm = AESGCM(plaintext_dek)
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
        logger.debug(f"Decrypted file: {len(encrypted_data)} bytes -> {len(plaintext)} bytes")
        return plaintext
    except Exception as e:
        logger.error(f"File decryption failed: {e}")
        raise ValueError(f"File decryption failed: {e}")


def encrypt_file_stream(file_stream, existing_dek_encrypted: str = None) -> tuple[bytes, str]:
    """
    Encrypt a file stream (e.g., from request.files).
    
    Convenience wrapper that reads the stream and encrypts.
    
    Args:
        file_stream: File-like object with read() method
        existing_dek_encrypted: Optional existing wrapped DEK to reuse
    
    Returns:
        Tuple of (encrypted_file_bytes, dek_encrypted)
    """
    file_data = file_stream.read()
    return encrypt_file(file_data, existing_dek_encrypted)

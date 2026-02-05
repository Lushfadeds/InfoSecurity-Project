"""Test AWS KMS integration"""
from dotenv import load_dotenv
load_dotenv()

import os
print("=" * 50)
print("AWS KMS Integration Test")
print("=" * 50)

# Check env vars
print("\n1. Environment Variables:")
print("   AWS_KMS_KEY_ID:", os.environ.get('AWS_KMS_KEY_ID', 'NOT SET'))
print("   AWS_REGION:", os.environ.get('AWS_REGION', 'NOT SET'))
print("   AWS_ACCESS_KEY_ID:", os.environ.get('AWS_ACCESS_KEY_ID', 'NOT SET')[:10] + '...' if os.environ.get('AWS_ACCESS_KEY_ID') else 'NOT SET')

# Check boto3
print("\n2. boto3 Library:")
try:
    import boto3
    print("   Installed: YES")
    print("   Version:", boto3.__version__)
except ImportError:
    print("   Installed: NO - run: pip install boto3")
    exit()

# Check crypto_fields
print("\n3. KMS Availability Check:")
from crypto_fields import is_kms_available, generate_data_key
print("   is_kms_available():", is_kms_available())

# Try to generate a key
print("\n4. Key Generation Test:")
try:
    dek, wrapped = generate_data_key()
    print("   SUCCESS!")
    print("   DEK length:", len(dek), "bytes")
    print("   Wrapped DEK:", wrapped[:50] + "...")
    print("   Using:", "AWS KMS" if is_kms_available() else "Local APP_KEK (fallback)")
except Exception as e:
    print("   FAILED:", str(e))

print("\n" + "=" * 50)

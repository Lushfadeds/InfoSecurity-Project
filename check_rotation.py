from dotenv import load_dotenv
load_dotenv()

import boto3, json

kms = boto3.client('kms', region_name='ap-southeast-2')
key_id = 'c8908f12-3f55-4cae-a526-75e3754a860b'

print("=== KEY INFO ===")
desc = kms.describe_key(KeyId=key_id)
m = desc['KeyMetadata']
print(f"  Created:  {m['CreationDate']}")
print(f"  State:    {m['KeyState']}")
print(f"  Spec:     {m['KeySpec']}")

print("\n=== ROTATION STATUS (raw) ===")
rot = kms.get_key_rotation_status(KeyId=key_id)
for k, v in rot.items():
    if k != 'ResponseMetadata':
        print(f"  {k}: {v}")

print("\n=== ENABLING AUTO-ROTATION ===")
try:
    kms.enable_key_rotation(KeyId=key_id)
    print("  Auto-rotation enabled!")
except Exception as e:
    print(f"  Result: {e}")

print("\n=== PERFORMING ON-DEMAND ROTATION ===")
try:
    result = kms.rotate_key_on_demand(KeyId=key_id)
    print(f"  SUCCESS! KeyId: {result.get('KeyId')}")
except Exception as e:
    print(f"  Result: {e}")

print("\n=== ROTATION STATUS AFTER ===")
rot2 = kms.get_key_rotation_status(KeyId=key_id)
for k, v in rot2.items():
    if k != 'ResponseMetadata':
        print(f"  {k}: {v}")

import botocore
print(f"\nboto3/botocore version: {botocore.__version__}")

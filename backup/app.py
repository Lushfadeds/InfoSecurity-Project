# AWS Lambda
import os
import subprocess
import logging
import psycopg2
import boto3
from datetime import datetime
import hashlib
import math

# Setup Logging with Sensitive Data Filtering
class SensitiveFilter(logging.Filter):
    def filter(self, record):
        msg = record.getMessage()
        secrets = [os.environ.get('SUPABASE_URI'), os.environ.get('RDS_URI')]
        for secret in secrets:
            if secret and secret in msg:
                msg = msg.replace(secret, "[REDACTED]")
        record.msg = msg
        return True

logger = logging.getLogger()
logger.addFilter(SensitiveFilter())
logger.setLevel(logging.INFO)

# AWS S3 Client
s3_client = boto3.client('s3')

# Merkle Tree
def get_merkle_root(file_path):
    CHUNK_SIZE = 1024 * 1024 
    hashes = []

    with open(file_path, 'rb') as f:
        while chunk := f.read(CHUNK_SIZE):
            chunk_hash = hashlib.sha256(chunk).hexdigest()
            hashes.append(chunk_hash)

    if not hashes:
        return hashlib.sha256(b"").hexdigest()

    while len(hashes) > 1:
        new_level = []

        for i in range(0, len(hashes), 2):
            left = hashes[i]

            if i + 1 < len(hashes):
                right = hashes[i + 1]
            else:
                right = left

            combined = left + right
            new_hash = hashlib.sha256(combined.encode()).hexdigest()
            new_level.append(new_hash)
        
        hashes = new_level
    
    return hashes[0]

# Update Backup Log in Supabase
def log_update(log_id, status, download_url=None, merkle_root=None):
    try:
        if not log_id:
            logger.warning("No log ID provided for update.")
            return
        
        conn = psycopg2.connect(os.environ['SUPABASE_URI'])
        cur = conn.cursor()
        update_query = "UPDATE backup_history SET status = %s, file_url = %s, checksum = %s WHERE id = %s"
        cur.execute(update_query, (status, download_url, merkle_root, log_id))
        conn.commit()
        cur.close()
        logger.info(f"Log {log_id} updated to status: {status}")
    except Exception as e:
        logger.error(f"Failed to update log {log_id}: {e}")

# Upload Backup to S3 and Generate Presigned URL
def upload_to_s3(file_path, bucket_name):
    try:
        file_name = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sql"
        
        # 1. Upload
        logger.info(f"Uploading {file_name} to S3...")
        s3_client.upload_file(file_path, bucket_name, file_name)
        
        # 2. Generate Presigned URL (Valid for 7 days = 604800 seconds)
        url = s3_client.generate_presigned_url(
            'get_object',
            Params={'Bucket': bucket_name, 'Key': file_name},
            ExpiresIn=604800 
        )
        return url
    except Exception as e:
        logger.error(f"S3 Upload failed: {e}")
        return None

# Lambda Handler
def lambda_handler(event, context):
    logger.info("Starting Backup Process...")

    SUPABASE_URI = os.environ.get('SUPABASE_URI')
    RDS_URI = os.environ.get('RDS_URI')

    if not SUPABASE_URI or not RDS_URI:
        raise ValueError("Missing Environment Variables")

    S3_BUCKET = os.environ.get('S3_BUCKET')
    TEMP_FILE = "/tmp/backup.sql"

    dump_cmd = f"pg_dump '{SUPABASE_URI}' --clean --if-exists --no-owner --no-acl"
    restore_cmd = f"psql '{RDS_URI}'"

    try:
        logger.info("Dumping to temp file...")
        dump_cmd = f"pg_dump '{SUPABASE_URI}' --clean --if-exists --no-owner --no-acl -f {TEMP_FILE}"
        subprocess.run(dump_cmd, shell=True, check=True, stderr=subprocess.PIPE)

        # Merkle Root Calculation
        logger.info("Calculating Merkle Root...")
        merkle_root = get_merkle_root(TEMP_FILE)

        # Upload to S3
        logger.info("Uploading to S3...")
        download_url = upload_to_s3(TEMP_FILE, S3_BUCKET)

        logger.info("Restoring to RDS...")
        restore_cmd = f"psql '{RDS_URI}' -f {TEMP_FILE}"
        subprocess.run(restore_cmd, shell=True, check=True, stderr=subprocess.PIPE)
        
        # Cleanup
        if os.path.exists(TEMP_FILE): 
            os.remove(TEMP_FILE)
        
        logger.info("Backup Success!")
        log_update(event.get('log_id'), 'Completed', download_url, merkle_root)
        return {"statusCode": 200, "body": "Backup Complete"}
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Backup Failed: {e.stderr.decode()}")
        log_update(event.get('log_id'), 'Failed')
        raise e
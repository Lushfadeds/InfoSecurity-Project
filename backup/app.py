# AWS Lambda
import subprocess
import os
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    logger.info("Starting Backup Process...")
    
    # 1. Get Config
    # Format: postgresql://user:pass@host:5432/dbname
    SUPABASE_URI = os.environ.get('SUPABASE_URI')
    RDS_URI = os.environ.get('RDS_URI')

    if not SUPABASE_URI or not RDS_URI:
        raise ValueError("Missing Environment Variables")

    # 2. Construct Commands
    # --clean: Drop DB objects before creating them (fresh start)
    # --if-exists: Prevents errors if tables don't exist yet
    # --no-owner --no-acl: CRITICAL for moving between cloud providers
    dump_cmd = f"pg_dump '{SUPABASE_URI}' --clean --if-exists --no-owner --no-acl"
    restore_cmd = f"psql '{RDS_URI}'"

    # 3. Execute Pipeline (Dump | Restore)
    try:
        # The pipe symbol '|' sends the output of dump straight into restore
        full_command = f"{dump_cmd} | {restore_cmd}"
        
        subprocess.run(full_command, shell=True, check=True, stderr=subprocess.PIPE)
        
        logger.info("Backup Success!")
        return {"statusCode": 200, "body": "Backup Complete"}
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Backup Failed: {e.stderr.decode()}")
        raise e
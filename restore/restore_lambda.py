# restore_lambda.py — Deploy as a separate AWS Lambda function
# Environment variables required:
#   SUPABASE_URI — PostgreSQL connection string

import os
import re
import subprocess
import logging
import psycopg2
import base64
from datetime import datetime, timezone

class SensitiveFilter(logging.Filter):
    def filter(self, record):
        msg = record.getMessage()
        secret = os.environ.get('SUPABASE_URI')
        if secret and secret in msg:
            record.msg = msg.replace(secret, "[REDACTED]")
        return True

logger = logging.getLogger()
logger.addFilter(SensitiveFilter())
logger.setLevel(logging.INFO)


def log_restore_event(status, initiated_by, error=None):
    try:
        conn = psycopg2.connect(os.environ['SUPABASE_URI'])
        cur  = conn.cursor()
        cur.execute(
            """
            INSERT INTO restore_history (status, initiated_by, error_message, restored_at)
            VALUES (%s, %s, %s, %s)
            """,
            (status, initiated_by, error, datetime.now(timezone.utc).isoformat())
        )
        conn.commit()
        cur.close()
    except Exception as e:
        logger.error(f"Failed to log restore event: {e}")


# Supabase system schemas that belong to supabase_admin — never restorable
# by a regular user. Any statement touching these is skipped entirely.
SUPABASE_SYSTEM_SCHEMAS = {
    'storage', 'graphql', 'graphql_public', 'pg_net',
    'pg_cron', 'pg_graphql', 'pgsodium', 'pgsodium_masks',
    'realtime', 'supabase_functions', 'vault', '_realtime',
    'extensions', 'pgbouncer', 'pgtle',
    'auth',         # Supabase auth schema
    'pg_catalog',   # system catalog
    'information_schema',
}

# Statement types to always skip
OWNERSHIP_PATTERNS = re.compile(
    r'^\s*(ALTER\s+(EVENT\s+TRIGGER|TABLE|SEQUENCE|FUNCTION|SCHEMA|TYPE)\s+\S+\s+OWNER\s+TO|'
    r'CREATE\s+EVENT\s+TRIGGER|'
    r'ALTER\s+EVENT\s+TRIGGER|'
    r'CREATE\s+EXTENSION|'       # extensions are pre-installed by Supabase
    r'COMMENT\s+ON\s+EXTENSION'  # extension comments require superuser
    r')',
    re.IGNORECASE
)


def is_system_statement(statement: str) -> bool:
    """
    Returns True if a SQL statement references a Supabase system schema
    or is an ownership/event-trigger statement that cannot be restored.
    """
    if OWNERSHIP_PATTERNS.search(statement):
        return True
    # Check if any system schema name appears in the statement
    stmt_lower = statement.lower()
    for schema in SUPABASE_SYSTEM_SCHEMAS:
        # Match schema.table or SET search_path = schema patterns
        if re.search(rf'\b{re.escape(schema)}\b', stmt_lower):
            return True
    return False


def filter_sql(sql_text: str) -> str:
    """
    Split the dump into individual statements (split on ';' boundaries
    while respecting $$ dollar-quoted blocks) and discard any that touch
    Supabase system schemas or ownership changes.
    """
    kept       = []
    skipped    = 0
    in_dollars = False
    buffer     = []

    for line in sql_text.splitlines(keepends=True):
        # Track entry/exit of dollar-quoted blocks ($$...$$)
        if '$$' in line:
            in_dollars = not in_dollars

        buffer.append(line)

        # Statement ends at a semicolon outside a dollar-quoted block
        if not in_dollars and line.rstrip().endswith(';'):
            statement = ''.join(buffer)
            if is_system_statement(statement):
                skipped += 1
            else:
                kept.append(statement)
            buffer = []

    # Flush any remaining lines (e.g. trailing comments with no semicolon)
    if buffer:
        remainder = ''.join(buffer)
        if not is_system_statement(remainder):
            kept.append(remainder)

    logger.info(f"SQL filter: kept {len(kept)} statements, skipped {skipped} system statements")
    return '\n'.join(kept)


def lambda_handler(event, context):
    """
    Restores the database from SQL content passed in the event payload.

    Expected payload:
    {
        "sql_content":  "<base64-encoded .sql file contents>",
        "initiated_by": "admin@example.com"
    }
    """
    logger.info("Starting Restore Process...")

    SUPABASE_URI = os.environ.get('SUPABASE_URI')
    if not SUPABASE_URI:
        raise ValueError("SUPABASE_URI environment variable is not set")

    sql_b64      = event.get('sql_content')
    initiated_by = event.get('initiated_by', 'unknown')

    if not sql_b64:
        return {"statusCode": 400, "body": "Missing sql_content in event payload"}

    TEMP_FILE = "/tmp/restore.sql"

    try:
        # Decode and filter out Supabase system statements
        sql_text     = base64.b64decode(sql_b64).decode('utf-8', errors='replace')
        filtered_sql = filter_sql(sql_text)

        with open(TEMP_FILE, 'w', encoding='utf-8') as f:
            f.write(filtered_sql)
        logger.info(f"Written filtered SQL to {TEMP_FILE} ({len(filtered_sql)} chars)")

        # Run psql — without ON_ERROR_STOP so minor warnings don't abort
        result = subprocess.run(
            ["psql", SUPABASE_URI, "--file", TEMP_FILE, "--no-password"],
            capture_output=True,
            text=True,
        )

        if os.path.exists(TEMP_FILE):
            os.remove(TEMP_FILE)

        # Only fail on errors that are NOT harmless Supabase noise
        IGNORED_PHRASES = [
            'must be owner of',
            'already exists',
            'does not exist, skipping',
            'supabase_admin',
            'permission denied for schema auth',
            'permission denied for schema',
            'extension',
            'does not exist',
        ] + list(SUPABASE_SYSTEM_SCHEMAS)

        real_errors = [
            line for line in (result.stderr or '').splitlines()
            if 'ERROR' in line
            and not any(phrase in line for phrase in IGNORED_PHRASES)
        ]

        if real_errors:
            error_msg = '\n'.join(real_errors[:10])
            logger.error(f"Restore errors: {error_msg}")
            log_restore_event('Failed', initiated_by, error=error_msg)
            return {"statusCode": 500, "body": f"Restore failed: {error_msg}"}

        if result.stderr:
            logger.info(f"psql non-fatal output: {result.stderr[:500]}")

        logger.info("Restore completed successfully")
        log_restore_event('Completed', initiated_by)
        return {"statusCode": 200, "body": "Restore complete"}

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        log_restore_event('Failed', initiated_by, error=str(e))
        if os.path.exists(TEMP_FILE):
            os.remove(TEMP_FILE)
        return {"statusCode": 500, "body": str(e)}
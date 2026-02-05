# (moved route to after app = Flask(__name__))
import os
import re
import secrets
import logging
import json
import hashlib
import threading
from io import BytesIO
from uuid import uuid4, UUID
from datetime import datetime, timezone, timedelta
from functools import wraps
import fitz  # PyMuPDF
import spacy
import time

from flask import (
    Flask, render_template, request, redirect, 
    url_for, session, abort, jsonify, flash, send_file
)
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail, Message
from supabase import create_client, Client
from dotenv import load_dotenv

# Optional AWS S3 replication for audit logs
try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
    HAS_BOTO3 = True
except Exception:
    boto3 = None
    HAS_BOTO3 = False

# Import envelope encryption module
from crypto_fields import (
    envelope_encrypt_fields,
    envelope_decrypt_field,
    envelope_decrypt_fields,
    get_profile_with_decryption,
    can_access_record,
    mask_nric,
    encrypt_file,
    decrypt_file,
    generate_data_key,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# --- App + config --------------------------------------------------------
# Load environment variables
load_dotenv()


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-change-me')
csrf = CSRFProtect(app)

# --- Access Control Helpers ---
def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # Check if user is logged in
        user = session.get('user')
        if not user:
            flash('You must be logged in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        return fn(*args, **kwargs)
    return wrapper

# --- Flask-Mail Configuration ---
# Using Port 587 with TLS is generally more compatible with different networks
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')


app.config['APP_KEK'] = os.environ.get('APP_KEK')

# Initialize Supabase with SUPABASE_KEY
# Use Anon/Legacy key by default; service role key only for server-side admin operations
supabase: Client = create_client(
    os.environ.get('SUPABASE_URL'),
    os.environ.get('SUPABASE_KEY')  # Anon key (or service role for admin operations)
)

# Initialize Mail after config is set
mail = Mail(app)
nlp = spacy.load("en_core_web_sm")

# --- Audit Logging (PHI) -------------------------------------------------
AUDIT_LOG_DIR = os.path.join(app.instance_path, "audit")
AUDIT_LOG_PATH = os.path.join(AUDIT_LOG_DIR, "phi_audit.jsonl")
AUDIT_LOG_LOCK = threading.Lock()


def _ensure_audit_log_dir() -> None:
    os.makedirs(AUDIT_LOG_DIR, exist_ok=True)


def _compute_entry_hash(entry: dict) -> str:
    payload = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _get_last_audit_line() -> str | None:
    if not os.path.exists(AUDIT_LOG_PATH):
        return None
    try:
        with open(AUDIT_LOG_PATH, "rb") as f:
            f.seek(0, os.SEEK_END)
            if f.tell() == 0:
                return None
            # Read backwards to find last newline
            offset = min(4096, f.tell())
            f.seek(-offset, os.SEEK_END)
            data = f.read().splitlines()
            if not data:
                return None
            return data[-1].decode("utf-8")
    except Exception as e:
        logger.error(f"Failed to read audit log tail: {e}")
        return None


def _get_last_hash() -> str:
    last_line = _get_last_audit_line()
    if not last_line:
        return ""
    try:
        entry = json.loads(last_line)
        return entry.get("hash", "")
    except Exception:
        return ""


def _append_audit_entry(entry: dict) -> None:
    _ensure_audit_log_dir()
    line = json.dumps(entry, separators=(",", ":")) + "\n"
    # Append-only write
    fd = os.open(AUDIT_LOG_PATH, os.O_APPEND | os.O_CREAT | os.O_WRONLY)
    try:
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
    finally:
        try:
            os.close(fd)
        except Exception:
            pass


def _replicate_audit_to_s3(entry: dict) -> None:
    if not HAS_BOTO3:
        return
    bucket = os.environ.get("AWS_S3_AUDIT_BUCKET")
    region = os.environ.get("AWS_REGION")
    if not bucket or not region:
        return
    storage_class = os.environ.get("AWS_S3_STORAGE_CLASS", "GLACIER")
    try:
        s3 = boto3.client("s3", region_name=region)
        key = f"phi-audit/{entry['timestamp'][:10]}/{entry['event_id']}.json"
        s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=json.dumps(entry, separators=(",", ":")).encode("utf-8"),
            StorageClass=storage_class,
            ContentType="application/json"
        )
    except (BotoCoreError, ClientError) as e:
        logger.error(f"S3 replication failed: {e}")
    except Exception as e:
        logger.error(f"S3 replication error: {e}")


def _insert_audit_to_supabase(entry: dict) -> bool:
    """Insert audit log entry into Supabase audit_logs table. Returns True on success."""
    try:
        # Map entry fields to existing Supabase audit_logs table schema
        # Hash chain stored in 'details' for tamper-evidence verification
        hash_chain_data = {
            "prev_hash": entry.get("prev_hash"),
            "hash": entry.get("hash"),
            "clearance_level": entry.get("clearance_level"),
            "classification": entry.get("classification"),
            "storage": entry.get("storage"),
        }
        if entry.get("extra"):
            hash_chain_data["extra"] = entry.get("extra")
        
        # Prepare new_value as JSON string if target_user_id exists
        new_value_data = None
        if entry.get("target_user_id"):
            new_value_data = json.dumps({"target_user_id": entry.get("target_user_id")})
        
        # Get user agent safely
        user_agent = None
        try:
            if request:
                user_agent = request.headers.get("User-Agent", "")[:500]
        except RuntimeError:
            # Outside request context
            user_agent = "System"
        
        # Determine status with warning support
        status = "Success"
        if not entry.get("allowed"):
            status = "Denied"
        elif entry.get("extra", {}).get("dlp_warning"):
            status = "Warning"
        elif entry.get("extra", {}).get("dlp_blocked"):
            status = "Failed"
        
        # Build resource description from entry
        resource_desc = entry.get("resource_description", "")
        if not resource_desc:
            # Build from action and record_id
            action = entry.get("action", "")
            record_id = entry.get("record_id")
            if record_id:
                resource_desc = f"{action} - {record_id}"
            else:
                resource_desc = action
        
        audit_record = {
            "timestamp": entry.get("timestamp"),
            "user_id": entry.get("user_id"),
            "user_name": entry.get("user_name") or entry.get("role"),
            "action": entry.get("action"),
            "entity_type": entry.get("classification"),
            "entity_id": entry.get("record_id"),
            "old_value": entry.get("old_value"),
            "new_value": new_value_data or entry.get("new_value"),
            "ip_address": entry.get("ip"),
            "user_agent": user_agent,
            "status": status,
            "details": json.dumps(hash_chain_data),
        }
        
        supabase.table("audit_logs").insert(audit_record).execute()
        return True
    except Exception as e:
        logger.error(f"Failed to insert audit log to Supabase: {e}")
        return False


def log_phi_event(
    action: str,
    classification: str,
    record_id: str | None = None,
    target_user_id: str | None = None,
    allowed: bool = True,
    extra: dict | None = None,
    user_name: str | None = None,
    user_id: str | None = None,
    resource_description: str | None = None,
    old_value: str | None = None,
    new_value: str | None = None,
) -> dict:
    """
    Log a PHI-related event with hash chain for immutability.
    
    Args:
        action: The action type (e.g., LOGIN, VIEW_PROFILE, CREATE_APPOINTMENT)
        classification: Data classification (internal, restricted, confidential, critical)
        record_id: ID of the affected record (if any)
        target_user_id: ID of the user being accessed/affected
        allowed: Whether the action was permitted
        extra: Additional context data
        user_name: Display name of the user performing the action
        user_id: Override user_id (for pre-login events)
        resource_description: Human-readable description of the resource
        old_value: Previous value (for updates)
        new_value: New value (for creates/updates)
    """
    user_session = session.get("user") or {}
    
    # Allow overriding user_id and user_name for pre-login events
    effective_user_id = user_id or user_session.get("user_id") or user_session.get("id")
    effective_user_name = user_name or user_session.get("full_name") or user_session.get("role")
    
    entry = {
        "event_id": str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_id": effective_user_id,
        "user_name": effective_user_name,
        "role": user_session.get("role"),
        "clearance_level": user_session.get("clearance_level", "Restricted"),
        "action": action,
        "classification": classification,
        "record_id": record_id,
        "target_user_id": target_user_id,
        "allowed": allowed,
        "ip": request.remote_addr,
        "storage": "append_only_file",
        "resource_description": resource_description,
        "old_value": old_value,
        "new_value": new_value,
    }
    if extra:
        entry["extra"] = extra

    with AUDIT_LOG_LOCK:
        prev_hash = _get_last_hash()
        entry["prev_hash"] = prev_hash
        entry_hash = _compute_entry_hash({k: v for k, v in entry.items() if k != "hash"})
        entry["hash"] = entry_hash
        _append_audit_entry(entry)           # Local append-only file (tamper-evident)
        _insert_audit_to_supabase(entry)     # Supabase audit_logs table
        _replicate_audit_to_s3(entry)        # Optional S3 offsite backup

    analyze_suspicious_activity(entry)
    return entry


def _read_recent_audit_entries(limit: int = 500) -> list[dict]:
    if not os.path.exists(AUDIT_LOG_PATH):
        return []
    try:
        with open(AUDIT_LOG_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()[-limit:]
        entries = []
        for line in lines:
            try:
                entries.append(json.loads(line))
            except Exception:
                continue
        return entries
    except Exception as e:
        logger.error(f"Failed to read audit logs: {e}")
        return []


def analyze_suspicious_activity(latest_entry: dict) -> None:
    user_id = latest_entry.get("user_id")
    if not user_id:
        return

    window_minutes = int(os.environ.get("AUDIT_WINDOW_MINUTES", "5"))
    max_views = int(os.environ.get("AUDIT_MAX_VIEWS", "20"))
    max_high_phi = int(os.environ.get("AUDIT_MAX_HIGH_PHI", "10"))
    max_denied = int(os.environ.get("AUDIT_MAX_DENIED", "3"))

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    entries = _read_recent_audit_entries()
    recent = []
    for e in entries:
        try:
            ts = datetime.fromisoformat(e.get("timestamp"))
        except Exception:
            continue
        if ts >= cutoff and e.get("user_id") == user_id:
            recent.append(e)

    view_actions = {"VIEW_PROFILE", "VIEW_CONSULTATION", "LIST_CONSULTATIONS"}
    high_sensitivity = {"restricted", "confidential"}

    view_count = sum(1 for e in recent if e.get("action") in view_actions and e.get("allowed") is True)
    high_phi_count = sum(
        1 for e in recent
        if e.get("classification") in high_sensitivity and e.get("action") in view_actions
    )
    denied_count = sum(1 for e in recent if e.get("allowed") is False)

    reasons = []
    if view_count >= max_views:
        reasons.append("mass_record_viewing")
    if high_phi_count >= max_high_phi:
        reasons.append("repeated_high_sensitivity_access")
    if denied_count >= max_denied:
        reasons.append("access_above_clearance")

    if reasons:
        alert_entry = {
            "event_id": str(uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_id": user_id,
            "role": latest_entry.get("role"),
            "clearance_level": latest_entry.get("clearance_level"),
            "action": "ALERT",
            "classification": "internal",
            "record_id": latest_entry.get("record_id"),
            "target_user_id": latest_entry.get("target_user_id"),
            "allowed": True,
            "ip": latest_entry.get("ip"),
            "storage": "append_only_file",
            "extra": {
                "reasons": reasons,
                "window_minutes": window_minutes,
                "view_count": view_count,
                "high_phi_count": high_phi_count,
                "denied_count": denied_count,
                "trigger_event_id": latest_entry.get("event_id")
            }
        }
        with AUDIT_LOG_LOCK:
            prev_hash = _get_last_hash()
            alert_entry["prev_hash"] = prev_hash
            alert_hash = _compute_entry_hash({k: v for k, v in alert_entry.items() if k != "hash"})
            alert_entry["hash"] = alert_hash
            _append_audit_entry(alert_entry)           # Local append-only file
            _insert_audit_to_supabase(alert_entry)     # Supabase audit_logs table
            _replicate_audit_to_s3(alert_entry)        # Optional S3 offsite backup


# --- Consultation Queue Management ---
def get_consultation_queue(doctor_id: str, status: str = "waiting") -> list:
    """Fetch waiting patients for a doctor, ordered by appointment time (FIFO)."""
    try:
        queue_response = (
            supabase.table("appointments")
            .select("*")
            .eq("doctor_id", doctor_id)
            .eq("status", status)
            .order("appointment_datetime", desc=False)  # FIFO - earliest first
            .execute()
        )
        return queue_response.data if queue_response.data else []
    except Exception as e:
        logger.error(f"Error fetching consultation queue: {e}")
        return []


def get_queue_position(doctor_id: str, patient_id: str) -> dict | None:
    """Get patient's position in the consultation queue."""
    try:
        queue = get_consultation_queue(doctor_id, status="waiting")
        for idx, appointment in enumerate(queue, start=1):
            if appointment.get("patient_id") == patient_id:
                appointment_time = appointment.get("appointment_time") or appointment.get("appointment_datetime")
                return {
                    "position": idx,
                    "total_waiting": len(queue),
                    "appointment_id": appointment.get("id"),
                    "appointment_time": appointment_time
                }
        return None
    except Exception as e:
        logger.error(f"Error getting queue position: {e}")
        return None


def start_consultation(appointment_id: str, doctor_id: str) -> bool:
    """Mark appointment as in_progress."""
    try:
        update_res = (
            supabase.table("appointments")
            .update({"status": "in_progress"})
            .eq("id", appointment_id)
            .execute()
        )
        
        if update_res.data:
            appointment = update_res.data[0] if isinstance(update_res.data, list) else update_res.data
            
            log_phi_event(
                action="START_CONSULTATION",
                classification="restricted",
                record_id=appointment_id,
                target_user_id=appointment.get("patient_id"),
                allowed=True,
                extra={"doctor_id": doctor_id}
            )
            return True
        return False
    except Exception as e:
        logger.error(f"Error starting consultation: {e}")
        return False


def complete_consultation(appointment_id: str, consultation_data: dict) -> bool:
    """Mark appointment as completed and save consultation record."""
    try:
        appointment_update = (
            supabase.table("appointments")
            .update({"status": "completed"})
            .eq("id", appointment_id)
            .execute()
        )
        
        if appointment_update.data:
            appointment = appointment_update.data[0] if isinstance(appointment_update.data, list) else appointment_update.data
            
            # Combine notes and diagnosis into clinical_notes for encryption
            clinical_notes = f"Diagnosis: {consultation_data.get('diagnosis', '')}\n\nNotes: {consultation_data.get('notes', '')}"
            
            # Encrypt clinical notes using envelope encryption
            phi_fields = {
                'clinical_notes': clinical_notes
            }
            dek_encrypted, encrypted_fields = envelope_encrypt_fields(None, phi_fields)
            
            # Get doctor name from session
            doctor_session = session.get('user')
            doctor_name = doctor_session.get('full_name', 'Unknown')
            
            # Determine classification method
            selected_classification = consultation_data.get("classification", "restricted")
            default_classification = "restricted"
            classification_method = "Automatic" if selected_classification == default_classification else "Manual"
            
            consultation_record = {
                "patient_id": appointment.get("patient_id"),
                "doctor_id": appointment.get("doctor_id"),
                "doctor_name": doctor_name,
                "diagnosis": consultation_data.get("diagnosis", ""),
                "clinical_notes_encrypted": encrypted_fields.get("clinical_notes_encrypted", ""),
                "treatment_plan": consultation_data.get("treatment", ""),
                "classification": selected_classification,
                "classification_method": classification_method,
                "dek_encrypted": dek_encrypted,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "expiry_date": calculate_expiry_date(None, 90)
            }
            
            supabase.table("consultations").insert(consultation_record).execute()
            
            log_phi_event(
                action="COMPLETE_CONSULTATION",
                classification="confidential",
                record_id=appointment_id,
                target_user_id=appointment.get("patient_id"),
                allowed=True
            )
            return True
        return False
    except Exception as e:
        logger.error(f"Error completing consultation: {e}")
        return False


def verify_audit_chain() -> dict:
    entries = _read_recent_audit_entries(limit=100000)
    prev_hash = ""
    errors = []
    for idx, entry in enumerate(entries):
        expected_prev = entry.get("prev_hash", "")
        if expected_prev != prev_hash:
            errors.append({"index": idx, "event_id": entry.get("event_id"), "reason": "prev_hash_mismatch"})
            break
        recomputed = _compute_entry_hash({k: v for k, v in entry.items() if k != "hash"})
        if recomputed != entry.get("hash"):
            errors.append({"index": idx, "event_id": entry.get("event_id"), "reason": "hash_mismatch"})
            break
        prev_hash = entry.get("hash", "")
    return {"valid": len(errors) == 0, "errors": errors, "count": len(entries)}

# --- Data Retention Helpers ---
def calculate_expiry_date(creation_date: str | None = None, retention_days: int = 90) -> str:
    """Calculate expiry date as retention_days from creation date (default 90 days)."""
    if creation_date:
        try:
            created_dt = datetime.fromisoformat(creation_date.replace("Z", "+00:00"))
        except Exception:
            created_dt = datetime.now(timezone.utc)
    else:
        created_dt = datetime.now(timezone.utc)
    
    expiry_dt = created_dt + timedelta(days=retention_days)
    return expiry_dt.isoformat()

def is_retention_expired(expiry_date: str | None) -> bool:
    """Check if data retention period has expired."""
    if not expiry_date:
        return False
    try:
        expiry_dt = datetime.fromisoformat(expiry_date.replace("Z", "+00:00"))
        return datetime.now(timezone.utc) >= expiry_dt
    except Exception:
        return False

# --- Access Control Helpers ---
def _is_valid_uuid(value):
    """Validate if a string is a valid UUID format."""
    if not isinstance(value, str):
        return False
    try:
        UUID(value)
        return True
    except (ValueError, AttributeError, TypeError):
        return False


def _get_staff_display_name(user_session: dict | None) -> str:
    if not user_session:
        return "Staff User"

    staff_id = user_session.get('user_id') or user_session.get('id')
    if staff_id:
        try:
            staff_res = (
                supabase.table("staff_profile")
                .select("full_name")
                .eq("id", staff_id)
                .single()
                .execute()
            )
            if staff_res.data and staff_res.data.get("full_name"):
                return staff_res.data.get("full_name")
        except Exception as e:
            logger.warning(f"Could not fetch staff_profile name for {staff_id}: {e}")

    if staff_id:
        try:
            profile_res = (
                supabase.table("profiles")
                .select("full_name")
                .eq("id", staff_id)
                .single()
                .execute()
            )
            if profile_res.data and profile_res.data.get("full_name"):
                return profile_res.data.get("full_name")
        except Exception as e:
            logger.warning(f"Could not fetch profiles name for {staff_id}: {e}")

    return user_session.get("full_name") or "Staff User"


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return wrapper

# --- Data Masking Logic ---
def apply_policy_masking(user_session, record):
    masked_out = record.copy()
    user_role = str(user_session.get('role', '')).lower()

    if user_role == 'patient':
        # 1. NRIC MASKING (Check for 'nric' or 'NRIC')
        nric_val = record.get('nric') or record.get('NRIC')
        if nric_val:
            nric_pattern = r"^([A-Z])\d{4}(\d{3}[A-Z])$"
            masked_nric = re.sub(nric_pattern, r"\1****\2", str(nric_val))
            # Force overwrite both so Alpine.js toggle fails to show real ID
            masked_out['nric'] = masked_nric
            masked_out['nric_masked'] = masked_nric

        # 2. PHONE MASKING
        phone_val = record.get('phone') or record.get('mobile_number')
        if phone_val:
            masked_out['phone_masked'] = re.sub(r"^(\d{2})\d+(\d{2})$", r"\1****\2", str(phone_val))

        # 3. EMAIL MASKING
        email_val = record.get('email')
        if email_val:
            masked_out['email_masked'] = re.sub(r"(^[^@]).+([^@]@)", r"\1****\2", str(email_val))
        
        # --- 2. Date of Birth (Masking Year) ---
        # Rule: Show day/month, mask year (e.g., 2026-01-29 -> ****-01-29)
        dob_val = record.get('dob')
        if dob_val:
            masked_out['dob_masked'] = re.sub(r".", "*", str(dob_val))

        # --- 3. Emergency Contact Phone ---
        # Rule: Same as personal phone (e.g., 87654321 -> 87****21)
        e_phone = record.get('emergency_phone')
        if e_phone:
            masked_out['emergency_phone_masked'] = re.sub(r"^(\d{2})\d+(\d{2})$", r"\1****\2", str(e_phone))

        # --- 4. Address (Masking Numbers) ---
        # Rule: Replace all digits with '*' (e.g., BLK 120A -> BLK ***A)
        addr_val = record.get('address')
        if addr_val:
            masked_out['address_masked'] = re.sub(r"\d", "*", str(addr_val))

        return masked_out
    
    # If role is 'doctor' or 'admin', we masked out the important records.

    if user_role in ('doctor'):
        # MCR Number masking (e.g., M12345 -> M***45)
        mcr_val = record.get('mcr_number')
        if mcr_val and mcr_val != 'N/A':
            masked_out['mcr_number'] = re.sub(r'^([A-Z])(\d+)(\d{2})$', r'\1***\3', str(mcr_val))
        
        # Email masking (e.g., john.doe@email.com -> j****@email.com)
        email_val = record.get('email')
        if email_val:
            masked_out['email'] = re.sub(r"(^[^@]).+([^@]@)", r"\1****\2", str(email_val))
    
        return masked_out
    
    # For Admin only User-management related masking
    if user_role in ('admin'):
        nric_val = record.get('nric') or record.get('NRIC')
        if nric_val:
            nric_pattern = r"^([A-Z])\d{4}(\d{3}[A-Z])$"
            masked_nric = re.sub(nric_pattern, r"\1****\2", str(nric_val))
            # Force overwrite both so Alpine.js toggle fails to show real ID
            masked_out['nric'] = masked_nric
            masked_out['nric_masked'] = masked_nric

        # Phone masking
        phone_val = record.get('phone') or record.get('mobile_number')
        if phone_val:
            masked_out['mobile_number'] = re.sub(r"^(\d{2})\d+(\d{2})$", r"\1****\2", str(phone_val))

    return masked_out

# --- Tokenization for Sensitive IDs ---
def generate_token(record_type: str = "mc") -> str:
    """
    Generate a unique tokenized ID for medical records.

    Args:
        record_type: Type of record to tokenize. Accepts:
            - 'mc' or 'medical_certificate' → MC-{10-digit-number}
            - 'rx' or 'prescription' → RX-{10-digit-number}
    
    Returns:
        Tokenized ID with format: PREFIX-{10-digit-number}
        Example: MC-1373149560
    """
    # Map record types to prefixes
    prefix_map = {
        'mc': 'MC',
        'medical_certificate': 'MC',
        'rx': 'RX',
        'prescription': 'RX',
    }
    
    # Get prefix from map, default to MC if not found
    prefix = prefix_map.get(record_type.lower(), 'MC')
    
    # Generate 10-digit numeric ID from cryptographic hash
    hash_input = f"{prefix}{datetime.now(timezone.utc).isoformat()}{secrets.token_hex(8)}".encode()
    numeric_suffix = str(int(hashlib.sha256(hash_input).hexdigest(), 16) % 10000000000).zfill(10)
    
    return f"{prefix}-{numeric_suffix}"

# --- Data Loss Prevention (DLP) ---
def run_dlp_security_service(file, user_session):
    """Run DLP checks on uploaded file to detect PHI."""
    text = ""
    file_ext = file.filename.rsplit('.', 1)[-1].lower()
    try:
        file_content = file.read()
        file.seek(0) # Reset immediately after reading
        
        if file_ext == 'pdf':
            doc = fitz.open(stream=file_content, filetype="pdf")
            for page in doc:
                text += page.get_text()
        else:
            # If it's an image, we'd need OCR (Tesseract), 
            # for now, we'll treat text-less images as 'Clean' or skip
            text = "" 
            
    except Exception as e:
        print(f"Extraction Error: {e}")
        return {
            "audit_id": f"AUDIT-{time.strftime('%Y%m%d')}-{secrets.token_hex(2).upper()}",
            "phi_tags": "Extraction Failed - File Format Error",
            "findings": [],
            "error": str(e)
        }

    findings = []

    def _add_finding(finding_id: str, name: str, finding_type: str) -> None:
        if any(f.get("id") == finding_id for f in findings):
            return
        findings.append({"id": finding_id, "name": name, "type": finding_type})

    # NRIC Check (Singapore NRIC/FIN pattern)
    if re.search(r"\b[STFG]\d{7}[A-Z]\b", text, re.IGNORECASE):
        logger.info("DLP: NRIC pattern detected in document")
        _add_finding("NRIC_FIN", "NRIC/Medical Record Number", "CRITICAL")

    # Email detection
    if re.search(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", text, re.IGNORECASE):
        logger.info("DLP: Email address detected in document")
        _add_finding("EMAIL", "Email Address", "SENSITIVE")

    # Phone Check (Singapore mobile numbers, with optional +65)
    if re.search(r"\b(?:\+65\s?)?(?:[689]\d{7})\b", text):
        logger.info("DLP: Phone number detected in document")
        _add_finding("PHONE_SG", "Mobile Number", "SENSITIVE")

    # Address detection (keyword + number heuristic)
    address_keyword = re.search(
        r"\b(?:blk|block|street|st|road|rd|avenue|ave|lane|ln|jalan|drive|dr|unit|#|floor|level)\b",
        text,
        re.IGNORECASE,
    )
    if address_keyword and re.search(r"\b\d{1,5}\b", text):
        logger.info("DLP: Address pattern detected in document")
        _add_finding("ADDRESS", "Address", "SENSITIVE")

    # DOB detection
    if re.search(r"\b(?:dob|date\s*of\s*birth|birth\s*date|d\.o\.b\.)\b", text, re.IGNORECASE):
        logger.info("DLP: Date of birth label detected in document")
        _add_finding("DOB", "Date of Birth", "SENSITIVE")

    # NLP Name Detection (Person entities only)
    doc_nlp = nlp(text)
    for ent in doc_nlp.ents:
        if ent.label_ == "PERSON":
            logger.info(f"DLP: PERSON entity detected: {ent.text}")
            _add_finding("PERSON_NAME", "Patient Name/Identity", "SENSITIVE")
            break  # Only add once to avoid duplicates

    # PHI keyword detection (clinical context)
    phi_keywords = [
        "allergy", "allergies", "diagnosis", "diagnoses", "chief complaint",
        "history of present illness", "past medical history", "pmh", "medication",
        "medications", "prescription", "rx", "dosage", "dose", "mg", "ml",
        "mcg", "units", "blood pressure", "bp", "temperature", "pulse",
        "respiration", "spo2", "lab", "laboratory", "radiology", "x-ray",
        "ct", "mri", "ultrasound", "clinic", "hospital", "ward", "admission",
        "discharge", "progress note", "soap", "assessment", "plan",
        "doctor", "physician", "nurse", "patient",
    ]
    phi_pattern = r"\b(?:" + "|".join([re.escape(k) for k in phi_keywords]) + r")\b"
    if re.search(phi_pattern, text, re.IGNORECASE):
        logger.info("DLP: Clinical keywords detected in document")
        _add_finding("CLINICAL_KEYWORDS", "Clinical/Medical Content", "PHI")

    # Generate audit tracking ID
    audit_id = f"AUDIT-{time.strftime('%Y%m%d')}-{secrets.token_hex(3).upper()}"
    
    # Create PHI tags summary
    phi_tags = ", ".join(list(set([f['name'] for f in findings]))) if findings else "No PHI Detected"
    
    if any(f['type'] == 'CRITICAL' for f in findings):
        classification = "confidential"
        severity = "critical"
        status = "flagged" # Matches your dashboard logic
    elif any(f['type'] in {"SENSITIVE", "PHI"} for f in findings):
        classification = "restricted"
        severity = "high"
        status = "flagged"
    else:
        classification = "internal"
        severity = "low"
        status = "allowed"
    
    # Return classification and metadata
    try:
        user_display = user_session.get("full_name") or "Unknown"
        user_role = user_session.get("role") or "unknown"

        dlp_event = {
            "Timestamps": datetime.now(timezone.utc).isoformat(),
            "user": user_display,
            "role": user_role,
            "action": f"UPLOAD_{classification.upper()}",
            "Data_type": phi_tags,
            "severity": severity,
            "status": status,
            "details": f"File: {file.filename} | ID: {audit_id}"
        }
        supabase.table("DLP_events").insert(dlp_event).execute()
    except Exception as e:
        logger.error(f"Failed to insert DLP event: {e}")

    return {
        "audit_id": audit_id,
        "classification": classification,
        "phi_tags": phi_tags,
        "dlp_status": f"Scanned: {classification.title()}",
        "severity": severity,
        "status": status
    }



@app.context_processor
def inject_globals():
    from datetime import timezone
    return {'current_user': session.get('user'), 'current_year': datetime.now(timezone.utc).year}

# --- Routes ---
@app.route('/')
def index():
    # Fetch public administrative broadcasts for home page
    broadcasts = []
    try:
        broadcasts_res = (
            supabase.table("administrative")
            .select("id, title, description, record_type, staff_id, created_at")
            .eq("classification", "public")
            .eq("is_deleted", 0)
            .order("created_at", desc=True)
            .limit(10)
            .execute()
        )

        if broadcasts_res.data:
            staff_ids = list({rec.get("staff_id") for rec in broadcasts_res.data if rec.get("staff_id")})
            admin_ids = [rec.get("id") for rec in broadcasts_res.data]

            staff_name_map = {}
            if staff_ids:
                try:
                    staff_profile_res = supabase.table("staff_profile").select("id, full_name").in_("id", staff_ids).execute()
                    if staff_profile_res.data:
                        for staff in staff_profile_res.data:
                            staff_name_map[staff['id']] = staff.get('full_name', 'Unknown Staff')
                except Exception as e:
                    logger.warning(f"Failed to fetch staff names from staff_profile: {e}")

                missing_staff_ids = [sid for sid in staff_ids if sid not in staff_name_map]
                if missing_staff_ids:
                    try:
                        profiles_res = supabase.table("profiles").select("id, full_name").in_("id", missing_staff_ids).execute()
                        if profiles_res.data:
                            for profile in profiles_res.data:
                                staff_name_map[profile['id']] = profile.get('full_name', 'Unknown Staff')
                    except Exception as e:
                        logger.warning(f"Failed to fetch staff names from profiles: {e}")

            attachments_map = {}
            if admin_ids:
                try:
                    attachments_res = (
                        supabase.table("administrative_attachments")
                        .select("id, administrative_id, filename, file_size")
                        .in_("administrative_id", admin_ids)
                        .eq("is_deleted", 0)
                        .execute()
                    )
                    if attachments_res.data:
                        for attachment in attachments_res.data:
                            admin_id = attachment.get("administrative_id")
                            if admin_id not in attachments_map:
                                attachments_map[admin_id] = []
                            attachments_map[admin_id].append({
                                'id': attachment.get('id'),
                                'filename': attachment.get('filename'),
                                'file_size': attachment.get('file_size')
                            })
                except Exception as e:
                    logger.warning(f"Failed to fetch attachments: {e}")

            for record in broadcasts_res.data:
                staff_id = record.get('staff_id')
                uploaded_by = staff_name_map.get(staff_id, 'Unknown Staff')
                created_at = record.get('created_at', '')
                formatted_time = _format_creation_time(created_at)

                broadcasts.append({
                    'id': record.get('id'),
                    'record_type': record.get('record_type'),
                    'title': record.get('title'),
                    'description': record.get('description'),
                    'uploaded_by': uploaded_by,
                    'created_at': formatted_time,
                    'attachments': attachments_map.get(record.get('id'), [])
                })
    except Exception as e:
        logger.error(f"Error loading public administrative broadcasts: {e}")

    return render_template('public/index.html', broadcasts=broadcasts)

@app.route('/about')
def about():
    return render_template('public/about.html')

@app.route('/contact')
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        return render_template('public/contact.html', submitted=True, name=name)
    return render_template('public/contact.html', submitted=False)

@app.route('/faq')
def faq():
    return render_template('public/faq.html')

@app.route('/announcements')
def announcements():
    return render_template('public/announcements.html')

@app.route('/signup')
def signup():
    return render_template('auth/signup.html')

@app.route('/send_registration_otp', methods=['POST'])
def send_registration_otp():
    email = request.form.get('email')
    otp = str(secrets.randbelow(899999) + 100000)
    session['reg_otp'] = otp
    session['temp_reg_data'] = request.form.to_dict()
    
    try:
        msg = Message("PinkHealth - Registration OTP", recipients=[email])
        msg.body = f"Welcome to PinkHealth! Your verification code is: {otp}"
        mail.send(msg)
        return jsonify({"success": True})
    except Exception as e:
        # Check your VS Code Terminal to see the actual error message
        print(f"CRITICAL SMTP ERROR: {str(e)}")
        return jsonify({"success": False, "message": f"Mail error: {str(e)}"}), 500

@app.route('/final_register', methods=['POST'])
def final_register():
    user_otp = request.form.get('otp')
    if user_otp != session.get('reg_otp'):
        return jsonify({"success": False, "message": "Invalid verification code"}), 400
    
    data = session.get('temp_reg_data')
    if not data:
        return jsonify({"success": False, "message": "Session expired"}), 400
    
    # Enforce required fields
    required_fields = [
        'fullName', 'nric', 'phone', 'dob', 'postal_code', 'email', 'password'
    ]
    missing = [f for f in required_fields if not data.get(f)]
    if missing:
        return jsonify({"success": False, "message": f"Missing required fields: {', '.join(missing)}"}), 400

    try:
        auth_res = supabase.auth.sign_up({
            "email": data['email'],
            "password": data['password'],
            "options": {"email_confirm": False}
        })

        if auth_res.user:
            # Encrypt PHI fields using envelope encryption
            phi_fields = {
                'nric': data.get('nric', ''),
                'phone': data.get('phone', ''),
                'address': data.get('address', '') or '',
                'dob': data.get('dob', '') or '',
                'postal_code': data.get('postal_code', '') or ''
            }

            # Generate DEK and encrypt fields (no existing DEK for new user)
            dek_encrypted, encrypted_fields = envelope_encrypt_fields(None, phi_fields)

            # Normalize optional fields
            profile_entry = {
                "id": auth_res.user.id,
                "full_name": data.get('fullName', '') or '',
                "email": data.get('email', '') or '',
                "nric_encrypted": encrypted_fields.get('nric_encrypted', ''),
                "phone_encrypted": encrypted_fields.get('phone_encrypted', ''),
                "address_encrypted": encrypted_fields.get('address_encrypted', ''),
                "dob_encrypted": encrypted_fields.get('dob_encrypted', ''),
                "postal_code_encrypted": encrypted_fields.get('postal_code_encrypted', ''),
                "dek_encrypted": dek_encrypted,
                "clinic_id": None,
                "blood_type": data.get('blood_type', '') or '',
                "emergency_name": data.get('emergency_name', '') or '',
                "emergency_relationship": data.get('emergency_relationship', '') or '',
                "emergency_phone": data.get('emergency_phone', '') or '',
                "nationality": data.get('nationality', '') or '',
                "gender": data.get('gender', '') or ''
            }

            supabase.table("patient_profile").insert(profile_entry).execute()

            # profiles table: Only store non-PHI fields (role, clearance, name)
            # PHI (nric, phone) is stored encrypted in patient_profile only
            supabase.table("profiles").insert({
                "id": auth_res.user.id,
                "full_name": data.get('fullName', '') or '',
                "clearance_level": "Restricted",
                "role": "patient"
            }).execute()

            logger.info(f"User registered with encrypted PHI: {auth_res.user.id}")
            
            # Log account creation
            log_phi_event(
                action="ACCOUNT_CREATE",
                classification="restricted",
                record_id=auth_res.user.id,
                target_user_id=auth_res.user.id,
                allowed=True,
                user_id=auth_res.user.id,
                user_name=data.get('fullName', ''),
                resource_description=f"New Patient Account - {data.get('fullName', '')}",
                extra={"role": "patient", "email": data.get('email', '')}
            )

            session.pop('reg_otp', None)
            session.pop('temp_reg_data', None)
            return jsonify({"success": True})

    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        # Log failed registration
        log_phi_event(
            action="ACCOUNT_CREATE_FAILED",
            classification="internal",
            allowed=False,
            user_name=data.get('fullName', '') if data else 'Unknown',
            resource_description="Account Registration",
            extra={"email": data.get('email', '') if data else '', "reason": str(e)[:100]}
        )
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/reset_password')
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email')
        return render_template('auth/reset-password.html', submitted=True, email=email)
    return render_template('auth/reset-password.html', submitted=False)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        try:
            # 1. Sign in with Supabase Auth
            auth_res = supabase.auth.sign_in_with_password({"email": email, "password": password})
            if auth_res.user:
                # 2. Get the user's profile from the 'profiles' table
                profile_res = (
                    supabase.table("profiles")
                    .select("*")
                    .eq("id", auth_res.user.id)
                    .single()
                    .execute()
                )

                if profile_res.data:
                    profile = profile_res.data
                    role = profile.get('role', 'patient')
                    clinic_id = profile.get('clinic_id')
                    full_name = profile.get('full_name', '')
                    
                    # 3. Set session with proper structure for access control
                    # Store minimal session data - encrypted fields stay in DB
                    session['user'] = {
                        'user_id': auth_res.user.id,
                        'id': auth_res.user.id,  # Keep 'id' for backward compatibility
                        'email': auth_res.user.email,
                        'role': role,
                        'clearance_level': 'Restricted',
                        'clinic_id': clinic_id,
                        'patient_id': auth_res.user.id,  # For patient access control
                        'full_name': full_name,
                    }
                    session['login_password'] = password
                    
                    logger.info(f"User logged in: {auth_res.user.id}, role: {role}")
                    
                    # Log successful login
                    log_phi_event(
                        action="LOGIN",
                        classification="internal",
                        record_id=auth_res.user.id,
                        target_user_id=auth_res.user.id,
                        allowed=True,
                        user_id=auth_res.user.id,
                        user_name=full_name or email,
                        resource_description="Authentication System",
                        extra={"role": role, "method": "password"}
                    )
                    
                    # 4. Redirect based on role
                    if role == "patient":
                        return redirect(url_for("patient_dashboard"))
                    elif role == "doctor":
                        return redirect(url_for("doctor_dashboard"))
                    elif role == "staff":
                        return redirect(url_for("staff_dashboard"))
                    elif role == "pharmacy":
                        return redirect(url_for("pharmacy_dashboard"))
                    elif role == "admin":
                        return redirect(url_for("admin_dashboard"))
                    else:
                        return redirect(url_for("patient_dashboard"))

        except Exception as e:
            logger.error(f"Login failed: {e}")
            # Log failed login attempt
            log_phi_event(
                action="LOGIN_FAILED",
                classification="internal",
                allowed=False,
                user_name=email,
                resource_description="Authentication System",
                extra={"email": email, "reason": str(e)[:100]}
            )
            flash("Invalid email or password", "error")

    # Keep 'auth/' since your login.html is in that folder
    return render_template("auth/login.html")

@app.route('/patient-dashboard')
@login_required
def patient_dashboard():
    user_session = session.get('user')
    user_id = user_session.get('user_id') or user_session.get('id')
    
    # Fetch profile with encrypted fields from Supabase
    try:
        profile_res = (
            supabase.table("patient_profile")
            .select("*")
            .eq("id", user_id)
            .single()
            .execute()
        )
        
        if profile_res.data:
            # Decrypt PHI fields based on access control
            profile_data = get_profile_with_decryption(profile_res.data, user_session)
            # Apply additional masking based on role
            masked_data = apply_policy_masking(user_session, profile_data)

            return render_template('patient/patient-dashboard.html', user=masked_data)
        else:
            flash("Profile not found", "error")
            return redirect(url_for('login'))
            
    except Exception as e:
        logger.error(f"Error fetching patient dashboard: {e}")
        flash("Error loading profile", "error")
        return redirect(url_for('login'))

@app.route('/doctor-dashboard')
@login_required
def doctor_dashboard():
    user_session = session.get('user')
    doctor_id = user_session.get('user_id') or user_session.get('id')
    doctor_email = user_session.get('email')
    
    logger.info(f"Doctor dashboard accessed by doctor_id: {doctor_id}")
    
    # Fetch doctor profile information
    doctor_name = "Doctor"
    doctor_specialty = "General Practitioner"
    try:
        if doctor_email:
            profile_res = (
                supabase.table("doctor_profile")
                .select("full_name, specialty")
                .eq("email", doctor_email)
                .single()
                .execute()
            )
            if profile_res.data:
                doctor_name = profile_res.data.get('full_name', 'Doctor')
                doctor_specialty = profile_res.data.get('specialty', 'General Practitioner')
    except Exception as e:
        logger.warning(f"Failed to fetch doctor profile: {e}")
    
    # Get consultation queue for the doctor - waiting, in_progress, completed
    waiting_queue = get_consultation_queue(doctor_id, status="waiting")
    in_progress_queue = get_consultation_queue(doctor_id, status="in_progress")
    completed_queue = get_consultation_queue(doctor_id, status="completed")
    
    logger.info(
        f"Queue fetched: {len(waiting_queue)} waiting appointments, {len(in_progress_queue)} in progress, {len(completed_queue)} completed"
    )
    queue_display = []
    
    # Process in_progress appointments first (so they appear at top)
    for appointment in in_progress_queue:
        try:
            logger.debug(f"Processing in_progress appointment: {appointment.get('id')}, patient_id: {appointment.get('patient_id')}")
            patient_res = supabase.table("patient_profile").select("full_name").eq("id", appointment.get("patient_id")).single().execute()
            
            if patient_res.data:
                patient = patient_res.data
                logger.debug(f"Patient found: {patient.get('full_name')}")
                
                queue_display.append({
                    "appointment_id": appointment.get("id"),
                    "patient_name": patient.get("full_name", "Unknown"),
                    "patient_id": appointment.get("patient_id"),
                    "appointment_time": appointment.get("appointment_datetime"),
                    "visit_type": appointment.get("visit_type", "General"),
                    "booked_at": appointment.get("created_at"),
                    "status": "in_progress",
                    "action_label": "Continue",
                    "action_url": url_for('start_consultation_route', appointment_id=appointment.get("id"))
                })
            else:
                logger.warning(f"Patient not found for appointment {appointment.get('id')}")
        except Exception as e:
            logger.warning(f"Could not fetch patient for appointment {appointment.get('id')}: {e}")
    
    # Process waiting appointments
    for appointment in waiting_queue:
        try:
            logger.debug(f"Processing appointment: {appointment.get('id')}, patient_id: {appointment.get('patient_id')}")
            patient_res = supabase.table("patient_profile").select("full_name").eq("id", appointment.get("patient_id")).single().execute()
            
            if patient_res.data:
                patient = patient_res.data
                logger.debug(f"Patient found: {patient.get('full_name')}")
                
                queue_display.append({
                    "appointment_id": appointment.get("id"),
                    "patient_name": patient.get("full_name", "Unknown"),
                    "patient_id": appointment.get("patient_id"),
                    "appointment_time": appointment.get("appointment_datetime"),
                    "visit_type": appointment.get("visit_type", "General"),
                    "booked_at": appointment.get("created_at"),
                    "status": "waiting",
                    "action_label": "Start",
                    "action_url": url_for('start_consultation_route', appointment_id=appointment.get("id"))
                })
            else:
                logger.warning(f"Patient not found for appointment {appointment.get('id')}")
        except Exception as e:
            logger.warning(f"Could not fetch patient for appointment {appointment.get('id')}: {e}")

    # Process completed appointments
    for appointment in completed_queue:
        try:
            logger.debug(f"Processing completed appointment: {appointment.get('id')}, patient_id: {appointment.get('patient_id')}")
            patient_res = supabase.table("patient_profile").select("full_name").eq("id", appointment.get("patient_id")).single().execute()

            if patient_res.data:
                patient = patient_res.data
                logger.debug(f"Patient found: {patient.get('full_name')}")

                queue_display.append({
                    "appointment_id": appointment.get("id"),
                    "patient_name": patient.get("full_name", "Unknown"),
                    "patient_id": appointment.get("patient_id"),
                    "appointment_time": appointment.get("appointment_datetime"),
                    "visit_type": appointment.get("visit_type", "General"),
                    "booked_at": appointment.get("created_at"),
                    "status": "completed",
                    "action_label": "View",
                    "action_url": url_for('verify_consultation_password')
                })
            else:
                logger.warning(f"Patient not found for appointment {appointment.get('id')}")
        except Exception as e:
            logger.warning(f"Could not fetch patient for appointment {appointment.get('id')}: {e}")
    
    logger.info(f"Queue display prepared: {len(queue_display)} patients to display")
    
    log_phi_event(
        action="VIEW_DASHBOARD",
        classification="internal",
        allowed=True,
        extra={"queue_size": len(queue_display), "waiting": len(waiting_queue), "in_progress": len(in_progress_queue)}
    )
    
    return render_template('doctor/doctor-dashboard.html', 
                           queue=queue_display,
                           queue_count=len(queue_display),
                           doctor_name=doctor_name,
                           doctor_specialty=doctor_specialty)


@app.route('/doctor/data-erasure', methods=['GET', 'POST'])
@login_required
def doctor_data_erasure():
    user_session = session.get('user')
    doctor_id = user_session.get('user_id') or user_session.get('id')

    if request.method == 'POST':
        selected_docs = request.form.getlist('documents')
        reason = request.form.get('reason', '').strip()

        if not selected_docs:
            flash('Please select at least one document to erase.', 'error')
            return redirect(url_for('doctor_data_erasure'))

        if not reason:
            flash('Reason for erasure is required.', 'error')
            return redirect(url_for('doctor_data_erasure'))

        try:
            payload = {
                "requester_id": doctor_id,
                "requester_role": "doctor",
                "status": "pending",
                "reason": reason,
                "documents": selected_docs,
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            insert_res = supabase.table("data_erasure_requests").insert(payload).execute()

            if not insert_res.data:
                flash('Failed to submit erasure request. Please try again.', 'error')
            else:
                flash('Erasure request submitted successfully.', 'success')

            return redirect(url_for('doctor_data_erasure'))
        except Exception as e:
            logger.error(f"Error submitting erasure request: {e}")
            flash('Error submitting erasure request.', 'error')
            return redirect(url_for('doctor_data_erasure'))

    documents = []
    patient_ids = set()
    try:
        consultations_res = (
            supabase.table("consultations")
            .select("id, created_at, patient_id, classification")
            .eq("doctor_id", doctor_id)
            .order("created_at", desc=True)
            .execute()
        )
        if consultations_res.data:
            for row in consultations_res.data:
                patient_id = row.get('patient_id')
                if patient_id:
                    patient_ids.add(patient_id)
                documents.append({
                    "value": f"consultations:{row.get('id')}",
                    "title": "Consultation",
                    "type": "consultation",
                    "patient_id": patient_id,
                    "classification": row.get('classification', 'internal'),
                    "created_at": _format_creation_time(row.get('created_at', ''))
                })

        prescriptions_res = (
            supabase.table("prescriptions")
            .select("id, created_at, patient_id, classification")
            .eq("doctor_id", doctor_id)
            .order("created_at", desc=True)
            .execute()
        )
        if prescriptions_res.data:
            for row in prescriptions_res.data:
                patient_id = row.get('patient_id')
                if patient_id:
                    patient_ids.add(patient_id)
                documents.append({
                    "value": f"prescriptions:{row.get('id')}",
                    "title": "Prescription",
                    "type": "prescription",
                    "patient_id": patient_id,
                    "classification": row.get('classification', 'internal'),
                    "created_at": _format_creation_time(row.get('created_at', ''))
                })

        mc_res = (
            supabase.table("medical_certificates")
            .select("id, created_at, patient_id, classification")
            .eq("doctor_id", doctor_id)
            .order("created_at", desc=True)
            .execute()
        )
        if mc_res.data:
            for row in mc_res.data:
                patient_id = row.get('patient_id')
                if patient_id:
                    patient_ids.add(patient_id)
                documents.append({
                    "value": f"medical_certificates:{row.get('id')}",
                    "title": "Medical Certificate",
                    "type": "medical_certificate",
                    "patient_id": patient_id,
                    "classification": row.get('classification', 'internal'),
                    "created_at": _format_creation_time(row.get('created_at', ''))
                })
    except Exception as e:
        logger.error(f"Error loading documents for erasure: {e}")

    patient_name_map = {}
    patient_nric_map = {}
    if patient_ids:
        try:
            patient_res = (
                supabase.table("patient_profile")
                .select("id, full_name, nric_encrypted, dek_encrypted")
                .in_("id", list(patient_ids))
                .execute()
            )
            if patient_res.data:
                for row in patient_res.data:
                    patient_id = row.get('id')
                    patient_name_map[patient_id] = row.get('full_name', 'Unknown')
                    
                    # Decrypt NRIC using envelope decryption
                    try:
                        nric_decrypted = envelope_decrypt_field(row.get('dek_encrypted', ''), row.get('nric_encrypted', ''))
                        if nric_decrypted:
                            # Mask format: First letter + **** + Last 4 characters
                            # Example: S1234567A -> S****567A
                            masked_nric = re.sub(r'^(.)(.*?)(....)$', r'\1****\3', str(nric_decrypted))
                            patient_nric_map[patient_id] = masked_nric
                        else:
                            patient_nric_map[patient_id] = "N/A"
                    except Exception as e:
                        logger.warning(f"Could not decrypt NRIC for patient {patient_id}: {e}")
                        patient_nric_map[patient_id] = "N/A"
        except Exception as e:
            logger.warning(f"Failed to fetch patient data for erasure list: {e}")

    for doc in documents:
        doc["patient_name"] = patient_name_map.get(doc.get("patient_id"), "Unknown")
        doc["masked_nric"] = patient_nric_map.get(doc.get("patient_id"), "N/A")

    # Fetch pending/approved erasure requests and extract already-requested document IDs
    requested_doc_ids = set()
    try:
        all_requests_res = (
            supabase.table("data_erasure_requests")
            .select("documents, status")
            .eq("requester_id", doctor_id)
            .in_("status", ["pending", "approved"])
            .execute()
        )
        if all_requests_res.data:
            for row in all_requests_res.data:
                docs = row.get('documents') or []
                if isinstance(docs, list):
                    requested_doc_ids.update(docs)
    except Exception as e:
        logger.warning(f"Failed to fetch pending/approved erasure requests: {e}")

    # Filter out documents that already have pending or approved erasure requests
    documents = [doc for doc in documents if doc.get("value") not in requested_doc_ids]

    recent_requests = []
    try:
        requests_res = (
            supabase.table("data_erasure_requests")
            .select("id, reason, status, created_at, documents, rejection_reason, rejected_at")
            .eq("requester_id", doctor_id)
            .order("created_at", desc=True)
            .limit(5)
            .execute()
        )
        if requests_res.data:
            for row in requests_res.data:
                docs = row.get('documents') or []
                docs_count = len(docs) if isinstance(docs, list) else 0
                recent_requests.append({
                    "id": row.get('id'),
                    "reason": row.get('reason'),
                    "status": row.get('status', 'pending'),
                    "created_at": _format_creation_time(row.get('created_at', '')),
                    "rejection_reason": row.get('rejection_reason', ''),
                    "rejected_at": _format_creation_time(row.get('rejected_at', '')) if row.get('rejected_at') else None,
                    "documents_count": docs_count
                })
    except Exception as e:
        logger.error(f"Error loading erasure requests: {e}")

    return render_template(
        'doctor/data-erasure.html',
        documents=documents,
        recent_requests=recent_requests
    )

@app.route('/doctor/queue', methods=['GET'])
@login_required
def doctor_queue():
    """Display the consultation queue for the doctor."""
    user_session = session.get('user')
    doctor_id = user_session.get('user_id') or user_session.get('id')
    
    queue = get_consultation_queue(doctor_id, status="waiting")
    queue_display = []
    
    for idx, appointment in enumerate(queue, start=1):
        try:
            patient_res = supabase.table("patient_profile").select("full_name").eq("id", appointment.get("patient_id")).single().execute()
            
            if patient_res.data:
                patient = patient_res.data
                
                queue_display.append({
                    "position": idx,
                    "appointment_id": appointment.get("id"),
                    "patient_name": patient.get("full_name", "Unknown"),
                    "patient_id": appointment.get("patient_id"),
                    "appointment_time": appointment.get("appointment_datetime"),
                    "visit_type": appointment.get("visit_type", "General"),
                    "booked_at": appointment.get("created_at")
                })
        except Exception as e:
            logger.warning(f"Could not fetch patient for appointment {appointment.get('id')}: {e}")
    
    log_phi_event(
        action="VIEW_CONSULTATION_QUEUE",
        classification="internal",
        allowed=True,
        extra={"queue_size": len(queue_display)}
    )
    
    return render_template('doctor/consultation-queue.html', queue=queue_display)


@app.route('/doctor/start-consultation/<appointment_id>', methods=['GET', 'POST'])
@login_required
def start_consultation_route(appointment_id):
    """Open consultation page for the next patient in queue."""
    user_session = session.get('user')
    doctor_id = user_session.get('user_id') or user_session.get('id')
    
    if not _is_valid_uuid(appointment_id):
        flash('Invalid appointment ID', 'error')
        return redirect(url_for('doctor_dashboard'))
    
    try:
        # Verify the appointment belongs to this doctor
        appointment_res = (
            supabase.table("appointments")
            .select("*")
            .eq("id", appointment_id)
            .eq("doctor_id", doctor_id)
            .single()
            .execute()
        )
        
        if not appointment_res.data:
            flash('Appointment not found or unauthorized', 'error')
            return redirect(url_for('doctor_dashboard'))
        
        appointment = appointment_res.data
        patient_id = appointment.get("patient_id")
        
        # Fetch patient details with encrypted NRIC
        patient_res = supabase.table("patient_profile").select("id, full_name, nric_encrypted, dek_encrypted").eq("id", patient_id).single().execute()
        patient = patient_res.data if patient_res.data else {}
        
        # Decrypt and mask NRIC
        nric_masked = '****'
        if patient.get('nric_encrypted') and patient.get('dek_encrypted'):
            try:
                nric_decrypted = envelope_decrypt_field(patient.get('dek_encrypted'), patient.get('nric_encrypted'))
                if nric_decrypted:
                    # Mask format: First letter + **** + Last 4 characters
                    # Example: S1234567A -> S****567A
                    nric_masked = re.sub(r'^(.)(.*?)(....)$', r'\1****\3', str(nric_decrypted))
            except Exception as e:
                logger.warning(f"Could not decrypt NRIC for patient {patient_id}: {e}")
                nric_masked = '****'
        
        # Add masked NRIC to patient dict for template
        patient['nric_masked'] = nric_masked
        
        # Mark as in_progress only when first loading the consultation page
        if request.method == 'GET':
            start_consultation(appointment_id, doctor_id)
            log_phi_event(
                action="START_CONSULTATION",
                classification="restricted",
                record_id=appointment_id,
                target_user_id=patient_id,
                allowed=True,
                extra={"doctor_id": doctor_id}
            )
        
        # Handle form submission to complete consultation
        if request.method == 'POST':
            consultation_data = {
                "notes": request.form.get("notes", ""),
                "diagnosis": request.form.get("diagnosis", ""),
                "treatment": request.form.get("treatment", ""),
                "classification": request.form.get("classification", "restricted")
            }
            
            if complete_consultation(appointment_id, consultation_data):
                flash(f"Consultation completed and saved", "success")
                return redirect(url_for('doctor_dashboard'))
            else:
                flash(f"Failed to complete consultation", "error")
        
        return render_template('doctor/consultation.html', 
                             appointment_id=appointment_id,
                             appointment=appointment,
                             patient=patient)
            
    except Exception as e:
        logger.error(f"Error starting consultation: {e}")
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('doctor_dashboard'))


@app.route('/doctor/patient-lookup')
@login_required
def doctor_patient_lookup():
    search_term = request.args.get('q', '')
    search_by = request.args.get('search_by', 'name')
    
    try:
        # Fetch all patients from patient_profile table
        response = supabase.table("patient_profile").select("id, full_name, nric_encrypted, dob_encrypted, dek_encrypted, created_at").execute()
        
        user_session = session.get('user')
        all_patients = []
        
        if response.data:
            for patient in response.data:
                patient_id = patient.get('id')
                
                # Decrypt or mask NRIC and DOB based on access control
                encrypted_fields = {
                    'nric_encrypted': patient.get('nric_encrypted', ''),
                    'dob_encrypted': patient.get('dob_encrypted', ''),
                }
                dek_encrypted = patient.get('dek_encrypted', '')
                
                # Decrypt NRIC and mask it
                nric_masked = '****'
                nric_decrypt_error = False
                try:
                    nric_decrypted = envelope_decrypt_field(dek_encrypted, encrypted_fields.get('nric_encrypted', ''))
                    if nric_decrypted:
                        # Mask format: First letter + **** + Last 4 characters
                        # Example: S1234567A -> S****567A
                        nric_masked = re.sub(r'^(.)(.*?)(....)$', r'\1****\3', str(nric_decrypted))
                except Exception as decrypt_error:
                    logger.warning(f"Could not decrypt NRIC for patient {patient.get('full_name')} ({patient_id}): {str(decrypt_error)}")
                    nric_decrypt_error = True
                    nric_masked = '⚠️ Decryption Error'
                
                # Decrypt DOB
                dob_display = 'N/A'
                try:
                    dob_decrypted = envelope_decrypt_field(dek_encrypted, encrypted_fields.get('dob_encrypted', ''))
                    if dob_decrypted:
                        dob_display = dob_decrypted
                except Exception as decrypt_error:
                    logger.warning(f"Could not decrypt DOB for patient {patient.get('full_name')} ({patient_id}): {str(decrypt_error)}")
                    dob_display = 'N/A'
                
                # Get last visit date from consultations table
                last_visit = 'N/A'
                try:
                    consultations_response = (
                        supabase.table("consultations")
                        .select("created_at")
                        .eq("patient_id", patient_id)
                        .order("created_at", desc=True)
                        .limit(1)
                        .execute()
                    )
                    
                    if consultations_response.data and len(consultations_response.data) > 0:
                        last_visit_date = consultations_response.data[0].get('created_at')
                        if last_visit_date:
                            # Parse and format the date
                            last_visit_dt = datetime.fromisoformat(last_visit_date.replace('Z', '+00:00'))
                            last_visit = last_visit_dt.strftime('%d %b %Y')
                except Exception as e:
                    logger.warning(f"Could not fetch last visit for patient {patient_id}: {str(e)}")
                
                patient_data = {
                    'id': patient_id,
                    'name': patient.get('full_name', 'N/A'),
                    'nric': nric_masked,
                    'dob': dob_display,
                    'last_visit': last_visit,
                    'decrypt_error': nric_decrypt_error
                }
                
                all_patients.append(patient_data)
        
        # Filter patients based on search
        if search_term:
            # Search by name, NRIC, or other fields
            if search_by == 'nric':
                patients = [p for p in all_patients if search_term.lower() in p.get('nric', '').lower()]
            elif search_by == 'phone':
                # Note: phone is encrypted; searching by phone requires decryption of all records
                # For now, skip phone search or use a simpler approach
                patients = all_patients
            else:  # search_by == 'name'
                patients = [p for p in all_patients if search_term.lower() in p.get('name', '').lower()]
        else:
            patients = all_patients
        
        log_phi_event(
            action="SEARCH_PATIENTS",
            classification="restricted",
            record_id=None,
            target_user_id=None,
            allowed=True,
            extra={"search_term": search_term, "search_by": search_by, "results": len(patients)}
        )
        
        return render_template('doctor/patient-lookup.html', 
                               patients=patients, 
                               search_term=search_term, 
                               search_by=search_by)
    
    except Exception as e:
        logger.error(f"Error fetching patients: {str(e)}")
        flash('Error loading patient data', 'error')
        return render_template('doctor/patient-lookup.html', 
                               patients=[], 
                               search_term=search_term, 
                               search_by=search_by)


@app.route('/doctor/consultation', methods=['GET', 'POST'])
@app.route('/doctor/consultation/<patient_id>', methods=['GET', 'POST'])
@login_required
def doctor_consultation(patient_id=None):
    """Legacy route - redirect to queue-based consultation flow."""
    flash('Please start a consultation from the waiting queue on your dashboard', 'info')
    return redirect(url_for('doctor_dashboard'))


@app.route('/doctor/view-consultations')
@login_required
def list_consultations():
    """List all saved consultations - redirects to password check."""
    return redirect(url_for('verify_consultation_password'))


@app.route('/doctor/verify-consultation-password', methods=['GET', 'POST'])
@login_required
def verify_consultation_password():
    """Password verification page for viewing consultations."""
    CONSULTATION_PASSWORD = session.get('login_password')
    
    if request.method == 'POST':
        entered_password = request.form.get('password', '')
        
        if CONSULTATION_PASSWORD and entered_password == CONSULTATION_PASSWORD:
            # Password is correct - redirect to consultation list
            session['consultation_auth'] = True
            session['consultation_auth_time'] = datetime.now(timezone.utc).isoformat()
            flash('Password verified. You can now view consultations.', 'success')
            return redirect(url_for('consultations_list'))
        else:
            flash('Incorrect password. Please try again.', 'error')
    
    return render_template('doctor/verify-password.html')


@app.route('/doctor/consultations-list')
@login_required
def consultations_list():
    """List all saved consultations (password protected)."""
    # Check if user has verified password in this session
    if not session.get('consultation_auth'):
        log_phi_event(
            action="LIST_CONSULTATIONS",
            classification="restricted",
            record_id=None,
            target_user_id=None,
            allowed=False,
            extra={"reason": "consultation_password_not_verified"}
        )
        flash('Please verify your password to view consultations.', 'error')
        return redirect(url_for('verify_consultation_password'))
    
    try:
        # Fetch all consultations from database (exclude soft-deleted)
        consultations_res = (
            supabase.table("consultations")
            .select("id, patient_id, doctor_name, diagnosis, classification, created_at")
            .eq("is_deleted", 0)
            .order("created_at", desc=True)
            .execute()
        )
        
        consultations = consultations_res.data if consultations_res.data else []
        patient_name_map = {}
        try:
            patient_ids = list({c.get("patient_id") for c in consultations if c.get("patient_id")})
            if patient_ids:
                patients_res = (
                    supabase.table("patient_profile")
                    .select("id, full_name")
                    .in_("id", patient_ids)
                    .execute()
                )
                if patients_res.data:
                    patient_name_map = {p.get("id"): p.get("full_name") for p in patients_res.data}
        except Exception as e:
            logger.warning(f"Failed to fetch patient names for consultations: {e}")

        for consultation in consultations:
            consultation["patient_name"] = patient_name_map.get(consultation.get("patient_id"), "Unknown")
        logger.info(f"Fetched {len(consultations)} consultations")

        log_phi_event(
            action="LIST_CONSULTATIONS",
            classification="restricted",
            record_id=None,
            target_user_id=None,
            allowed=True,
            extra={"count": len(consultations)}
        )
        
        return render_template('doctor/consultations-list.html', consultations=consultations)
        
    except Exception as e:
        logger.error(f"Error fetching consultations: {str(e)}")
        flash("Error loading consultations", "error")
        return redirect(url_for('doctor_dashboard'))


@app.route('/doctor/view-consultation/<consultation_id>')
@login_required
def view_consultation(consultation_id):
    """View a saved consultation with decrypted clinical notes (password protected)."""
    # Check if user has verified password in this session
    if not session.get('consultation_auth'):
        log_phi_event(
            action="VIEW_CONSULTATION",
            classification="restricted",
            record_id=consultation_id,
            target_user_id=None,
            allowed=False,
            extra={"reason": "consultation_password_not_verified"}
        )
        flash('Please verify your password to view consultations.', 'error')
        return redirect(url_for('verify_consultation_password'))
    
    try:
        # Validate UUID format
        if not consultation_id or len(consultation_id) < 10:
            flash("Invalid consultation ID format. Expected UUID.", "error")
            return redirect(url_for('consultations_list'))
        
        # Fetch consultation from database (exclude soft-deleted)
        consultation_res = (
            supabase.table("consultations")
            .select("*")
            .eq("id", consultation_id)
            .eq("is_deleted", 0)
            .single()
            .execute()
        )
        
        if not consultation_res.data:
            flash("Consultation not found", "error")
            return redirect(url_for('consultations_list'))
        
        consultation = consultation_res.data
        
        # Decrypt clinical notes
        decrypted_notes = None
        if consultation.get('clinical_notes_encrypted') and consultation.get('dek_encrypted'):
            decrypted_notes = envelope_decrypt_field(
                consultation['dek_encrypted'],
                consultation['clinical_notes_encrypted']
            )
        
        # Prepare consultation data for display
        consultation['clinical_notes'] = decrypted_notes or "[Unable to decrypt notes]"

        # Fetch patient name for display
        patient_name = "Unknown"
        try:
            patient_res = (
                supabase.table("patient_profile")
                .select("full_name")
                .eq("id", consultation.get("patient_id"))
                .single()
                .execute()
            )
            if patient_res.data:
                patient_name = patient_res.data.get("full_name", "Unknown")
        except Exception as e:
            logger.warning(f"Failed to fetch patient name for consultation {consultation_id}: {e}")
        
        logger.info(f"Consultation {consultation_id} retrieved for viewing")

        log_phi_event(
            action="VIEW_CONSULTATION",
            classification=consultation.get("classification", "restricted"),
            record_id=consultation_id,
            target_user_id=consultation.get("patient_id"),
            allowed=True
        )
        
        return render_template('doctor/view-consultation.html', consultation=consultation, patient_name=patient_name)
        
    except Exception as e:
        error_msg = str(e)
        if 'invalid input syntax for type uuid' in error_msg:
            flash("Invalid consultation ID. Please check the ID format.", "error")
        else:
            logger.error(f"Error retrieving consultation: {error_msg}")
            flash(f"Error loading consultation", "error")
        return redirect(url_for('consultations_list'))


@app.route('/doctor/write-mc', methods=['GET', 'POST'])
@login_required
def doctor_write_mc():
    from datetime import date
    
    user_session = session.get('user')
    doctor_id = user_session.get('user_id') or user_session.get('id')
    doctor_email = user_session.get('email')
    
    # Fetch doctor information from database
    doctor = {'name': 'Doctor', 'specialty': 'General Practitioner'}
    try:
        if doctor_email:
            profile_res = (
                supabase.table("doctor_profile")
                .select("full_name, specialty")
                .eq("email", doctor_email)
                .single()
                .execute()
            )
            if profile_res.data:
                doctor = {
                    'name': profile_res.data.get('full_name', 'Doctor'),
                    'specialty': profile_res.data.get('specialty', 'General Practitioner')
                }
    except Exception as e:
        logger.warning(f"Failed to fetch doctor profile: {e}")
    
    today = date.today().strftime('%d/%m/%Y')
    patient = {}
    default_classification = "confidential"
    
    if request.method == 'POST':
        patient_name = request.form.get('patient_name', '').strip()
        patient_id = request.form.get('patient_id', '').strip()
        classification = request.form.get('classification', default_classification).strip()
        start_date_str = request.form.get('start_date', '').strip()
        duration = request.form.get('duration', '1').strip()
        
        if not patient_id:
            flash('Please select a patient from the search results', 'error')
            return render_template('doctor/write-mc.html', 
                                   patient=patient, 
                                   doctor=doctor, 
                                   today=today,
                                   classification=classification)
        
        if not start_date_str:
            flash('Please select a start date', 'error')
            return render_template('doctor/write-mc.html', 
                                   patient=patient, 
                                   doctor=doctor, 
                                   today=today,
                                   classification=classification)
        
        try:
            # Calculate end date based on duration
            from datetime import datetime, timedelta
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            duration_days = int(duration)
            end_date = start_date + timedelta(days=duration_days - 1)
            
            # Get doctor information
            doctor_email = user_session.get('email')
            doctor_name_db = doctor['name']
            doctor_specialty_db = doctor['specialty']
            
            # Determine classification method
            classification_method = "Automatic" if classification == default_classification else "Manual"
            
            # Generate tokenized MC ID
            tokenized_mc_id = generate_token('mc')
            
            # Create MC record in database
            mc_data = {
                "mc_number": tokenized_mc_id,
                "patient_id": patient_id,
                "doctor_id": doctor_id,
                "doctor_name": doctor_name_db,
                "doctor_specialty": doctor_specialty_db,
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "duration_days": duration_days,
                "classification": classification,
                "classification_method": classification_method,
                "issued_at": datetime.now(timezone.utc).isoformat(),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "expiry_date": calculate_expiry_date(None, 90),
                "status": "active"
                
            }
            
            # Insert into medical_certificates table
            mc_result = supabase.table("medical_certificates").insert(mc_data).execute()
            
            if mc_result.data:
                mc_id = mc_result.data[0].get('id') if isinstance(mc_result.data, list) else mc_result.data.get('id')
                
                # Log the MC issuance with proper classification
                log_phi_event(
                    action="ISSUE_MC",
                    classification=classification,
                    record_id=mc_id,
                    target_user_id=patient_id,
                    allowed=True,
                    extra={
                        "doctor_id": doctor_id, 
                        "tokenized_mc_id": tokenized_mc_id,
                        "duration": duration_days,
                        "start_date": start_date.isoformat(),
                        "end_date": end_date.isoformat()
                    }
                )
                
                flash(f'Medical Certificate {tokenized_mc_id} issued successfully for {duration_days} day(s)!', 'success')
                return redirect(url_for('doctor_dashboard'))
            else:
                flash('Failed to issue MC. Please try again.', 'error')
                
        except ValueError as e:
            logger.error(f"Date parsing error in MC issuance: {e}")
            flash('Invalid date format. Please try again.', 'error')
        except Exception as e:
            logger.error(f"Error issuing MC: {e}")
            flash(f'Error issuing MC: {str(e)}', 'error')
        
        return render_template('doctor/write-mc.html', 
                               patient=patient, 
                               doctor=doctor, 
                               today=today,
                               classification=classification)
    
    return render_template('doctor/write-mc.html', 
                           patient=patient, 
                           doctor=doctor, 
                           today=today,
                           classification=default_classification)


@app.route('/doctor/api/search-patient', methods=['GET'])
@login_required
def api_search_patient():
    """API endpoint to search for patients by name."""
    query = request.args.get('q', '').strip()
    
    if not query or len(query) < 2:
        return jsonify([])
    
    try:
        user_session = session.get('user')
        doctor_id = user_session.get('user_id') or user_session.get('id')
        
        # Fetch patients from database
        response = supabase.table("patient_profile").select("id, full_name, nric_encrypted, dek_encrypted").execute()
        
        patients = []
        if response.data:
            for patient in response.data:
                # Only include patients whose names match the query
                if query.lower() in patient.get('full_name', '').lower():
                    patient_id = patient.get('id')
                    
                    # Decrypt and mask NRIC
                    nric_masked = '****'
                    try:
                        nric_decrypted = envelope_decrypt_field(
                            patient.get('dek_encrypted', ''),
                            patient.get('nric_encrypted', '')
                        )
                        if nric_decrypted:
                            nric_masked = re.sub(r'^(.)(.*?)(....)$', r'\1****\3', str(nric_decrypted))
                    except Exception as e:
                        logger.warning(f"Could not decrypt NRIC for patient {patient_id}: {e}")
                        nric_masked = '****'
                    
                    patients.append({
                        'id': patient_id,
                        'name': patient.get('full_name', ''),
                        'nric': nric_masked
                    })
        
        log_phi_event(
            action="SEARCH_PATIENT_API",
            classification="restricted",
            allowed=True,
            extra={"search_term": query, "results": len(patients)}
        )
        
        return jsonify(patients)
    
    except Exception as e:
        logger.error(f"Error searching patients: {e}")
        return jsonify([])


@app.route('/doctor/api/search-consulted-patients', methods=['GET'])
@login_required
def api_search_consulted_patients():
    """Search patients by name, limited to those with completed consultations."""
    query = request.args.get('q', '').strip()

    if not query or len(query) < 2:
        return jsonify([])

    try:
        consultations_res = (
            supabase.table("consultations")
            .select("patient_id")
            .execute()
        )

        consulted_patient_ids = []
        if consultations_res.data:
            consulted_patient_ids = list({c.get("patient_id") for c in consultations_res.data if c.get("patient_id")})

        if not consulted_patient_ids:
            return jsonify([])

        response = (
            supabase.table("patient_profile")
            .select("id, full_name, nric_encrypted, dek_encrypted")
            .in_("id", consulted_patient_ids)
            .execute()
        )

        patients = []
        if response.data:
            for patient in response.data:
                if query.lower() in patient.get('full_name', '').lower():
                    patient_id = patient.get('id')
                    nric_masked = '****'
                    try:
                        nric_decrypted = envelope_decrypt_field(
                            patient.get('dek_encrypted', ''),
                            patient.get('nric_encrypted', '')
                        )
                        if nric_decrypted:
                            nric_masked = re.sub(r'^(.)(.*?)(....)$', r'\1****\3', str(nric_decrypted))
                    except Exception as e:
                        logger.warning(f"Could not decrypt NRIC for patient {patient_id}: {e}")
                        nric_masked = '****'

                    patients.append({
                        'id': patient_id,
                        'name': patient.get('full_name', ''),
                        'nric': nric_masked
                    })

        log_phi_event(
            action="SEARCH_CONSULTED_PATIENTS_API",
            classification="restricted",
            allowed=True,
            extra={"search_term": query, "results": len(patients)}
        )

        return jsonify(patients)

    except Exception as e:
        logger.error(f"Error searching consulted patients: {e}")
        return jsonify([])



@app.route('/doctor/write-prescription', methods=['GET', 'POST'])
@login_required
def doctor_write_prescription():
    patient = {}
    default_classification = "internal"

    if request.method == 'POST':
        user_session = session.get('user')
        doctor_id = user_session.get('user_id') or user_session.get('id')
        patient_id = request.form.get('patient_id', '').strip()
        patient_name = request.form.get('patient_name', '').strip()
        classification = request.form.get('classification', default_classification).strip()
        classification_method = "Automatic" if classification == default_classification else "Manual"

        if not patient_id:
            flash('Please select a patient from the search results', 'error')
            return render_template('doctor/write-prescription.html', 
                                   patient=patient,
                                   classification=classification)

        # Extract medications from dynamic form fields
        medications = []
        try:
            medication_indexes = set()
            for key in request.form.keys():
                match = re.match(r"medications\[(\d+)\]\[name\]", key)
                if match:
                    medication_indexes.add(int(match.group(1)))

            for idx in sorted(medication_indexes):
                name = request.form.get(f"medications[{idx}][name]", "").strip()
                dosage = request.form.get(f"medications[{idx}][dosage]", "").strip()
                frequency = request.form.get(f"medications[{idx}][frequency]", "").strip()
                duration = request.form.get(f"medications[{idx}][duration]", "").strip()
                instructions = request.form.get(f"medications[{idx}][instructions]", "").strip()

                if not name:
                    continue

                medications.append({
                    "name": name,
                    "dosage": dosage,
                    "frequency": frequency,
                    "duration": duration,
                    "instructions": instructions
                })
        except Exception as e:
            logger.error(f"Error parsing medications: {e}")
            medications = []

        if not medications:
            flash('Please add at least one medication', 'error')
            return render_template('doctor/write-prescription.html', 
                                   patient=patient,
                                   classification=classification)

        try:
            rx_number = generate_token("rx")
            prescription_data = {
                "patient_id": patient_id,
                "doctor_id": doctor_id,
                "medications": medications,
                "classification": classification,
                "classification_method": classification_method,
                "rx_number": rx_number,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "expiry_date": calculate_expiry_date(None, 90)
            }

            insert_res = supabase.table("prescriptions").insert(prescription_data).execute()
            if not insert_res.data:
                flash('Failed to generate prescription. Please try again.', 'error')
                return render_template('doctor/write-prescription.html', 
                                       patient=patient,
                                       classification=classification)

            prescription_id = insert_res.data[0].get('id') if isinstance(insert_res.data, list) else insert_res.data.get('id')

            log_phi_event(
                action="ISSUE_PRESCRIPTION",
                classification=classification,
                record_id=prescription_id,
                target_user_id=patient_id,
                allowed=True,
                extra={
                    "doctor_id": doctor_id,
                    "medications_count": len(medications),
                    "classification_method": classification_method
                }
            )

            flash(
                f'Prescription generated successfully for {patient_name}!',
                'success'
            )
            return redirect(url_for('doctor_dashboard'))
        except Exception as e:
            logger.error(f"Error saving prescription: {e}")
            flash('Error generating prescription. Please try again.', 'error')
            return render_template('doctor/write-prescription.html', 
                                   patient=patient,
                                   classification=classification)

    return render_template('doctor/write-prescription.html', 
                           patient=patient,
                           classification=default_classification)

    return render_template('doctor/write-prescription.html', patient=patient)


@app.route('/doctor/profile', methods=['GET', 'POST'])
@login_required
def doctor_profile():
    user_session = session.get('user')
    
    # Check if user is a doctor
    if user_session.get('role') != 'doctor':
        abort(403)
    
    doctor_email = user_session.get('email')
    if not doctor_email:
        flash('Doctor email not found in session', 'error')
        return redirect(url_for('doctor_dashboard'))

    if request.method == 'POST':
        full_name = (request.form.get('full_name') or '').strip()
        specialty = (request.form.get('specialty') or '').strip()
        update_payload = {
            "full_name": full_name,
            "specialty": specialty,
        }
        try:
            update_res = (
                supabase.table("doctor_profile")
                .update(update_payload)
                .eq("email", doctor_email)
                .execute()
            )
            if getattr(update_res, 'error', None):
                logger.error(f"Doctor profile update error: {update_res.error}")
                flash('Failed to update profile', 'error')
            else:
                flash('Profile updated successfully', 'success')
            return redirect(url_for('doctor_profile'))
        except Exception as e:
            logger.error(f"Failed to update doctor profile: {e}")
            flash('Error updating profile', 'error')
            return redirect(url_for('doctor_profile'))

    # Fetch doctor profile from doctor_profile table using email
    try:
        profile_res = (
            supabase.table("doctor_profile")
            .select("*")
            .eq("email", doctor_email)
            .single()
            .execute()
        )
        
        if profile_res.data:
            doctor_data = profile_res.data
            
            # Format doctor information for template
            doctor = {
                'name': doctor_data.get('full_name', doctor_data.get('name', 'N/A')),
                'specialty': doctor_data.get('specialty', 'General Practitioner'),
                'mcr_number': doctor_data.get('mcr_number', 'N/A'),
                'email': doctor_data.get('email', 'N/A'),
            }

            # Apply regex-based masking using apply_policy_masking()
            doctor_masked = apply_policy_masking(user_session, doctor)
            
            return render_template('doctor/doctor-profile.html', doctor=doctor_masked)
        else:
            flash('Doctor profile not found', 'error')
            return redirect(url_for('doctor_dashboard'))
            
    except Exception as e:
        logger.error(f"Failed to fetch doctor profile: {e}")
        flash('Error loading profile', 'error')
        return redirect(url_for('doctor_dashboard'))


# --- Pharmacy Routes ---------------------------------------------------------
@app.route('/pharmacy-dashboard')
def pharmacy_dashboard():
    # Mock stats
    stats = {
        'pending': 12,
        'dispensed': 34,
        'low_stock': 8,
        'total_items': 456
    }
    
    # Mock pending prescriptions
    pending_prescriptions = [
        {'id': 'RX001', 'patient': 'Sarah Lee', 'doctor': 'Dr. Chen', 'time': '10:30 AM', 'items': 3, 'priority': 'Normal'},
        {'id': 'RX002', 'patient': 'James Tan', 'doctor': 'Dr. Lim', 'time': '10:45 AM', 'items': 2, 'priority': 'Urgent'},
        {'id': 'RX003', 'patient': 'Mary Wong', 'doctor': 'Dr. Kumar', 'time': '11:00 AM', 'items': 4, 'priority': 'Normal'},
    ]
    
    # Mock low stock items
    low_stock_items = [
        {'name': 'Paracetamol 500mg', 'current': 50, 'minimum': 100, 'unit': 'tablets'},
        {'name': 'Amoxicillin 250mg', 'current': 30, 'minimum': 75, 'unit': 'capsules'},
        {'name': 'Omeprazole 20mg', 'current': 15, 'minimum': 50, 'unit': 'capsules'},
    ]
    
    return render_template('pharmacy/pharmacy-dashboard.html', 
                           stats=stats,
                           pending_prescriptions=pending_prescriptions,
                           low_stock_items=low_stock_items)


@app.route('/pharmacy/dispense', methods=['GET', 'POST'])
def pharmacy_dispense():
    search_term = request.args.get('q', '')
    
    # Mock prescriptions data
    all_prescriptions = [
        {
            'id': 'RX001',
            'patient': 'Sarah Lee',
            'nric_masked': '****567A',
            'doctor': 'Dr. Chen Wei Ming',
            'date': '2024-12-12',
            'status': 'pending',
            'medications': [
                {'name': 'Paracetamol', 'dosage': '500mg', 'quantity': '20 tablets', 'instructions': 'Take 1-2 tablets every 6 hours as needed', 'in_stock': True},
                {'name': 'Amoxicillin', 'dosage': '250mg', 'quantity': '21 capsules', 'instructions': 'Take 1 capsule 3 times daily for 7 days', 'in_stock': True},
                {'name': 'Cetirizine', 'dosage': '10mg', 'quantity': '14 tablets', 'instructions': 'Take 1 tablet once daily at bedtime', 'in_stock': True}
            ]
        },
        {
            'id': 'RX002',
            'patient': 'James Tan',
            'nric_masked': '****432B',
            'doctor': 'Dr. Lim Hui Ling',
            'date': '2024-12-12',
            'status': 'pending',
            'medications': [
                {'name': 'Omeprazole', 'dosage': '20mg', 'quantity': '28 capsules', 'instructions': 'Take 1 capsule daily before breakfast', 'in_stock': True},
                {'name': 'Metformin', 'dosage': '500mg', 'quantity': '60 tablets', 'instructions': 'Take 1 tablet twice daily with meals', 'in_stock': False}
            ]
        }
    ]
    
    # Filter prescriptions
    if search_term:
        prescriptions = [p for p in all_prescriptions if search_term.lower() in p['id'].lower() or search_term.lower() in p['patient'].lower()]
    else:
        prescriptions = all_prescriptions
    
    if request.method == 'POST':
        prescription_id = request.form.get('prescription_id')
        flash(f'Prescription {prescription_id} dispensed successfully!', 'success')
        return redirect(url_for('pharmacy_dispense'))
    
    return render_template('pharmacy/dispense-medication.html', 
                           prescriptions=prescriptions,
                           search_term=search_term)


@app.route('/pharmacy/inventory', methods=['GET', 'POST'])
def pharmacy_inventory():
    search_term = request.args.get('q', '')
    filter_category = request.args.get('category', 'all')
    
    # Mock inventory data
    all_inventory = [
        {'id': 'MED001', 'name': 'Paracetamol 500mg', 'category': 'Analgesics', 'current_stock': 50, 'minimum_stock': 100, 'unit': 'tablets', 'expiry_date': '2025-06-15', 'supplier': 'PharmaCorp', 'cost': '$0.10'},
        {'id': 'MED002', 'name': 'Amoxicillin 250mg', 'category': 'Antibiotics', 'current_stock': 30, 'minimum_stock': 75, 'unit': 'capsules', 'expiry_date': '2025-03-20', 'supplier': 'MediSupply', 'cost': '$0.45'},
        {'id': 'MED003', 'name': 'Omeprazole 20mg', 'category': 'Gastrointestinal', 'current_stock': 15, 'minimum_stock': 50, 'unit': 'capsules', 'expiry_date': '2025-01-10', 'supplier': 'PharmaCorp', 'cost': '$0.35'},
        {'id': 'MED004', 'name': 'Metformin 500mg', 'category': 'Diabetes', 'current_stock': 120, 'minimum_stock': 80, 'unit': 'tablets', 'expiry_date': '2025-08-30', 'supplier': 'HealthDist', 'cost': '$0.25'},
        {'id': 'MED005', 'name': 'Cetirizine 10mg', 'category': 'Antihistamines', 'current_stock': 85, 'minimum_stock': 60, 'unit': 'tablets', 'expiry_date': '2025-05-18', 'supplier': 'MediSupply', 'cost': '$0.20'},
    ]
    
    categories = list(set(item['category'] for item in all_inventory))
    
    # Filter inventory
    inventory = all_inventory
    if search_term:
        inventory = [i for i in inventory if search_term.lower() in i['name'].lower() or search_term.lower() in i['id'].lower()]
    if filter_category != 'all':
        inventory = [i for i in inventory if i['category'] == filter_category]
    
    # Stats
    stats = {
        'total_items': len(all_inventory),
        'low_stock': len([i for i in all_inventory if i['current_stock'] < i['minimum_stock']]),
        'expiring_soon': 2,
        'total_value': '$12,450'
    }
    
    if request.method == 'POST':
        flash('Inventory item added successfully!', 'success')
        return redirect(url_for('pharmacy_inventory'))
    
    return render_template('pharmacy/inventory-management.html',
                           inventory=inventory,
                           categories=categories,
                           search_term=search_term,
                           filter_category=filter_category,
                           stats=stats)

# --- Admin Routes ------------------------------------------------------------
@app.route('/admin-dashboard')
@login_required
def admin_dashboard():
    user = session.get('user') 
    if user.get('role') not in ('admin'):
        abort(403)
    return render_template('admin/admin-dashboard.html')

@app.route('/admin/audit-logs')
@login_required
def admin_audit_logs():
    user = session.get('user')
    if user.get('role') not in ('admin'):
        abort(403)
    return render_template('admin/audit-logs.html')


@app.route('/api/admin/audit-logs')
@login_required
def api_get_audit_logs():
    """
    API endpoint to fetch audit logs from Supabase.
    Supports filtering by date range, action type, status, and search term.
    """
    user = session.get('user')
    if user.get('role') not in ('admin'):
        return jsonify({"error": "Forbidden"}), 403
    
    try:
        # Parse query parameters
        date_range = request.args.get('date_range', 'today')
        action_filter = request.args.get('action', 'all')
        status_filter = request.args.get('status', 'all')
        search_term = request.args.get('search', '').strip()
        security_filter = request.args.get('security_filter', 'all')
        limit = min(int(request.args.get('limit', 100)), 500)
        
        # Calculate date range
        now = datetime.now(timezone.utc)
        if date_range == 'today':
            start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif date_range == 'week':
            start_date = now - timedelta(days=7)
        elif date_range == 'month':
            start_date = now - timedelta(days=30)
        else:
            start_date = now - timedelta(days=365)
        
        # Build query
        query = supabase.table("audit_logs").select("*").gte("timestamp", start_date.isoformat())
        
        # Apply action filter
        if action_filter != 'all':
            query = query.ilike("action", f"%{action_filter}%")
        
        # Apply status filter
        if status_filter != 'all':
            query = query.eq("status", status_filter.capitalize())
        
        # Apply security-focused filters
        if security_filter == 'phi_access':
            query = query.in_("entity_type", ["restricted", "confidential", "critical"])
        elif security_filter == 'failed_auth':
            query = query.or_("action.ilike.%LOGIN_FAILED%,status.eq.Denied")
        elif security_filter == 'export_events':
            query = query.or_("action.ilike.%EXPORT%,action.ilike.%DOWNLOAD%")
        elif security_filter == 'high_risk':
            query = query.or_("action.ilike.%DELETE%,action.ilike.%UPDATE%,action.ilike.%CREATE%")
        elif security_filter == 'dlp_scans':
            query = query.ilike("action", "%UPLOAD%")
        elif security_filter == 'dlp_blocked':
            query = query.eq("status", "Failed")
        
        # Order and limit
        query = query.order("timestamp", desc=True).limit(limit)
        
        result = query.execute()
        logs = result.data or []
        
        # Apply search filter (client-side for flexibility)
        if search_term:
            search_lower = search_term.lower()
            logs = [
                log for log in logs
                if search_lower in str(log.get('user_name', '')).lower()
                or search_lower in str(log.get('action', '')).lower()
                or search_lower in str(log.get('entity_id', '')).lower()
                or search_lower in str(log.get('ip_address', '')).lower()
            ]
        
        # Enrich logs with user names from profiles if needed
        user_ids = list(set(log.get('user_id') for log in logs if log.get('user_id')))
        user_names = {}
        if user_ids:
            try:
                profiles_res = supabase.table("profiles").select("id, full_name, role").in_("id", user_ids[:50]).execute()
                if profiles_res.data:
                    user_names = {p['id']: {'name': p.get('full_name', ''), 'role': p.get('role', '')} for p in profiles_res.data}
            except Exception as e:
                logger.warning(f"Failed to fetch user names: {e}")
        
        # Format logs for frontend
        formatted_logs = []
        for log in logs:
            user_id = log.get('user_id')
            user_info = user_names.get(user_id, {})
            
            # Parse details JSON
            details = {}
            if log.get('details'):
                try:
                    details = json.loads(log['details'])
                except Exception:
                    pass
            
            formatted_logs.append({
                'id': log.get('id'),
                'timestamp': log.get('timestamp'),
                'user': user_info.get('name') or log.get('user_name') or 'Unknown User',
                'role': user_info.get('role') or log.get('user_name') or 'unknown',
                'user_id': user_id,
                'action': log.get('action', ''),
                'resource': log.get('entity_id') or log.get('action', ''),
                'entity_type': log.get('entity_type', 'internal'),
                'ip_address': log.get('ip_address', ''),
                'user_agent': log.get('user_agent', ''),
                'status': log.get('status', 'Success').lower(),
                'hash': details.get('hash', ''),
                'prev_hash': details.get('prev_hash', ''),
                'verified': bool(details.get('hash')),
                'details': log.get('new_value') or '',
                'extra': details.get('extra', {}),
                'classification': details.get('classification', 'internal'),
            })
        
        # Calculate stats
        stats = {
            'total': len(logs),
            'success': sum(1 for log in logs if log.get('status', '').lower() == 'success'),
            'failed': sum(1 for log in logs if log.get('status', '').lower() in ['denied', 'failed']),
            'warning': sum(1 for log in logs if log.get('status', '').lower() == 'warning'),
            'dlp_scans': sum(1 for log in logs if 'UPLOAD' in (log.get('action') or '')),
            'dlp_blocked': sum(1 for log in logs if log.get('status', '').lower() == 'failed' and 'UPLOAD' in (log.get('action') or '')),
        }
        
        return jsonify({
            'logs': formatted_logs,
            'stats': stats,
            'count': len(formatted_logs)
        })
        
    except Exception as e:
        logger.error(f"Error fetching audit logs: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/admin/verify-hash-chain')
@login_required
def api_verify_hash_chain():
    """Verify the integrity of the hash chain in audit logs."""
    user = session.get('user')
    if user.get('role') not in ('admin'):
        return jsonify({"error": "Forbidden"}), 403
    
    try:
        # Read local audit file for verification
        entries = _read_recent_audit_entries(limit=1000)
        
        if not entries:
            return jsonify({"verified": True, "message": "No entries to verify", "count": 0})
        
        broken_links = []
        for i in range(1, len(entries)):
            current = entries[i]
            previous = entries[i - 1]
            
            if current.get('prev_hash') != previous.get('hash'):
                broken_links.append({
                    'index': i,
                    'event_id': current.get('event_id'),
                    'expected': previous.get('hash'),
                    'found': current.get('prev_hash')
                })
        
        return jsonify({
            'verified': len(broken_links) == 0,
            'count': len(entries),
            'broken_links': broken_links[:10],  # Limit to first 10
            'message': 'Hash chain integrity verified' if not broken_links else f'{len(broken_links)} broken link(s) found'
        })
        
    except Exception as e:
        logger.error(f"Error verifying hash chain: {e}")
        return jsonify({"error": str(e), "verified": False}), 500


@app.route('/admin/user-management')
@login_required
def admin_user_management():
    user = session.get('user')
    if user.get('role') not in ('admin'):
        abort(403)
    try:
        # Fetch all users from the profiles table
        users_res = supabase.table("profiles").select("*").execute()
        users = users_res.data if users_res.data else []
        
        # Fetch role-specific details
        patient_ids = [u.get('id') for u in users if u.get('role') == 'patient']
        staff_ids = [u.get('id') for u in users if u.get('role') == 'staff']
        doctor_ids = [u.get('id') for u in users if u.get('role') == 'doctor']
        
        patient_details = {}
        staff_details = {}
        doctor_details = {}
        
        # Fetch patient PHI from patient_profile (encrypted)
        if patient_ids:
            try:
                patient_res = supabase.table("patient_profile").select(
                    "id, nric_encrypted, phone_encrypted, dek_encrypted"
                ).in_("id", patient_ids).execute()
                if patient_res.data:
                    for patient in patient_res.data:
                        pid = patient.get('id')
                        dek = patient.get('dek_encrypted')
                        nric_enc = patient.get('nric_encrypted')
                        phone_enc = patient.get('phone_encrypted')
                        # Decrypt for admin display
                        nric = envelope_decrypt_field(dek, nric_enc) if dek and nric_enc else None
                        phone = envelope_decrypt_field(dek, phone_enc) if dek and phone_enc else None
                        patient_details[pid] = {'nric': nric, 'mobile_number': phone}
            except Exception as e:
                logger.warning(f"Failed to fetch patient details: {e}")
        
        if staff_ids:
            try:
                staff_res = supabase.table("staff_profile").select("id, full_name").in_("id", staff_ids).execute()
                if staff_res.data:
                    staff_details = {staff.get('id'): staff for staff in staff_res.data}
            except Exception as e:
                logger.warning(f"Failed to fetch staff details: {e}")
        
        if doctor_ids:
            try:
                doctor_res = supabase.table("doctor_profile").select("id, full_name, specialty, mcr_number").in_("id", doctor_ids).execute()
                if doctor_res.data:
                    doctor_details = {doctor.get('id'): doctor for doctor in doctor_res.data}
            except Exception as e:
                logger.warning(f"Failed to fetch doctor details: {e}")
        
        # Enrich user data with role-specific details
        for user in users:
            user_id = user.get('id')
            if user.get('role') == 'patient' and user_id in patient_details:
                # Add decrypted PHI from patient_profile
                user['nric'] = patient_details[user_id].get('nric') or ''
                user['mobile_number'] = patient_details[user_id].get('mobile_number') or ''
            elif user.get('role') == 'staff' and user_id in staff_details:
                # Staff details - full_name already in profiles
                pass
            elif user.get('role') == 'doctor' and user_id in doctor_details:
                user['specialty'] = doctor_details[user_id].get('specialty')
                user['mcr_number'] = doctor_details[user_id].get('mcr_number')

        # Apply policy-based masking for admin view
        user_session = session.get('user')
        users = [apply_policy_masking(user_session, u) for u in users]
        
        log_phi_event(
            action="VIEW_USER_MANAGEMENT",
            classification="restricted",
            allowed=True,
            extra={"user_count": len(users), "patient_count": len(patient_ids)}
        )
        
        return render_template('admin/user-management.html', users=users)

    except Exception as e:
        logger.error(f"Error fetching users: {e}")
        flash('Error loading users', 'error')
        return render_template('admin/user-management.html', users=[])


@app.route('/admin/backup-recovery')
@login_required
def admin_backup_recovery():
    user = session.get('user')
    if user.get('role') not in ('admin'):
        abort(403)
    return render_template('admin/backup-recovery.html')

@app.route('/admin/data-retention')
@login_required
def admin_data_retention():
    user = session.get('user')
    if user.get('role') not in ('admin'):
        abort(403)
    return render_template('admin/data-retention.html')


@app.route('/admin/encryption')
@login_required
def admin_encryption_status():
    user = session.get('user')
    if user.get('role') not in ('admin'):
        abort(403)
    return render_template('admin/encryption-status.html')


@app.route('/admin/dlp-events')
@login_required
def admin_dlp_events():
    user = session.get('user')
    if user.get('role') not in ('admin'):
        abort(403)

    events = []
    try:
        dlp_res = (
            supabase.table("DLP_events")
            .select("Timestamps,user,role,action,Data_type,severity,status,details")
            .order("Timestamps", desc=True)
            .execute()
        )
        rows = dlp_res.data if dlp_res.data else []
        events = [
            {
                "timestamp": _format_creation_time(row.get("Timestamps")) or row.get("Timestamps") or "",
                "user": row.get("user") or "",
                "role": row.get("role") or "unknown",
                "action": row.get("action") or "",
                "data_type": row.get("Data_type") or row.get("data_type") or "",
                "severity": row.get("severity") or "low",
                "status": row.get("status") or "",
                "details": row.get("details") or "",
            }
            for row in rows
        ]
    except Exception as e:
        logger.error(f"Failed to fetch DLP events: {e}")

    stats = {
        "total": len(events),
        "blocked": sum(1 for e in events if e.get("status") == "blocked"),
        "flagged": sum(1 for e in events if e.get("status") == "flagged"),
        "critical": sum(1 for e in events if e.get("severity") == "critical"),
    }

    return render_template('admin/dlp-events.html', events=events, stats=stats)


# ----------------------------------------------------------

def _normalize_method(method_str):
    """Normalize classification method display names."""
    if not method_str:
        return 'Unknown'
    method_lower = method_str.lower().strip()
    if 'auto' in method_lower or 'suggest' in method_lower:
        return 'Automatic'
    elif 'manual' in method_lower or 'override' in method_lower:
        return 'Manual'
    return method_str


def _format_creation_time(value: str) -> str:
    if not value:
        return ""
    try:
        ts = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return value


def _format_appointment_display(appointment_date: str | None, appointment_time: str | None, appointment_datetime: str | None) -> str:
    if appointment_date and appointment_time:
        formatted_time = appointment_time
        if "AM" not in appointment_time and "PM" not in appointment_time:
            for time_fmt in ("%H:%M", "%H:%M:%S"):
                try:
                    formatted_time = datetime.strptime(appointment_time, time_fmt).strftime("%I:%M %p")
                    break
                except Exception:
                    continue
        return f"{appointment_date} {formatted_time}".strip()

    if appointment_datetime:
        try:
            dt = datetime.fromisoformat(appointment_datetime.replace("Z", "+00:00"))
            return dt.strftime("%Y-%m-%d %I:%M %p")
        except Exception:
            for dt_fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S"):
                try:
                    dt = datetime.strptime(appointment_datetime, dt_fmt)
                    return dt.strftime("%Y-%m-%d %I:%M %p")
                except Exception:
                    continue
            return appointment_datetime

    return ""


@app.route('/admin/security/classification_matrix')
@login_required
def admin_security_classification_matrix():
    """Display the Classification Summary Matrix for all records."""
    user = session.get('user')
    if user.get('role') not in ('admin'):
        abort(403)
    
    # Fetch detailed classification counts from database
    classification_counts = {
        'restricted': 0,
        'confidential': 0,
        'internal': 0,
        'public': 0,
        'total': 0
    }
    
    classification_details = {
         'restricted': {'consultations': 0, 'medical_certificates': 0, 'prescriptions': 0, 'appointments': 0, 'administrative': 0, 'patient_documents': 0},
        'confidential': {'consultations': 0, 'medical_certificates': 0, 'prescriptions': 0, 'appointments': 0, 'administrative': 0, 'patient_documents': 0},
        'internal': {'consultations': 0, 'medical_certificates': 0, 'prescriptions': 0, 'appointments': 0, 'administrative': 0, 'patient_documents': 0},
        'public': {'consultations': 0, 'medical_certificates': 0, 'prescriptions': 0, 'appointments': 0, 'administrative': 0, 'patient_documents': 0}
    }
    
    # Records for the detailed overview table
    records = []
    
    try:
        # Fetch consultations with classification (exclude soft-deleted)
        consultations_res = supabase.table("consultations").select("id, created_at, classification, doctor_id, classification_method").eq("is_deleted", 0).execute()
        if consultations_res.data:
            for record in consultations_res.data:
                classification = record.get('classification', '').lower()
                if classification in classification_counts:
                    classification_counts[classification] += 1
                    classification_details[classification]['consultations'] += 1
                
                # Get doctor name and role
                doctor_id = record.get('doctor_id')
                doctor_name = 'Unknown'
                doctor_role = 'Unknown'
                if doctor_id:
                    try:
                        doctor_res = supabase.table("profiles").select("full_name, role").eq("id", doctor_id).single().execute()
                        if doctor_res.data:
                            doctor_name = doctor_res.data.get('full_name', 'Unknown')
                            doctor_role = doctor_res.data.get('role', 'Unknown')
                    except:
                        pass
                
                records.append({
                    'id': record.get('id', ''),
                    'type': 'Consultation',
                    'classification': record.get('classification', 'Internal').title(),
                    'method': _normalize_method(record.get('classification_method', 'Unknown')),
                    'creation_time': _format_creation_time(record.get('created_at', '')),
                    'uploaded_by': doctor_name,
                    'role': doctor_role
                })
        
        # Fetch medical certificates with classification (exclude soft-deleted)
        mc_res = supabase.table("medical_certificates").select("id, created_at, classification, doctor_id, classification_method").eq("is_deleted", 0).execute()
        if mc_res.data:
            for record in mc_res.data:
                classification = record.get('classification', '').lower()
                if classification in classification_counts:
                    classification_counts[classification] += 1
                    classification_details[classification]['medical_certificates'] += 1
                
                # Get doctor name and role
                doctor_id = record.get('doctor_id')
                doctor_name = 'Unknown'
                doctor_role = 'Unknown'
                if doctor_id:
                    try:
                        doctor_res = supabase.table("profiles").select("full_name, role").eq("id", doctor_id).single().execute()
                        if doctor_res.data:
                            doctor_name = doctor_res.data.get('full_name', 'Unknown')
                            doctor_role = doctor_res.data.get('role', 'Unknown')
                    except:
                        pass
                
                records.append({
                    'id': record.get('id', ''),
                    'type': 'Medical Certificate',
                    'classification': record.get('classification', 'Internal').title(),
                    'method': _normalize_method(record.get('classification_method', 'Unknown')),
                    'creation_time': _format_creation_time(record.get('created_at', '')),
                    'uploaded_by': doctor_name,
                    'role': doctor_role
                })

        # Fetch prescriptions with classification (exclude soft-deleted)
        prescriptions_res = supabase.table("prescriptions").select("id, created_at, classification, doctor_id, classification_method").eq("is_deleted", 0).execute()
        if prescriptions_res.data:
            for record in prescriptions_res.data:
                classification = record.get('classification', '').lower()
                if classification in classification_counts:
                    classification_counts[classification] += 1
                    classification_details[classification]['prescriptions'] += 1

                doctor_id = record.get('doctor_id')
                doctor_name = 'Unknown'
                doctor_role = 'Unknown'
                if doctor_id:
                    try:
                        doctor_res = supabase.table("profiles").select("full_name, role").eq("id", doctor_id).single().execute()
                        if doctor_res.data:
                            doctor_name = doctor_res.data.get('full_name', 'Unknown')
                            doctor_role = doctor_res.data.get('role', 'Unknown')
                    except:
                        pass

                records.append({
                    'id': record.get('id', ''),
                    'type': 'Prescription',
                    'classification': record.get('classification', 'Internal').title(),
                    'method': _normalize_method(record.get('classification_method', 'Unknown')),
                    'creation_time': _format_creation_time(record.get('created_at', '')),
                    'uploaded_by': doctor_name,
                    'role': doctor_role
                })

        # Fetch appointments with classification (exclude soft-deleted)
        try:
            appointments_res = supabase.table("appointments").select(
                "id, created_at, classification, classification_method, method, staff_id, patient_id, is_deleted"
            ).eq("is_deleted", 0).execute()
        except Exception as e:
            logger.warning(f"Appointments query with staff_id failed, retrying without staff_id: {e}")
            appointments_res = supabase.table("appointments").select(
                "id, created_at, classification, classification_method, method, patient_id, is_deleted"
            ).eq("is_deleted", 0).execute()
        if appointments_res.data:
            staff_ids = list({row.get("staff_id") for row in appointments_res.data if row.get("staff_id")})
            patient_ids = list({row.get("patient_id") for row in appointments_res.data if row.get("patient_id")})

            staff_map = {}
            patient_map = {}
            staff_profiles_map = {}
            patient_profiles_map = {}

            if staff_ids:
                staff_res = (
                    supabase.table("staff_profile")
                    .select("id, full_name")
                    .in_("id", staff_ids)
                    .execute()
                )
                if staff_res.data:
                    staff_map = {row.get("id"): row.get("full_name", "Unknown") for row in staff_res.data}

                staff_profile_res = (
                    supabase.table("profiles")
                    .select("id, full_name")
                    .in_("id", staff_ids)
                    .execute()
                )
                if staff_profile_res.data:
                    staff_profiles_map = {row.get("id"): row.get("full_name", "Unknown") for row in staff_profile_res.data}

            if patient_ids:
                patient_res = (
                    supabase.table("patient_profile")
                    .select("id, full_name")
                    .in_("id", patient_ids)
                    .execute()
                )
                if patient_res.data:
                    patient_map = {row.get("id"): row.get("full_name", "Unknown") for row in patient_res.data}

                patient_profile_res = (
                    supabase.table("profiles")
                    .select("id, full_name")
                    .in_("id", patient_ids)
                    .execute()
                )
                if patient_profile_res.data:
                    patient_profiles_map = {row.get("id"): row.get("full_name", "Unknown") for row in patient_profile_res.data}

            for record in appointments_res.data:
                classification = record.get('classification', '').lower()
                if classification in classification_counts:
                    classification_counts[classification] += 1
                    classification_details[classification]['appointments'] += 1

                method = (record.get("method") or "").lower()
                uploaded_by = "Unknown"
                role = "Unknown"

                if method == "walk-in":
                    staff_id = record.get("staff_id")
                    uploaded_by = staff_map.get(staff_id) or staff_profiles_map.get(staff_id) or "Unknown"
                    role = "staff"
                else:
                    patient_id = record.get("patient_id")
                    uploaded_by = patient_map.get(patient_id) or patient_profiles_map.get(patient_id) or "Unknown"
                    role = "patient"

                records.append({
                    'id': record.get('id', ''),
                    'type': 'Appointment',
                    'classification': record.get('classification', 'Internal').title(),
                    'method': _normalize_method(record.get('classification_method', 'Unknown')),
                    'creation_time': _format_creation_time(record.get('created_at', '')),
                    'uploaded_by': uploaded_by,
                    'role': role
                })
        
        # Fetch administrative records with classification (exclude soft-deleted)
        administrative_res = supabase.table("administrative").select("id, created_at, classification, staff_id, classification_method").eq("is_deleted", 0).execute()
        if administrative_res.data:
            # Get unique staff IDs
            admin_staff_ids = list({rec.get("staff_id") for rec in administrative_res.data if rec.get("staff_id")})
            
            staff_name_map = {}
            if admin_staff_ids:
                # Try staff_profile first
                try:
                    staff_profile_res = supabase.table("staff_profile").select("id, full_name").in_("id", admin_staff_ids).execute()
                    if staff_profile_res.data:
                        for staff in staff_profile_res.data:
                            staff_name_map[staff['id']] = staff.get('full_name', 'Unknown')
                except Exception as e:
                    logger.warning(f"Failed to fetch staff names from staff_profile: {e}")
                
                # Fallback to profiles table for any missing staff
                missing_staff_ids = [sid for sid in admin_staff_ids if sid not in staff_name_map]
                if missing_staff_ids:
                    try:
                        profiles_res = supabase.table("profiles").select("id, full_name").in_("id", missing_staff_ids).execute()
                        if profiles_res.data:
                            for profile in profiles_res.data:
                                staff_name_map[profile['id']] = profile.get('full_name', 'Unknown')
                    except Exception as e:
                        logger.warning(f"Failed to fetch staff names from profiles: {e}")
            
            for record in administrative_res.data:
                classification = record.get('classification', '').lower()
                if classification in classification_counts:
                    classification_counts[classification] += 1
                    classification_details[classification]['administrative'] += 1
                
                # Get staff name
                staff_id = record.get('staff_id')
                staff_name = staff_name_map.get(staff_id, 'Unknown')
                
                records.append({
                    'id': record.get('id', ''),
                    'type': 'Administrative Record',
                    'classification': record.get('classification', 'Internal').title(),
                    'method': _normalize_method(record.get('classification_method', 'Unknown')),
                    'creation_time': _format_creation_time(record.get('created_at', '')),
                    'uploaded_by': staff_name,
                    'role': 'staff'
                })
        
        # Fetch patient documents with classification
        patient_documents_res = supabase.table("patient_documents").select("id, created_at, user_id, filename, classification").execute()
        if patient_documents_res.data:
            # Get unique patient IDs
            patient_ids = list({doc.get("user_id") for doc in patient_documents_res.data if doc.get("user_id")})
            
            patient_name_map = {}
            if patient_ids:
                try:
                    patient_profile_res = supabase.table("patient_profile").select("id, full_name").in_("id", patient_ids).execute()
                    if patient_profile_res.data:
                        for patient in patient_profile_res.data:
                            patient_name_map[patient['id']] = patient.get('full_name', 'Unknown')
                except Exception as e:
                    logger.warning(f"Failed to fetch patient names from patient_profile: {e}")
                
                # Fallback to profiles table for any missing patients
                missing_patient_ids = [pid for pid in patient_ids if pid not in patient_name_map]
                if missing_patient_ids:
                    try:
                        profiles_res = supabase.table("profiles").select("id, full_name").in_("id", missing_patient_ids).execute()
                        if profiles_res.data:
                            for profile in profiles_res.data:
                                patient_name_map[profile['id']] = profile.get('full_name', 'Unknown')
                    except Exception as e:
                        logger.warning(f"Failed to fetch patient names from profiles: {e}")
            
            for record in patient_documents_res.data:
                classification = record.get('classification', '').lower()
                if classification in classification_counts:
                    classification_counts[classification] += 1
                    classification_details[classification]['patient_documents'] += 1
                
                # Get patient name
                patient_id = record.get('user_id')
                patient_name = patient_name_map.get(patient_id, 'Unknown')
                
                records.append({
                    'id': record.get('id', ''),
                    'type': 'Patient Document',
                    'classification': record.get('classification', 'Internal').title(),
                    'method': 'Automatic',  # Patient documents use auto-classification from DLP
                    'creation_time': _format_creation_time(record.get('created_at', '')),
                    'uploaded_by': patient_name,
                    'role': 'patient'
                })
        
        # Calculate total
        classification_counts['total'] = sum([
            classification_counts['restricted'],
            classification_counts['confidential'],
            classification_counts['internal'],
            classification_counts['public']
        ])
        
        # Sort records by creation time (newest first)
        records.sort(key=lambda x: x['creation_time'], reverse=True)
        
    except Exception as e:
        logger.warning(f"Failed to fetch classification counts: {e}")
    
    return render_template('admin/classification-matrix.html', 
                           classification_counts=classification_counts,
                           classification_details=classification_details,
                           records=records)


@app.route('/admin/security/account-deletion-requests')
@login_required
def admin_account_deletion_requests():
    """Display all patient-initiated account deletion requests for admin approval."""
    user_session = session.get('user')
    user_role = user_session.get('role', '').lower()
    
    if user_role not in ('admin', 'clinic_manager'):
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))
    
    # Fetch request stats
    request_stats = {
        'pending': 0,
        'approved': 0,
        'total': 0
    }
    
    pending_requests = []
    processed_requests = []
    
    try:
        # Fetch all account deletion requests ordered by creation time
        requests_res = supabase.table("account_deletion_requests").select("*").order("created_at", desc=False).execute()
        
        if requests_res.data:
            # Count by status
            for row in requests_res.data:
                status = row.get('status', 'pending').lower()
                if status in request_stats:
                    request_stats[status] += 1
            request_stats['total'] = len(requests_res.data)
            
            # Get all user IDs to fetch patient info
            user_ids = [row.get('user_id') for row in requests_res.data if row.get('user_id')]
            patient_info_map = {}
            
            if user_ids:
                try:
                    # Fetch patient profiles with encrypted NRIC
                    patient_res = supabase.table("patient_profile").select("id, full_name, nric_encrypted, dek_encrypted").in_("id", user_ids).execute()
                    
                    if patient_res.data:
                        for patient in patient_res.data:
                            patient_id = patient.get('id')
                            patient_name = patient.get('full_name', 'Unknown')
                            nric_masked = 'N/A'
                            
                            # Decrypt NRIC
                            try:
                                nric_decrypted = envelope_decrypt_field(patient.get('dek_encrypted', ''), patient.get('nric_encrypted', ''))
                                if nric_decrypted:
                                    nric_masked = re.sub(r'^(.)(.*?)(.{4})$', r'\1****\3', str(nric_decrypted))
                            except Exception as e:
                                logger.warning(f"Could not decrypt NRIC for patient {patient_id}: {e}")
                            
                            patient_info_map[patient_id] = {
                                'name': patient_name,
                                'nric': nric_masked
                            }
                except Exception as e:
                    logger.warning(f"Failed to fetch patient info: {e}")
            
            # Build request lists
            for row in requests_res.data:
                user_id = row.get('user_id')
                patient_info = patient_info_map.get(user_id, {'name': 'Unknown', 'nric': 'N/A'})
                
                request_obj = {
                    'id': row.get('id'),
                    'patient_name': patient_info['name'],
                    'patient_nric': patient_info['nric'],
                    'user_id': user_id,
                    'reason': row.get('reason', ''),
                    'status': row.get('status'),
                    'created_at': row.get('created_at', '').split('T')[0] if row.get('created_at') else '',
                    'approved_at': row.get('approved_at', '').split('T')[0] if row.get('approved_at') else '',
                    'approved_by': row.get('approved_by')
                }
                
                if row.get('status') == 'pending':
                    pending_requests.append(request_obj)
                else:
                    processed_requests.append(request_obj)
    
    except Exception as e:
        logger.error(f"Error fetching account deletion requests: {e}")
        flash('Error loading account deletion requests', 'error')
    
    return render_template('admin/account-deletion-requests.html',
                          request_stats=request_stats,
                          pending_requests=pending_requests,
                          processed_requests=processed_requests)


@app.route('/admin/account-deletion-requests/<request_id>/approve', methods=['POST'])
@login_required
def approve_account_deletion(request_id):
    """Approve an account deletion request and execute the deletion."""
    user_session = session.get('user')
    user_role = user_session.get('role', '').lower()
    
    if user_role not in ('admin', 'clinic_manager'):
        abort(403)
    
    try:
        # Fetch the deletion request
        request_res = supabase.table("account_deletion_requests").select("*").eq("id", request_id).single().execute()
        
        if not request_res.data:
            flash('Account deletion request not found', 'error')
            return redirect(url_for('admin_account_deletion_requests'))
        
        deletion_req = request_res.data
        user_id = deletion_req.get('user_id')
        
        # Update request status
        supabase.table("account_deletion_requests").update({
            "status": "approved",
            "approved_at": datetime.now(timezone.utc).isoformat(),
            "approved_by": user_session.get('user_id') or user_session.get('id')
        }).eq("id", request_id).execute()
        
        # Delete all patient-related data
        try:
            # Delete patient documents
            supabase.table("patient_documents").delete().eq("user_id", user_id).execute()
            
            # Delete appointments
            supabase.table("appointments").delete().eq("patient_id", user_id).execute()
            
            # Delete consultations
            supabase.table("consultations").delete().eq("patient_id", user_id).execute()
            
            # Delete prescriptions
            supabase.table("prescriptions").delete().eq("patient_id", user_id).execute()
            
            # Delete medical certificates
            supabase.table("medical_certificates").delete().eq("patient_id", user_id).execute()
            
            # Delete patient profile
            supabase.table("patient_profile").delete().eq("id", user_id).execute()
            
            # Delete user profile
            supabase.table("profiles").delete().eq("id", user_id).execute()
            
            # Delete the Supabase Auth user account (requires service role key)
            try:
                # Check if we have service role permissions
                service_role_key = os.environ.get('SUPABASE_SERVICE_ROLE_KEY')
                if service_role_key:
                    # Create admin client with service role key
                    admin_client = create_client(
                        os.environ.get('SUPABASE_URL'),
                        service_role_key
                    )
                    admin_client.auth.admin.delete_user(user_id)
                    logger.info(f"Deleted Supabase Auth user {user_id}")
                else:
                    # Try with regular client (may fail if not service role)
                    supabase.auth.admin.delete_user(user_id)
                    logger.info(f"Deleted Supabase Auth user {user_id}")
            except Exception as auth_err:
                logger.warning(f"Could not delete Supabase Auth user {user_id}: {auth_err}. User profile deleted - login will fail anyway.")
            
            # Log the event
            log_phi_event(
                action="APPROVE_ACCOUNT_DELETION",
                classification="restricted",
                record_id=request_id,
                target_user_id=user_id,
                allowed=True,
                extra={"reason": deletion_req.get('reason', '')[:100]}
            )
            
            logger.info(f"Admin {user_session.get('user_id')} approved and executed account deletion for patient {user_id}")
            flash('Account deletion approved and executed successfully', 'success')
        except Exception as e:
            logger.error(f"Error deleting user data: {e}")
            flash('Account deletion approved but encountered errors during data deletion', 'warning')
    
    except Exception as e:
        logger.error(f"Error approving account deletion: {e}")
        flash(f'Error approving request: {str(e)}', 'error')
    
    return redirect(url_for('admin_account_deletion_requests'))


@app.route('/admin/security/erasure-requests')
@login_required
def admin_erasure_requests():
    """Display all data erasure requests for admin approval."""
    user_session = session.get('user')
    user_role = user_session.get('role', '').lower()
    
    if user_role not in ('admin'):
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))
    
    # Fetch all erasure requests with counts by status
    request_stats = {
        'pending': 0,
        'approved': 0,
        'rejected': 0,
        'total': 0
    }
    
    erasure_requests = []
    pending_requests = []
    processed_requests = []
    
    try:
        # Fetch all erasure requests ordered by creation time (FCFS)
        requests_res = (
            supabase.table("data_erasure_requests")
            .select("id, requester_id, requester_role, status, reason, documents, created_at, approved_at, rejected_at, rejection_reason")
            .order("created_at", desc=False)  # FCFS - oldest first
            .execute()
        )
        
        if requests_res.data:
            # Count by status
            for row in requests_res.data:
                status = row.get('status', 'pending').lower()
                if status in request_stats:
                    request_stats[status] += 1
            request_stats['total'] = len(requests_res.data)
            
            # Get unique requester IDs and patient IDs from documents
            requester_ids = set()
            patient_ids = set()
            document_details = {}
            
            for row in requests_res.data:
                requester_id = row.get('requester_id')
                if requester_id:
                    requester_ids.add(requester_id)
                
                # Parse documents to extract patient IDs
                docs = row.get('documents') or []
                for doc_value in docs:
                    if isinstance(doc_value, str) and ':' in doc_value:
                        doc_type, doc_id = doc_value.split(':', 1)
                        if doc_type not in document_details:
                            document_details[doc_type] = []
                        document_details[doc_type].append(doc_id)
            
            # Fetch requester information (doctors and staff)
            requester_map = {}
            if requester_ids:
                try:
                    # Fetch doctor requesters
                    requester_res = (
                        supabase.table("doctor_profile")
                        .select("id, full_name")
                        .in_("id", list(requester_ids))
                        .execute()
                    )
                    if requester_res.data:
                        requester_map = {row.get('id'): row.get('full_name', 'Unknown') for row in requester_res.data}
                    
                    # Fetch staff requesters from staff_profile
                    staff_res = (
                        supabase.table("staff_profile")
                        .select("id, full_name")
                        .in_("id", list(requester_ids))
                        .execute()
                    )
                    if staff_res.data:
                        for row in staff_res.data:
                            requester_map[row.get('id')] = row.get('full_name', 'Unknown')
                    
                    # Fallback: fetch from profiles table for any missing requesters
                    missing_ids = [rid for rid in requester_ids if rid not in requester_map]
                    if missing_ids:
                        profile_res = (
                            supabase.table("profiles")
                            .select("id, full_name")
                            .in_("id", missing_ids)
                            .execute()
                        )
                        if profile_res.data:
                            for row in profile_res.data:
                                requester_map[row.get('id')] = row.get('full_name', 'Unknown')
                except Exception as e:
                    logger.warning(f"Failed to fetch requester information: {e}")
            
            # Fetch all documents to get patient IDs and details
            consultation_map = {}
            prescription_map = {}
            mc_map = {}
            administrative_map = {}
            appointment_map = {}
            patient_nric_map = {}
            
            if 'consultations' in document_details:
                try:
                    cons_res = (
                        supabase.table("consultations")
                        .select("id, patient_id, classification")
                        .in_("id", document_details['consultations'])
                        .execute()
                    )
                    if cons_res.data:
                        # store both patient_id and classification per consultation
                        consultation_map = {row.get('id'): {'patient_id': row.get('patient_id'), 'classification': row.get('classification')} for row in cons_res.data}
                        patient_ids.update([v.get('patient_id') for v in consultation_map.values() if v.get('patient_id')])
                except Exception as e:
                    logger.warning(f"Failed to fetch consultations: {e}")
            
            if 'prescriptions' in document_details:
                try:
                    presc_res = (
                        supabase.table("prescriptions")
                        .select("id, patient_id, classification")
                        .in_("id", document_details['prescriptions'])
                        .execute()
                    )
                    if presc_res.data:
                        prescription_map = {row.get('id'): {'patient_id': row.get('patient_id'), 'classification': row.get('classification')} for row in presc_res.data}
                        patient_ids.update([v.get('patient_id') for v in prescription_map.values() if v.get('patient_id')])
                except Exception as e:
                    logger.warning(f"Failed to fetch prescriptions: {e}")
            
            if 'medical_certificates' in document_details:
                try:
                    mc_res = (
                        supabase.table("medical_certificates")
                        .select("id, patient_id, classification")
                        .in_("id", document_details['medical_certificates'])
                        .execute()
                    )
                    if mc_res.data:
                        mc_map = {row.get('id'): {'patient_id': row.get('patient_id'), 'classification': row.get('classification')} for row in mc_res.data}
                        patient_ids.update([v.get('patient_id') for v in mc_map.values() if v.get('patient_id')])
                except Exception as e:
                    logger.warning(f"Failed to fetch medical certificates: {e}")
            
            if 'administrative' in document_details:
                try:
                    admin_res = (
                        supabase.table("administrative")
                        .select("id, title, classification, staff_id")
                        .in_("id", document_details['administrative'])
                        .execute()
                    )
                    if admin_res.data:
                        administrative_map = {row.get('id'): {'title': row.get('title'), 'classification': row.get('classification'), 'staff_id': row.get('staff_id')} for row in admin_res.data}
                except Exception as e:
                    logger.warning(f"Failed to fetch administrative records: {e}")
            
            if 'appointments' in document_details:
                try:
                    appt_res = (
                        supabase.table("appointments")
                        .select("id, patient_id, classification, method")
                        .in_("id", document_details['appointments'])
                        .execute()
                    )
                    if appt_res.data:
                        appointment_map = {row.get('id'): {'patient_id': row.get('patient_id'), 'classification': row.get('classification'), 'method': row.get('method')} for row in appt_res.data}
                        patient_ids.update([v.get('patient_id') for v in appointment_map.values() if v.get('patient_id')])
                except Exception as e:
                    logger.warning(f"Failed to fetch appointments: {e}")
            
            # Fetch patient information (names and NRICs)
            if patient_ids:
                try:
                    patient_res = (
                        supabase.table("patient_profile")
                        .select("id, full_name, nric_encrypted, dek_encrypted")
                        .in_("id", list(patient_ids))
                        .execute()
                    )
                    if patient_res.data:
                        for patient in patient_res.data:
                            patient_id = patient.get('id')
                            patient_name = patient.get('full_name', 'Unknown')
                            
                            # Decrypt NRIC
                            masked_nric = "N/A"
                            try:
                                nric_decrypted = envelope_decrypt_field(patient.get('dek_encrypted', ''), patient.get('nric_encrypted', ''))
                                if nric_decrypted:
                                    masked_nric = re.sub(r'^(.)(.*?)(....)$', r'\1****\3', str(nric_decrypted))
                            except Exception as e:
                                logger.warning(f"Could not decrypt NRIC for patient {patient_id}: {e}")
                            
                            patient_nric_map[patient_id] = {
                                'name': patient_name,
                                'nric': masked_nric
                            }
                except Exception as e:
                    logger.warning(f"Failed to fetch patient information: {e}")
            
            # Build erasure requests list (separate pending and processed)
            pending_requests = []
            processed_requests = []

            for row in requests_res.data:
                requester_id = row.get('requester_id')
                requester_name = requester_map.get(requester_id, 'Unknown')
                status = row.get('status', 'pending').lower()

                if status == 'pending':
                    # Build target records list for pending requests
                    target_records = []
                    docs = row.get('documents') or []

                    for doc_value in docs:
                        if isinstance(doc_value, str) and ':' in doc_value:
                            doc_type, doc_id = doc_value.split(':', 1)

                            # Get patient ID and classification info
                            patient_id = None
                            classification = None

                            if doc_type == 'consultations':
                                entry = consultation_map.get(doc_id)
                                if entry:
                                    patient_id = entry.get('patient_id')
                                    classification = entry.get('classification')
                            elif doc_type == 'prescriptions':
                                entry = prescription_map.get(doc_id)
                                if entry:
                                    patient_id = entry.get('patient_id')
                                    classification = entry.get('classification')
                            elif doc_type == 'medical_certificates':
                                entry = mc_map.get(doc_id)
                                if entry:
                                    patient_id = entry.get('patient_id')
                                    classification = entry.get('classification')
                            elif doc_type == 'administrative':
                                entry = administrative_map.get(doc_id)
                                if entry:
                                    # Administrative records don't have patient_id
                                    display_type = 'Administrative Record'
                                    target_records.append({
                                        'type': display_type,
                                        'patient_name': entry.get('title', 'Untitled'),
                                        'nric': 'N/A',
                                        'doc_id': doc_id,
                                        'doc_type': doc_type,
                                        'classification': entry.get('classification', 'internal')
                                    })
                                    continue  # Skip patient lookup for administrative
                            elif doc_type == 'appointments':
                                entry = appointment_map.get(doc_id)
                                if entry:
                                    patient_id = entry.get('patient_id')
                                    classification = entry.get('classification')

                            if patient_id:
                                patient_info = patient_nric_map.get(patient_id, {})

                                # Determine display type name
                                display_type = 'Unknown'
                                if doc_type == 'consultations':
                                    display_type = 'Consultation'
                                elif doc_type == 'prescriptions':
                                    display_type = 'Prescription'
                                elif doc_type == 'medical_certificates':
                                    display_type = 'Medical Certificate'
                                elif doc_type == 'appointments':
                                    display_type = 'Walk-in Appointment'

                                target_records.append({
                                    'type': display_type,
                                    'patient_name': patient_info.get('name', 'Unknown'),
                                    'nric': patient_info.get('nric', 'N/A'),
                                    'doc_id': doc_id,
                                    'doc_type': doc_type,
                                    'classification': classification or 'restricted'
                                })

                    pending_requests.append({
                        'id': row.get('id'),
                        'requester_name': requester_name,
                        'requester_role': row.get('requester_role', 'doctor').title(),
                        'status': status,
                        'reason': row.get('reason', ''),
                        'created_at': _format_creation_time(row.get('created_at', '')),
                        'target_records': target_records,
                        'target_count': len(target_records)
                    })
                else:
                    # Processed requests (approved/rejected) - add to recently processed list
                    processed_requests.append({
                        'id': row.get('id'),
                        'status': status,
                        'requester_name': requester_name,
                        'requester_role': row.get('requester_role', 'doctor').title(),
                        'approved_at': _format_creation_time(row.get('approved_at')) if row.get('approved_at') else None,
                        'rejected_at': _format_creation_time(row.get('rejected_at')) if row.get('rejected_at') else None,
                        'rejection_reason': row.get('rejection_reason') or '',
                        'processed_at_raw': row.get('approved_at') or row.get('rejected_at') or ''
                    })

            # Sort processed requests (most recent first)
            try:
                processed_requests.sort(key=lambda x: x.get('processed_at_raw') or '', reverse=True)
            except Exception:
                pass

            # --- Identify retention-expired documents for manual erasure ---
            expired_items = []
            try:
                # Query each table for potential expired documents
                tables = [
                    ('consultations', 'Consultation'),
                    ('prescriptions', 'Prescription'),
                    ('medical_certificates', 'Medical Certificate'),
                    ('appointments', 'Appointment'),
                    ('administrative', 'Administrative')
                ]
                expired_patient_ids = set()
                for table_name, display in tables:
                    try:
                        if table_name == 'administrative':
                            res = supabase.table(table_name).select('id, title, staff_id, classification, expiry_date, created_at').execute()
                        else:
                            res = supabase.table(table_name).select('id, patient_id, classification, expiry_date, created_at').execute()
                        if res.data:
                            for doc in res.data:
                                if is_retention_expired(doc.get('expiry_date')):
                                    if table_name == 'administrative':
                                        expired_items.append({
                                            'doc_type': table_name,
                                            'type_display': display,
                                            'doc_id': doc.get('id'),
                                            'patient_id': None,
                                            'classification': doc.get('classification', 'internal'),
                                            'expiry_date': doc.get('expiry_date'),
                                            'created_at': _format_creation_time(doc.get('created_at')),
                                            'patient_name': doc.get('title', 'Untitled'),
                                            'nric': 'N/A'
                                        })
                                    else:
                                        pid = doc.get('patient_id')
                                        expired_items.append({
                                            'doc_type': table_name,
                                            'type_display': display,
                                            'doc_id': doc.get('id'),
                                            'patient_id': pid,
                                            'classification': doc.get('classification', 'restricted'),
                                            'expiry_date': doc.get('expiry_date'),
                                            'created_at': _format_creation_time(doc.get('created_at'))
                                        })
                                        if pid:
                                            expired_patient_ids.add(pid)
                    except Exception as e:
                        logger.warning(f"Failed to fetch from {table_name}: {e}")

                # Fetch patient info for expired items (if not already present)
                missing_patient_ids = [pid for pid in expired_patient_ids if pid not in patient_nric_map]
                if missing_patient_ids:
                    try:
                        patient_res2 = (
                            supabase.table('patient_profile')
                            .select('id, full_name, nric_encrypted, dek_encrypted')
                            .in_('id', missing_patient_ids)
                            .execute()
                        )
                        if patient_res2.data:
                            for patient in patient_res2.data:
                                patient_id = patient.get('id')
                                masked_nric = 'N/A'
                                try:
                                    nric_decrypted = envelope_decrypt_field(patient.get('dek_encrypted', ''), patient.get('nric_encrypted', ''))
                                    if nric_decrypted:
                                        masked_nric = re.sub(r'^(.)(.*?)(....)$', r'\1****\3', str(nric_decrypted))
                                except Exception as e:
                                    logger.warning(f"Could not decrypt NRIC for patient {patient_id}: {e}")
                                patient_nric_map[patient_id] = {
                                    'name': patient.get('full_name', 'Unknown'),
                                    'nric': masked_nric
                                }
                    except Exception as e:
                        logger.warning(f"Failed to fetch patient info for expired items: {e}")

                # Attach patient info to expired items
                for item in expired_items:
                    pid = item.get('patient_id')
                    if pid:
                        pinfo = patient_nric_map.get(pid, {})
                        item['patient_name'] = pinfo.get('name', 'Unknown')
                        item['nric'] = pinfo.get('nric', 'N/A')

            except Exception as e:
                logger.error(f"Error identifying expired documents: {e}")

    except Exception as e:
        logger.error(f"Error loading erasure requests: {e}")
        flash('Error loading erasure requests', 'error')
    
    return render_template(
        'admin/erasure-requests.html',
        request_stats=request_stats,
        pending_requests=pending_requests,
        processed_requests=processed_requests,
        expired_erasures=expired_items
    )


@app.route('/admin/security/erasure-requests/<request_id>/approve', methods=['POST'])
@login_required
def approve_erasure_request(request_id):
    """Approve an erasure request and execute lifecycle-based deletion."""
    user_session = session.get('user')
    user_role = user_session.get('role', '').lower()
    
    if user_role not in ('admin', 'clinic_manager'):
        flash('Unauthorized', 'error')
        return redirect(url_for('admin_erasure_requests'))
    
    try:
        # Fetch the erasure request
        request_res = (
            supabase.table("data_erasure_requests")
            .select("*")
            .eq("id", request_id)
            .single()
            .execute()
        )
        
        if not request_res.data:
            flash('Erasure request not found', 'error')
            return redirect(url_for('admin_erasure_requests'))
        
        erasure_req = request_res.data
        docs = erasure_req.get('documents') or []
        
        # Update status to approved
        supabase.table("data_erasure_requests").update({
            "status": "approved",
            "approved_at": datetime.now(timezone.utc).isoformat(),
            "approved_by": user_session.get('user_id') or user_session.get('id')
        }).eq("id", request_id).execute()
        
        # Execute lifecycle-based deletion for each document
        for doc_value in docs:
            if isinstance(doc_value, str) and ':' in doc_value:
                doc_type, doc_id = doc_value.split(':', 1)
                execute_lifecycle_deletion(doc_type, doc_id)
        
        log_phi_event(
            action="APPROVE_ERASURE_REQUEST",
            classification="restricted",
            record_id=request_id,
            allowed=True,
            extra={"documents_count": len(docs), "approver": user_session.get('full_name', 'Unknown')}
        )
        
        flash('Erasure request approved and deletion executed', 'success')
        return redirect(url_for('admin_erasure_requests'))
    
    except Exception as e:
        logger.error(f"Error approving erasure request: {e}")
        flash(f'Error approving request: {str(e)}', 'error')
        return redirect(url_for('admin_erasure_requests'))


@app.route('/admin/security/erasure-requests/<request_id>/reject', methods=['POST'])
@login_required
def reject_erasure_request(request_id):
    """Reject an erasure request."""
    user_session = session.get('user')
    user_role = user_session.get('role', '').lower()
    
    if user_role not in ('admin', 'clinic_manager'):
        flash('Unauthorized', 'error')
        return redirect(url_for('admin_erasure_requests'))
    
    try:
        reason = request.form.get('rejection_reason', '').strip()
        
        # Update status to rejected
        supabase.table("data_erasure_requests").update({
            "status": "rejected",
            "rejection_reason": reason,
            "rejected_at": datetime.now(timezone.utc).isoformat(),
            "rejected_by": user_session.get('user_id') or user_session.get('id')
        }).eq("id", request_id).execute()
        
        log_phi_event(
            action="REJECT_ERASURE_REQUEST",
            classification="restricted",
            record_id=request_id,
            allowed=True,
            extra={"rejection_reason": reason}
        )
        
        flash('Erasure request rejected', 'success')
        return redirect(url_for('admin_erasure_requests'))
    
    except Exception as e:
        logger.error(f"Error rejecting erasure request: {e}")
        flash(f'Error rejecting request: {str(e)}', 'error')
        return redirect(url_for('admin_erasure_requests'))


def execute_lifecycle_deletion(doc_type: str, doc_id: str):
    """Execute lifecycle-based deletion based on retention expiry and data sensitivity.
    
    Rules:
    1. Retention Expired (>90 days) → Hard Delete
    2. Retention NOT Expired + PII/PHI (restricted/confidential) → Anonymize
    3. Retention NOT Expired + No PII (internal/public) → Soft Delete And/Or Anonymize (for appointments)
    """
    try:
        if doc_type == 'consultations':
            table_name = 'consultations'
        elif doc_type == 'prescriptions':
            table_name = 'prescriptions'
        elif doc_type == 'medical_certificates':
            table_name = 'medical_certificates'
        elif doc_type == 'administrative':
            table_name = 'administrative'
        elif doc_type == 'appointments':
            table_name = 'appointments'
        else:
            logger.warning(f"Unknown document type for deletion: {doc_type}")
            return
        
        # Fetch the document
        doc_res = supabase.table(table_name).select("*").eq("id", doc_id).single().execute()
        
        if not doc_res.data:
            logger.warning(f"Document not found: {doc_type}:{doc_id}")
            return
        
        document = doc_res.data
        is_expired = is_retention_expired(document.get('expiry_date'))
        classification = document.get('classification', 'internal').lower()
        
        # === LIFECYCLE DELETION DECISION TREE ===
        
        if is_expired:
            # Rule 1: Retention expired → Hard delete
            logger.info(f"Hard deleting {doc_type}:{doc_id} (retention expired >90 days)")
            supabase.table(table_name).delete().eq("id", doc_id).execute()
            
            # If administrative record, also hard delete its attachments
            if doc_type == 'administrative':
                try:
                    attachments_res = (
                        supabase.table("administrative_attachments")
                        .select("id, file_path")
                        .eq("administrative_id", doc_id)
                        .execute()
                    )
                    if attachments_res.data:
                        for attachment in attachments_res.data:
                            # Delete file from disk
                            file_path = os.path.join(app.instance_path, 'uploads', attachment.get('file_path', ''))
                            if os.path.exists(file_path):
                                os.remove(file_path)
                            # Delete from database
                            supabase.table("administrative_attachments").delete().eq("id", attachment.get('id')).execute()
                            logger.info(f"Hard deleted administrative attachment: {attachment.get('id')}")
                except Exception as e:
                    logger.error(f"Error hard deleting attachments for administrative {doc_id}: {e}")
        
        elif classification in ('restricted', 'confidential'):
            # Rule 2: Retention NOT expired + PII/PHI → Anonymize
            logger.info(f"Anonymizing {doc_type}:{doc_id} (retention active + PII/PHI)")
            anonymize_document(table_name, doc_id, document)
        
        else:  # internal or public
            # Rule 3: Retention NOT expired + No PII → Soft delete and/or Anonymize
            # Special case: Appointments contain PII (patient_id) even if classified as internal
            if doc_type == 'appointments':
                logger.info(f"Anonymizing {doc_type}:{doc_id} (retention active but contains PII)")
                anonymize_document(table_name, doc_id, document)
                # Also mark as deleted for consistency
                supabase.table(table_name).update({"is_deleted": 1}).eq("id", doc_id).execute()
            else:
                # For administrative records (no direct PII), soft delete is sufficient
                logger.info(f"Soft deleting {doc_type}:{doc_id} (retention active + no PII)")
                supabase.table(table_name).update({"is_deleted": 1}).eq("id", doc_id).execute()
                
                # If administrative record, also soft delete its attachments
                if doc_type == 'administrative':
                    try:
                        supabase.table("administrative_attachments").update({
                            "is_deleted": 1
                        }).eq("administrative_id", doc_id).execute()
                        logger.info(f"Soft deleted attachments for administrative {doc_id}")
                    except Exception as e:
                        logger.error(f"Error soft deleting attachments for administrative {doc_id}: {e}")
    
    except Exception as e:
        logger.error(f"Error executing lifecycle deletion for {doc_type}:{doc_id}: {e}")


@app.route('/admin/security/retention-expired/<doc_type>/<doc_id>/erase', methods=['POST'])
@login_required
def execute_retention_erasure(doc_type, doc_id):
    """Manually execute erasure for a retention-expired document."""
    user_session = session.get('user')
    user_role = user_session.get('role', '').lower()
    if user_role not in ('admin', 'clinic_manager'):
        flash('Unauthorized', 'error')
        return redirect(url_for('admin_erasure_requests'))
    try:
        # Only allow known doc types
        if doc_type not in ('consultations', 'prescriptions', 'medical_certificates', 'administrative', 'appointments'):
            flash('Invalid document type', 'error')
            return redirect(url_for('admin_erasure_requests'))

        # Execute lifecycle deletion (will hard-delete if expired)
        execute_lifecycle_deletion(doc_type, doc_id)

        log_phi_event(
            action="EXECUTE_RETENTION_ERASURE",
            classification="restricted",
            record_id=f"{doc_type}:{doc_id}",
            allowed=True
        )

        flash('Retention expired erasure executed', 'success')
        return redirect(url_for('admin_erasure_requests'))
    except Exception as e:
        logger.error(f"Error executing retention erasure for {doc_type}:{doc_id}: {e}")
        flash(f'Error executing erasure: {str(e)}', 'error')
        return redirect(url_for('admin_erasure_requests'))


def anonymize_document(table_name: str, doc_id: str, document: dict):
    """Anonymize a document by replacing sensitive data while preserving required fields."""
    try:
        anonymized_data = {}
        
        if table_name == 'consultations':
            anonymized_data = {
                "patient_id": None,
                "doctor_id": None,
                "doctor_name": None,
                "clinical_notes_encrypted": None,
                "dek_encrypted": None
            }
        elif table_name == 'prescriptions':
            anonymized_data = {
                "patient_id": None,
                "doctor_id": None,
            }
        elif table_name == 'medical_certificates':
            # Anonymize dates: keep year-month, remove day (set to 1st of month)
            start_date = document.get('start_date')
            end_date = document.get('end_date')
            
            # Extract YYYY-MM and append -01 for first day of month
            start_date_anonymized = start_date[:7] + "-01" if start_date else None
            end_date_anonymized = end_date[:7] + "-01" if end_date else None
            
            anonymized_data = {
                "patient_id": None,
                "doctor_id": None,
                "doctor_name": None,
                "start_date": start_date_anonymized,
                "end_date": end_date_anonymized,
                "duration_days": None,
                "mc_number": None
            }
        elif table_name == 'appointments':
            anonymized_data = {
                "patient_id": None,
                "doctor_id": None,
                "staff_id": None,
                "notes": None
            }
        
        supabase.table(table_name).update(anonymized_data).eq("id", doc_id).execute()
        logger.info(f"Successfully anonymized {table_name}:{doc_id}")
    
    except Exception as e:
        logger.error(f"Error anonymizing document {table_name}:{doc_id}: {e}")


@app.route('/book-appointment', methods=['GET', 'POST'])
@login_required
def book_appointment():
    user_session = session.get('user')
    user_id = user_session.get('user_id') or user_session.get('id')
    
    # Fetch and decrypt profile data
    try:
        profile_res = (
            supabase.table("profiles")
            .select("*")
            .eq("id", user_id)
            .single()
            .execute()
        )
        
        if profile_res.data:
            profile_data = get_profile_with_decryption(profile_res.data, user_session)
            masked_data = apply_policy_masking(user_session, profile_data)
        else:
            masked_data = user_session
    except Exception as e:
        logger.error(f"Error fetching profile for book appointment: {e}")
        masked_data = user_session
    
    # Fetch doctors from doctor_profile table
    try:
        doctors_res = supabase.table("doctor_profile").select("id, full_name, specialty, mcr_number, email").execute()
        
        doctors_list = []
        if doctors_res.data:
            for doc in doctors_res.data:
                doctor_info = {
                    "id": str(doc.get('id')),  # Ensure ID is a string
                    "name": doc.get('full_name', 'N/A'),
                    "specialty": doc.get('specialty', 'General Practitioner'),
                    "experience": "Licensed Professional",
                    "availability": "Mon - Fri"
                }
                doctors_list.append(doctor_info)
        
        logger.info(f"Loaded {len(doctors_list)} doctors from database")
        if doctors_list:
            logger.debug(f"First doctor: id={doctors_list[0].get('id')}, name={doctors_list[0].get('name')}, id_type={type(doctors_list[0].get('id'))}")
        
        if not doctors_list:
            logger.warning("No doctors found in database")
            flash("No doctors available at the moment. Please try again later.", "warning")
            
    except Exception as e:
        logger.error(f"Error fetching doctors: {e}")
        doctors_list = []
        flash("Error loading doctors list", "error")
    
    if request.method == 'POST':
        try:
            # Extract booking data from form
            doctor_id = request.form.get('doctor_id')
            appointment_date = request.form.get('date')
            appointment_time = request.form.get('time')
            visit_type = request.form.get('visit_type')
            notes = request.form.get('notes', '')
            
            logger.info(f"Form submission - doctor_id={doctor_id}, date={appointment_date}, time={appointment_time}, type={visit_type}")
            
            # Validate required fields
            if not all([doctor_id, appointment_date, appointment_time, visit_type]):
                logger.warning(f"Missing required fields in booking request")
                flash('Please fill in all required fields', 'error')
                return render_template('patient/book-appointment.html', doctors=doctors_list, user=masked_data)
            
            # Validate doctor_id is a valid UUID format
            if not _is_valid_uuid(doctor_id):
                logger.error(f"Invalid doctor_id format: {doctor_id}")
                flash('Invalid doctor selection. Please try again.', 'error')
                return render_template('patient/book-appointment.html', doctors=doctors_list, user=masked_data)
            
            # Combine date and time into datetime
            appointment_datetime = f"{appointment_date} {appointment_time}"
            
            # Prepare booking record
            booking_data = {
                "patient_id": user_id,
                "doctor_id": doctor_id,
                "appointment_date": appointment_date,
                "appointment_time": appointment_time,
                "appointment_datetime": appointment_datetime,
                "visit_type": visit_type,
                "notes": notes,
                "status": "waiting",  # Options: waiting, in_progress, completed, cancelled
                "method": "self-book",
                "classification": "internal",
                "classification_method": "Automatic",
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            
            # Insert booking into database
            insert_res = supabase.table("appointments").insert(booking_data).execute()
            
            if insert_res.data:
                logger.info(f"Appointment booked: {user_id} with doctor {doctor_id} on {appointment_date} at {appointment_time}")
                
                # Log PHI event
                log_phi_event(
                    action="BOOK_APPOINTMENT",
                    classification="restricted",
                    record_id=insert_res.data[0].get('id') if isinstance(insert_res.data, list) else None,
                    target_user_id=user_id,
                    allowed=True,
                    extra={"doctor_id": doctor_id, "appointment_date": appointment_date}
                )
                
                flash('Appointment booked successfully!', 'success')
                return render_template('patient/book-appointment.html', doctors=doctors_list, booking_success=True)
            else:
                logger.error("Failed to insert appointment booking")
                flash('Error booking appointment. Please try again.', 'error')
                
        except Exception as e:
            logger.error(f"Error booking appointment: {str(e)}")
            flash(f'Error booking appointment: {str(e)}', 'error')
    
    return render_template('patient/book-appointment.html', doctors=doctors_list, user=masked_data)

@app.route('/appointment-history')
@login_required
def appointment_history():
    user_session = session.get('user')
    user_id = user_session.get('user_id') or user_session.get('id')
    
    appointments_list = []
    
    try:
        # Fetch appointments for this patient (exclude soft-deleted)
        appointments_res = (
            supabase.table("appointments")
            .select("*")
            .eq("patient_id", user_id)
            .eq("is_deleted", 0)
            .order("appointment_datetime", desc=True)
            .execute()
        )
        
        if appointments_res.data:
            # Get unique doctor IDs
            doctor_ids = list(set([a.get('doctor_id') for a in appointments_res.data if a.get('doctor_id')]))
            
            # Fetch doctor names and specialties
            doctor_map = {}
            if doctor_ids:
                try:
                    doctors_res = (
                        supabase.table("doctor_profile")
                        .select("id, full_name, specialty")
                        .in_("id", doctor_ids)
                        .execute()
                    )
                    if doctors_res.data:
                        doctor_map = {
                            doc['id']: {
                                'name': doc['full_name'],
                                'specialty': doc.get('specialty', 'General Practitioner')
                            } for doc in doctors_res.data
                        }
                except Exception as e:
                    logger.warning(f"Failed to fetch doctor info: {e}")
            
            # Build appointments list
            for appt in appointments_res.data:
                doctor_info = doctor_map.get(appt.get('doctor_id'), {'name': 'Unknown Doctor', 'specialty': 'N/A'})
                
                # Format datetime
                appointment_datetime = appt.get('appointment_datetime', '')
                appointment_date = appt.get('appointment_date', '')
                appointment_time = appt.get('appointment_time', '')
                
                if appointment_datetime:
                    try:
                        dt_obj = datetime.fromisoformat(appointment_datetime.replace('Z', '+00:00'))
                        formatted_date = dt_obj.strftime('%d %b %Y')
                        formatted_time = dt_obj.strftime('%I:%M %p')
                    except:
                        formatted_date = appointment_date
                        formatted_time = appointment_time
                else:
                    formatted_date = appointment_date
                    formatted_time = appointment_time
                
                # Generate tokenized ID
                appt_id = appt.get('id', '')
                token_id = f"APT-{int(hashlib.sha256(f'{appt_id}{user_id}'.encode()).hexdigest(), 16) % 1000000:06d}"
                
                # Capitalize visit type
                visit_type = appt.get('visit_type', 'general')
                visit_type_display = visit_type.capitalize() if visit_type else 'General'
                
                # Get status
                status = appt.get('status', 'waiting')
                status_display = status.capitalize()
                
                # Get method
                method = appt.get('method', 'self-book')
                method_display = method.capitalize() if method else 'Self-book'
                
                appointment_obj = {
                    'id': appt_id,
                    'token_id': token_id,
                    'date': formatted_date,
                    'time': formatted_time,
                    'datetime': appointment_datetime,
                    'doctor': doctor_info['name'],
                    'specialty': doctor_info['specialty'],
                    'visit_type': visit_type_display,
                    'status': status_display,
                    'method': method_display,
                    'notes': appt.get('notes', '')
                }
                
                appointments_list.append(appointment_obj)
        
    except Exception as e:
        logger.error(f"Error fetching appointment history: {e}")
        flash("Error loading appointment history", "error")
    
    # Log viewing appointment history
    log_phi_event(
        action="VIEW_APPOINTMENT_HISTORY",
        classification="internal",
        target_user_id=user_id,
        allowed=True,
        extra={"count": len(appointments_list)}
    )
    
    return render_template('patient/appointment-history.html', appointments=appointments_list)

@app.route('/medical-certificates')
@login_required
def medical_certificates():
    user_session = session.get('user')
    user_id = user_session.get('user_id') or user_session.get('id')
    
    try:
        # Fetch patient profile for name and NRIC
        profile_res = supabase.table("patient_profile").select("*").eq("id", user_id).single().execute()
        
        patient_name = "Unknown"
        nric_masked = "****"
        
        if profile_res.data:
            patient_name = profile_res.data.get("full_name", "Unknown")
            
            # Decrypt NRIC if encrypted
            try:
                nric_encrypted = profile_res.data.get("nric_encrypted")
                dek_encrypted = profile_res.data.get("dek_encrypted")
                
                if nric_encrypted and dek_encrypted:
                    nric_decrypted = envelope_decrypt_field(dek_encrypted, nric_encrypted)
                    if nric_decrypted:
                        # Mask NRIC: show first char, ****, last 4 chars (e.g., S****871A)
                        nric_masked = re.sub(r'^(.)(.*?)(.{4})$', r'\1****\3', str(nric_decrypted))
            except Exception as e:
                logger.warning(f"Failed to decrypt NRIC for patient {user_id}: {e}")
        
        # Fetch medical certificates for this patient (exclude soft-deleted)
        mc_res = supabase.table("medical_certificates").select("*").eq("patient_id", user_id).eq("is_deleted", 0).execute()
        
        certificates = []
        if mc_res.data:
            for mc in mc_res.data:
                # Use tokenized ID from database, or generate fallback for old records
                tokenized_id = mc.get('mc_number')
                if not tokenized_id:
                    # Fallback for legacy records without mc_number
                    tokenized_id = generate_token("mc")
                    mc_id = mc.get('id')
                    if mc_id:
                        try:
                            supabase.table("medical_certificates").update({"mc_number": tokenized_id}).eq("id", mc_id).execute()
                        except Exception as e:
                            logger.warning(f"Failed to backfill mc_number for medical certificate {mc_id}: {e}")
                
                cert_dict = {
                    'id': mc.get('id'),
                    'status': mc.get('status', 'active'),
                    'doctor': mc.get('doctor_name', 'Doctor'),
                    'issue_date': mc.get('issued_at', '').split('T')[0] if mc.get('issued_at') else '',
                    'duration': f"{mc.get('duration_days', 1)} day(s)",
                    'start_date': mc.get('start_date', '').split('T')[0] if mc.get('start_date') else '',
                    'end_date': mc.get('end_date', '').split('T')[0] if mc.get('end_date') else '',
                    'mc_number': tokenized_id,
                    'tokenized_id': tokenized_id
                }
                certificates.append(cert_dict)
        
        # Log viewing medical certificates
        log_phi_event(
            action="VIEW_MEDICAL_CERTIFICATES",
            classification="confidential",
            target_user_id=user_id,
            allowed=True,
            extra={"count": len(certificates)}
        )
        
        return render_template('patient/medical-certificates.html', 
                             certificates=certificates,
                             patient_name=patient_name,
                             nric_masked=nric_masked)
    
    except Exception as e:
        logger.error(f"Error fetching medical certificates: {e}")
        flash("Error loading medical certificates", "error")
        return render_template('patient/medical-certificates.html', 
                             certificates=[],
                             patient_name="Unknown",
                             nric_masked="****")

@app.route('/patient/download-mc/<id>')
@login_required
def download_mc(id):
    """Generate and download a medical certificate as PDF"""
    user_session = session.get('user')
    user_id = user_session.get('user_id') or user_session.get('id')
    
    try:
        # Verify the certificate belongs to the logged-in patient (exclude soft-deleted)
        mc_res = supabase.table("medical_certificates").select("*").eq("id", id).eq("is_deleted", 0).single().execute()
        
        if not mc_res.data:
            abort(404)
        
        mc_data = mc_res.data
        
        # Authorization check: ensure patient can only download their own certificates
        if mc_data.get('patient_id') != user_id:
            abort(403)
        
        # Fetch patient profile using patient_id from medical certificate
        patient_id = mc_data.get('patient_id')
        profile_res = supabase.table("patient_profile").select("*").eq("id", patient_id).single().execute()
        
        patient_name = "Unknown"
        nric_masked = "****"
        
        if profile_res.data:
            patient_name = profile_res.data.get("full_name", "Unknown")
            
            # Decrypt NRIC if encrypted
            try:
                nric_encrypted = profile_res.data.get("nric_encrypted")
                dek_encrypted = profile_res.data.get("dek_encrypted")
                
                if nric_encrypted and dek_encrypted:
                    nric_decrypted = envelope_decrypt_field(dek_encrypted, nric_encrypted)
                    if nric_decrypted:
                        # Mask NRIC: show first char, ****, last 4 chars (e.g., S****871A)
                        nric_masked = re.sub(r'^(.)(.*?)(.{4})$', r'\1****\3', str(nric_decrypted))
            except Exception as e:
                logger.warning(f"Failed to decrypt NRIC for patient {patient_id}: {e}")
        
        # Get tokenized MC ID from database (or generate fallback for legacy records)
        tokenized_id = mc_data.get('mc_number')
        if not tokenized_id:
            # Fallback for legacy records without mc_number
            mc_number = str(int(hashlib.sha256(f"{mc_data.get('id', '')}{user_id}".encode()).hexdigest(), 16) % 10000000000).zfill(10)
            tokenized_id = f"MC-LEGACY-{mc_number}"
        
        # Create PDF using PyMuPDF
        pdf_document = fitz.open()
        page = pdf_document.new_page(width=297, height=420)  # A6 size (portrait)
        
        # Helper function to draw text
        def draw_text(page, text, x, y, size=11, bold=False, color=(0, 0, 0), centered=False, italic=False):
            fontname = "helv"  # Use standard helvetica, bold will be applied via font weight
            if centered:
                # Measure text width to center it
                text_rect = fitz.get_text_length(text, fontname=fontname, fontsize=size)
                x = (297 - text_rect) / 2  # Center on page width
            # For italic text, we use a slight transform or just render normally (PyMuPDF limitations)
            page.insert_text((x, y), text, fontsize=size, color=color, fontname=fontname)
        
        # Page dimensions
        page_width = 297
        margin = 25
        
        y_pos = 30
        line_height = 14
        
        # Title: MEDICAL CERTIFICATE (centered, large)
        draw_text(page, "MEDICAL CERTIFICATE", page_width/2, y_pos, size=14, bold=True, centered=True)
        y_pos += 20
        
        # Subtitle: PinkHealth Medical Centre (centered)
        draw_text(page, "PinkHealth Medical Centre", page_width/2, y_pos, size=9, color=(0.29, 0.33, 0.39), centered=True)
        y_pos += 25
        
        # "This is to certify that:"
        draw_text(page, "This is to certify that:", margin, y_pos, size=8)
        y_pos += line_height
        
        # Patient Name (bold)
        draw_text(page, f"Patient Name: {patient_name}", margin, y_pos, size=8, bold=True)
        y_pos += line_height
        
        # NRIC (bold)
        draw_text(page, f"NRIC: {nric_masked}", margin, y_pos, size=8, bold=True)
        y_pos += line_height + 8
        
        # "was examined and is unfit for duty from:"
        draw_text(page, "was examined and is unfit for duty from:", margin, y_pos, size=8)
        y_pos += line_height + 5
        
        # Date range
        start_date = mc_data.get('start_date', '').split('T')[0] if mc_data.get('start_date') else ''
        end_date = mc_data.get('end_date', '').split('T')[0] if mc_data.get('end_date') else ''
        duration = mc_data.get('duration_days', 1)
        
        # Convert dates from YYYY-MM-DD to DD/MM/YYYY format
        try:
            from datetime import datetime as dt
            if start_date:
                start_date_obj = dt.strptime(start_date, '%Y-%m-%d')
                start_date = start_date_obj.strftime('%d/%m/%Y')
            if end_date:
                end_date_obj = dt.strptime(end_date, '%Y-%m-%d')
                end_date = end_date_obj.strftime('%d/%m/%Y')
        except:
            pass
        
        draw_text(page, f"{start_date} to {end_date}", margin, y_pos, size=8)
        y_pos += line_height
        
        # Duration in parentheses
        draw_text(page, f"({duration} day{'s' if duration != 1 else ''})", margin, y_pos, size=8)
        y_pos += line_height + 12
        
        # Horizontal line
        page.draw_line((margin, y_pos), (page_width - margin, y_pos), width=1, color=(0, 0, 0))
        y_pos += 12
        
        # Doctor Information
        doctor_name = mc_data.get('doctor_name', 'Medical Professional')
        doctor_specialty = mc_data.get('doctor_specialty', 'General Practitioner')
        issue_date = mc_data.get('issued_at', '').split('T')[0] if mc_data.get('issued_at') else datetime.now().strftime('%d/%m/%Y')
        
        # Format date as DD/MM/YYYY
        try:
            from datetime import datetime as dt
            issue_date_obj = dt.strptime(issue_date, '%Y-%m-%d')
            issue_date = issue_date_obj.strftime('%d/%m/%Y')
        except:
            pass
        
        # Doctor name (bold, with Dr. prefix)
        draw_text(page, f"{doctor_name}", margin, y_pos, size=8, bold=True)
        y_pos += line_height
        
        # Specialty (gray, smaller)
        draw_text(page, doctor_specialty, margin, y_pos, size=7, color=(0.29, 0.33, 0.39))
        y_pos += line_height
        
        # Issue date
        draw_text(page, f"Date: {issue_date}", margin, y_pos, size=7)
        y_pos += line_height + 5
        
        # MC Number (tokenized ID)
        draw_text(page, f"MC No.    : {tokenized_id}", margin, y_pos, size=7)
        y_pos += line_height + 10
        
        # Disclaimer (italic) - wrap text for smaller page
        disclaimer_text = "*This certificate is not valid for absence from court or"
        draw_text(page, disclaimer_text, margin, y_pos, size=6, color=(0.4, 0.4, 0.4), italic=True)
        y_pos += 9
        draw_text(page, "other judicial proceedings unless specifically stated.", margin, y_pos, size=6, color=(0.4, 0.4, 0.4), italic=True)
        
        # Save PDF to bytes
        pdf_bytes = BytesIO()
        pdf_document.save(pdf_bytes)
        pdf_bytes.seek(0)
        pdf_document.close()
        
        # Log the download event
        log_phi_event(
            action="DOWNLOAD_MC",
            classification=mc_data.get('classification', 'confidential'),
            record_id=id,
            target_user_id=user_id,
            allowed=True,
            extra={"tokenized_mc_id": tokenized_id}
        )
        
        # Return PDF file
        filename = f"Medical_Certificate_{tokenized_id}_{issue_date.replace('/', '-')}.pdf"
        return send_file(
            pdf_bytes,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
    
    except Exception as e:
        logger.error(f"Error generating MC PDF: {e}")
        flash("Error generating medical certificate PDF", "error")
        return redirect(url_for('medical_certificates'))

@app.route('/prescriptions')
@login_required
def prescriptions():
    user_session = session.get('user')
    user_id = user_session.get('user_id') or user_session.get('id')
    
    prescriptions_list = []
    
    try:
        # Fetch prescriptions for this patient (exclude soft-deleted)
        prescriptions_res = (
            supabase.table("prescriptions")
            .select("*")
            .eq("patient_id", user_id)
            .eq("is_deleted", 0)
            .order("created_at", desc=True)
            .execute()
        )
        
        if prescriptions_res.data:
            # Get unique doctor IDs
            doctor_ids = list(set([p.get('doctor_id') for p in prescriptions_res.data if p.get('doctor_id')]))
            
            # Fetch doctor names
            doctor_map = {}
            if doctor_ids:
                try:
                    doctors_res = (
                        supabase.table("doctor_profile")
                        .select("id, full_name")
                        .in_("id", doctor_ids)
                        .execute()
                    )
                    if doctors_res.data:
                        doctor_map = {doc['id']: doc['full_name'] for doc in doctors_res.data}
                except Exception as e:
                    logger.warning(f"Failed to fetch doctor names: {e}")
            
            # Build prescriptions list
            for rx in prescriptions_res.data:
                doctor_name = doctor_map.get(rx.get('doctor_id'), 'Unknown Doctor')
                created_at = rx.get('created_at', '')
                
                # Format date
                if created_at:
                    try:
                        date_obj = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                        formatted_date = date_obj.strftime('%d %b %Y')
                    except:
                        formatted_date = created_at.split('T')[0]
                else:
                    formatted_date = 'N/A'
                
                # Generate or reuse tokenized ID
                rx_id = rx.get('id', '')
                token_id = rx.get('rx_number')
                token_str = str(token_id) if token_id else ""
                if not token_id or not re.match(r"^RX-\d{10}$", token_str):
                    token_id = generate_token("rx")
                    if rx_id:
                        try:
                            supabase.table("prescriptions").update({"rx_number": token_id}).eq("id", rx_id).execute()
                        except Exception as e:
                            logger.warning(f"Failed to backfill rx_number for prescription {rx_id}: {e}")
                rx_number = token_id
                
                # Parse medications (assuming JSON or comma-separated)
                medications = []
                medications_data = rx.get('medications', '')
                
                if medications_data:
                    try:
                        # Try parsing as JSON first
                        if isinstance(medications_data, str):
                            import json
                            meds_list = json.loads(medications_data)
                        else:
                            meds_list = medications_data
                        
                        if isinstance(meds_list, list):
                            for med in meds_list:
                                if isinstance(med, dict):
                                    medications.append({
                                        'name': med.get('name', 'Unknown'),
                                        'dosage': med.get('dosage', 'N/A'),
                                        'frequency': med.get('frequency', 'N/A'),
                                        'duration': med.get('duration', 'N/A'),
                                        'instructions': med.get('instructions', 'N/A'),
                                        'refills_remaining': med.get('refills', 0)
                                    })
                                elif isinstance(med, str):
                                    medications.append({
                                        'name': med,
                                        'dosage': 'N/A',
                                        'frequency': 'N/A',
                                        'duration': 'N/A',
                                        'instructions': 'N/A',
                                        'refills_remaining': 0
                                    })
                    except:
                        # Fallback: treat as single medication
                        medications.append({
                            'name': medications_data if isinstance(medications_data, str) else 'Medication',
                            'dosage': rx.get('dosage', 'N/A'),
                            'frequency': rx.get('frequency', 'N/A'),
                            'duration': rx.get('duration', 'N/A'),
                            'instructions': rx.get('instructions', 'N/A'),
                            'refills_remaining': 0
                        })
                
                # Determine status
                status = rx.get('status', 'Active')
                if not status or status.lower() == 'pending':
                    status = 'Active'
                
                prescription_obj = {
                    'id': rx_id,
                    'token_id': token_id,
                    'tokenized_id': token_id,
                    'rx_number': rx_number,
                    'doctor': doctor_name,
                    'date': formatted_date,
                    'created_at': formatted_date,
                    'medications': medications,
                    'status': status.capitalize(),
                    'valid_until': rx.get('valid_until', 'N/A'),
                    'refills_available': any(m.get('refills_remaining', 0) > 0 for m in medications)
                }
                
                prescriptions_list.append(prescription_obj)
        
    except Exception as e:
        logger.error(f"Error fetching prescriptions: {e}")
        flash("Error loading prescriptions", "error")
    
    # Log viewing prescriptions
    log_phi_event(
        action="VIEW_PRESCRIPTIONS",
        classification="confidential",
        target_user_id=user_id,
        allowed=True,
        extra={"count": len(prescriptions_list)}
    )
    
    return render_template('patient/prescriptions.html', prescriptions=prescriptions_list)

@app.route('/personal-particulars' , methods=['GET', 'POST'])
@login_required
def personal_particulars():
    user_session = session.get('user')
    user_id = user_session.get('user_id') or user_session.get('id')
    user_role = user_session.get('role')
    
    # --- POST: Handle Save Changes ---
    if request.method == 'POST':
        try:
            # DEBUG: log incoming form
            logger.info("FORM DATA: %s", request.form.to_dict())


            # PHI fields (encrypted)
            phi_fields = {
                'phone': request.form.get('phone', '') or '',
                'address': request.form.get('address', '') or '',
                'dob': request.form.get('dob', '') or '',
                'postal_code': request.form.get('postal_code', '') or ''
            }

            # Non-PHI fields (plaintext)
            non_phi = {
                'full_name': request.form.get('full_name', '') or '',
                'gender': request.form.get('gender', '') or '',
                'nationality': request.form.get('nationality', '') or '',
                'blood_type': request.form.get('blood_type', '') or '',
                'email': request.form.get('email', '') or '',
                'postal_code': request.form.get('postal_code', '') or '',
                'emergency_name': request.form.get('emergency_name', '') or '',
                'emergency_relationship': request.form.get('emergency_relationship', '') or '',
                'emergency_phone': request.form.get('emergency_phone', '') or ''
            }

            # 1) get existing DEK
            profile_res = supabase.table("patient_profile").select("dek_encrypted").eq("id", user_id).single().execute()
            existing_dek = profile_res.data.get('dek_encrypted') if profile_res.data else None

            # 2) encrypt PHI only
            dek_encrypted, encrypted = envelope_encrypt_fields(existing_dek, phi_fields)

            logger.info("Encrypted keys: %s", list(encrypted.keys()))

            # 3) build update payload for patient_profile (encrypted PHI + plaintext columns)
            update_payload = {
                "phone_encrypted": encrypted.get('phone_encrypted', ''),
                "address_encrypted": encrypted.get('address_encrypted', ''),
                "dob_encrypted": encrypted.get('dob_encrypted', ''),
                "postal_code_encrypted": encrypted.get('postal_code_encrypted', ''),
                "dek_encrypted": dek_encrypted,
                # plaintext fields
                "full_name": non_phi['full_name'],
                "gender": non_phi['gender'],
                "nationality": non_phi['nationality'],
                "blood_type": non_phi['blood_type'],
                "email": non_phi['email'],
                # removed plaintext postal_code
                "emergency_name": non_phi['emergency_name'],
                "emergency_relationship": non_phi['emergency_relationship'],
                "emergency_phone": non_phi['emergency_phone']
            }

            res = supabase.table("patient_profile").update(update_payload).eq("id", user_id).execute()
            logger.info("patient_profile update result: %s", getattr(res, 'data', res))

            # Check for error in response (supabase-py returns .error or similar in some versions)
            if getattr(res, 'error', None):
                logger.error("Supabase error: %s", res.error)
                flash("Failed to update profile (DB error)", "error")
                return redirect(url_for('personal_particulars'))

            # 4) sync profiles table for non-PHI summary fields only
            # Phone is PHI - only stored encrypted in patient_profile
            profiles_update = {
                "full_name": non_phi['full_name']
            }
            res2 = supabase.table("profiles").update(profiles_update).eq("id", user_id).execute()
            logger.info("profiles update result: %s", getattr(res2, 'data', res2))

            log_phi_event(
                action="UPDATE_PROFILE",
                classification="restricted",
                record_id=user_id,
                target_user_id=user_id,
                allowed=True
            )

            flash("Particulars updated successfully!", "success")
            return redirect(url_for('personal_particulars'))

        except Exception as e:
            logger.exception("Update error")
            flash("Failed to update profile", "error")
            return redirect(url_for('personal_particulars'))
        
        # --- GET: Display Data ---
    try:
        profile_res = supabase.table("patient_profile").select("*").eq("id", user_id).single().execute()
        if not profile_res.data:
            flash("Profile not found", "error")
            return redirect(url_for('patient_dashboard'))

        real_data = get_profile_with_decryption(profile_res.data, user_session)

        # Step A: Create the masked version
        masked_data = apply_policy_masking(user_session, real_data)

        # Step B: Prepare the final object for the HTML
        display_profile = masked_data.copy()
        # Step C: ONLY update fields that ARE NOT the NRIC
        # This prevents the real NRIC from overwriting the masked one
        editable_fields = ['phone', 'email', 'address', 'full_name','emergency_phone']
        for field in editable_fields:
            if field in real_data:
                display_profile[field] = real_data[field]

        # Log viewing personal particulars (PHI access)
        log_phi_event(
            action="VIEW_PERSONAL_PARTICULARS",
            classification="restricted",
            record_id=user_id,
            target_user_id=user_id,
            allowed=True
        )

        # Now pass to template
        return render_template('patient/personal-particulars.html', 
                       profile=display_profile, 
                       patient_profile=display_profile)

    except Exception as e:
        logger.exception("Load Error")
        flash("Error loading profile", "error")
        return redirect(url_for('patient_dashboard'))

@app.route('/patient/request-account-deletion', methods=['GET', 'POST'])
@login_required
def patient_request_account_deletion():
    """Patient-initiated account deletion request with password verification."""
    user_session = session.get('user')
    user_id = user_session.get('user_id') or user_session.get('id')
    user_role = user_session.get('role', '').lower()
    user_email = user_session.get('email')
    
    if user_role != 'patient':
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        reason = request.form.get('reason', '').strip()
        password = request.form.get('password', '').strip()
        
        if not reason:
            flash('Please select a reason for account deletion.', 'error')
            return redirect(url_for('patient_request_account_deletion'))
        
        if not password:
            flash('Password verification is required to proceed.', 'error')
            return redirect(url_for('patient_request_account_deletion'))
        
        # Verify password
        try:
            auth_response = supabase.auth.sign_in_with_password({
                "email": user_email,
                "password": password
            })
            if not auth_response.user:
                flash('Invalid password. Please verify your password and try again.', 'error')
                return redirect(url_for('patient_request_account_deletion'))
        except Exception as e:
            logger.warning(f"Password verification failed for user {user_id}: {e}")
            flash('Invalid password. Please verify your password and try again.', 'error')
            return redirect(url_for('patient_request_account_deletion'))
        
        try:
            # Check if there's already a pending request
            existing_res = (
                supabase.table("account_deletion_requests")
                .select("id, status")
                .eq("user_id", user_id)
                .eq("status", "pending")
                .execute()
            )
            
            if existing_res.data:
                flash('You already have a pending account deletion request.', 'warning')
                return redirect(url_for('patient_request_account_deletion'))
            
            # Create account deletion request
            payload = {
                "user_id": user_id,
                "user_role": "patient",
                "reason": reason,
                "status": "pending",
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            
            insert_res = supabase.table("account_deletion_requests").insert(payload).execute()
            
            if insert_res.data:
                log_phi_event(
                    action="REQUEST_ACCOUNT_DELETION",
                    classification="restricted",
                    record_id=insert_res.data[0].get('id') if isinstance(insert_res.data, list) else None,
                    target_user_id=user_id,
                    allowed=True,
                    extra={"reason": reason[:100]}
                )
                
                flash('Account deletion request submitted successfully. An administrator will review your request.', 'success')
                return redirect(url_for('patient_dashboard'))
            else:
                flash('Failed to submit request. Please try again.', 'error')
        
        except Exception as e:
            logger.error(f"Error submitting account deletion request: {e}")
            flash('Error submitting request. Please try again.', 'error')
    
    # Fetch existing requests for display
    requests_list = []
    try:
        requests_res = (
            supabase.table("account_deletion_requests")
            .select("*")
            .eq("user_id", user_id)
            .order("created_at", desc=True)
            .limit(5)
            .execute()
        )
        
        if requests_res.data:
            for row in requests_res.data:
                requests_list.append({
                    'id': row.get('id'),
                    'reason': row.get('reason'),
                    'status': row.get('status'),
                    'created_at': _format_creation_time(row.get('created_at')),
                    'processed_at': _format_creation_time(row.get('approved_at') or row.get('rejected_at') or ''),
                    'rejection_reason': row.get('rejection_reason', '')
                })
    except Exception as e:
        logger.error(f"Error fetching account deletion requests: {e}")
    
    return render_template('patient/request-account-deletion.html', requests=requests_list)


@app.route('/upload-documents', methods=['GET', 'POST'])
@login_required
def upload_documents():
    user = session.get('user')
    user_id = user.get('user_id') or user.get('id')

    if request.method == 'POST':
        file = request.files.get('documents')
        if not file or file.filename == '':
            flash("No file selected", "error")
            return redirect(request.url)

        # A. RUN DLP SCAN (Internal Log to DLP_events happens inside here)
        dlp_results = run_dlp_security_service(file, user)

        # B. LOG TO AUDIT TABLE (Hash Chain Logic)
        try:
            log_phi_event(
                action=f"UPLOAD_{dlp_results['classification'].upper()}",
                classification=dlp_results['classification'],
                record_id=file.filename,
                extra={
                    "audit_id": dlp_results['audit_id'],
                    "phi_tags": dlp_results['phi_tags']
                }
            )
        except Exception as e:
            logger.error(f"Audit Log Failed: {e}")

        try:
            file.seek(0)
            file_path = f"{user_id}/{file.filename}"
            
            supabase.storage.from_("patient-files").upload(
                path=file_path,
                file=file.read(),
                file_options={"content-type": "application/pdf"}
            )
            logger.info(f"File stored successfully at {file_path}")
        except Exception as e:
            logger.error(f"Supabase Storage Error: {e}")
            flash("Could not save the physical file to storage.", "error")
            return redirect(request.url)

        # C. SAVE TO PATIENT DOCUMENTS (Operational View)
        file.seek(0, 2)
        size_kb = f"{file.tell() // 1024} KB"
        file.seek(0)
        # C. ENCRYPT AND SAVE FILE TO DISK
        from werkzeug.utils import secure_filename
        filename = secure_filename(file.filename)
        encrypted_filename = filename + '.enc'
        file_data = file.read()
        encrypted_data, dek_encrypted = encrypt_file(file_data)

        # Save encrypted file to disk
        upload_dir = os.path.join(app.instance_path, 'uploads', 'patient', str(user_id))
        os.makedirs(upload_dir, exist_ok=True)
        file_path = os.path.join(upload_dir, encrypted_filename)
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)

        size_kb = f"{len(file_data) // 1024} KB"

        doc_data = {
            "user_id": user_id,
            "filename": filename,
            "file_path": f"patient/{user_id}/{encrypted_filename}",
            "classification": dlp_results['classification'],
            "phi_tags": dlp_results['phi_tags'],
            "audit_id": dlp_results['audit_id'],
            "size": size_kb,
            "dlp_status": dlp_results['dlp_status'],
            "storage_path": file_path,
            "created_at": datetime.now().isoformat()
        }

        try:
            supabase.table("patient_documents").insert(doc_data).execute()
            flash(f"Upload Success. Status: {dlp_results['classification'].title()}", "success")
        except Exception as e:
            logger.error(f"Doc Table Insert Failed: {e}")
            flash("System error saving document metadata.", "error")

        return redirect(url_for('upload_documents'))

    docs = get_patient_docs(user_id)
    return render_template('patient/upload-documents.html', documents=docs)
def get_patient_docs(user_id):
    res = supabase.table("patient_documents").select("*").eq("user_id", user_id).execute()
    return res.data if res.data else []

@app.route('/delete-document/<id>', methods=['POST'])
@login_required
def delete_document(id):
    user = session.get('user')
    user_id = user.get('user_id') or user.get('id')
    
    # Log document deletion
    log_phi_event(
        action="DELETE_DOCUMENT",
        classification="restricted",
        record_id=id,
        target_user_id=user_id,
        allowed=True,
        extra={"document_id": id}
    )
    
    supabase.table("patient_documents").delete().eq("id", id).execute()
    flash("Document deleted.", "success")
    return redirect(url_for('upload_documents'))

@app.route('/billing-payment')
@login_required
def billing_payment():
    return render_template('patient/billing-payment.html')

# ========================
# STAFF ROUTES
# ========================

@app.route('/staff/dashboard')
@login_required
def staff_dashboard():
    user_session = session.get('user')
    staff_name = _get_staff_display_name(user_session)
    patient_queue = []
    waiting_count = 0
    in_progress_count = 0

    try:
        appointments_res = (
            supabase.table("appointments")
            .select(
                "id, patient_id, doctor_id, appointment_datetime, appointment_date, appointment_time, "
                "status, created_at, visit_type, method, is_deleted"
            )
            .eq("is_deleted", 0)
            .order("appointment_datetime", desc=False)
            .execute()
        )
        appointments = appointments_res.data if appointments_res.data else []

        filtered_appointments = [
            appt for appt in appointments
            if appt.get("status") in {"waiting", "in_progress", "completed"}
        ]

        # Sort by status priority: in_progress first, then waiting, then completed
        status_priority = {"in_progress": 1, "waiting": 2, "completed": 3}
        filtered_appointments.sort(key=lambda appt: (
            status_priority.get(appt.get("status"), 999),
            appt.get("appointment_datetime") or ""
        ))

        patient_ids = list({appt.get("patient_id") for appt in filtered_appointments if appt.get("patient_id")})
        doctor_ids = list({appt.get("doctor_id") for appt in filtered_appointments if appt.get("doctor_id")})

        patient_map = {}
        doctor_map = {}

        if patient_ids:
            patient_res = (
                supabase.table("patient_profile")
                .select("id, full_name, nric_encrypted, dek_encrypted")
                .in_("id", patient_ids)
                .execute()
            )
            if patient_res.data:
                patient_map = {patient.get("id"): patient for patient in patient_res.data}

        if doctor_ids:
            doctor_res = (
                supabase.table("doctor_profile")
                .select("id, full_name")
                .in_("id", doctor_ids)
                .execute()
            )
            if doctor_res.data:
                doctor_map = {doctor.get("id"): doctor for doctor in doctor_res.data}

        waiting_appointments = [appt for appt in filtered_appointments if appt.get("status") == "waiting"]
        waiting_appointments.sort(key=lambda appt: appt.get("appointment_datetime") or "")
        waiting_positions = {
            appt.get("id"): idx + 1 for idx, appt in enumerate(waiting_appointments)
        }

        waiting_count = len(waiting_appointments)
        in_progress_count = len([appt for appt in filtered_appointments if appt.get("status") == "in_progress"])

        for appointment in filtered_appointments:
            patient = patient_map.get(appointment.get("patient_id"), {})
            doctor = doctor_map.get(appointment.get("doctor_id"), {})

            nric_masked = "****"
            if patient.get("nric_encrypted") and patient.get("dek_encrypted"):
                try:
                    nric_decrypted = envelope_decrypt_field(
                        patient.get("dek_encrypted"),
                        patient.get("nric_encrypted")
                    )
                    if nric_decrypted:
                        nric_masked = mask_nric(nric_decrypted)
                except Exception as e:
                    logger.warning(f"Could not decrypt NRIC for patient {patient.get('id')}: {e}")
                    nric_masked = "****"

            status = appointment.get("status", "waiting")
            appointment_time = _format_appointment_display(
                appointment.get("appointment_date"),
                appointment.get("appointment_time"),
                appointment.get("appointment_datetime")
            )

            patient_queue.append({
                "patient_name": patient.get("full_name", "Unknown"),
                "nric_masked": nric_masked,
                "doctor_name": doctor.get("full_name", "Unassigned"),
                "appointment_time": appointment_time or "-",
                "status": status,
                "method": appointment.get("method", "Self-Book"),
            })
    except Exception as e:
        logger.error(f"Error loading staff dashboard queue: {e}")

    # Fetch internal administrative broadcasts
    broadcasts = []
    try:
        # Get internal administrative records (newest first, limit to 10)
        broadcasts_res = (
            supabase.table("administrative")
            .select("id, title, description, record_type, staff_id, created_at, classification_method")
            .eq("classification", "internal")
            .eq("is_deleted", 0)
            .order("created_at", desc=True)
            .limit(10)
            .execute()
        )
        
        if broadcasts_res.data:
            # Get unique staff IDs who created these broadcasts
            staff_ids = list({rec.get("staff_id") for rec in broadcasts_res.data if rec.get("staff_id")})
            admin_ids = [rec.get("id") for rec in broadcasts_res.data]
            
            staff_name_map = {}
            if staff_ids:
                # Try staff_profile first
                try:
                    staff_profile_res = supabase.table("staff_profile").select("id, full_name").in_("id", staff_ids).execute()
                    if staff_profile_res.data:
                        for staff in staff_profile_res.data:
                            staff_name_map[staff['id']] = staff.get('full_name', 'Unknown Staff')
                except Exception as e:
                    logger.warning(f"Failed to fetch staff names from staff_profile: {e}")
                
                # Fallback to profiles table for any missing staff
                missing_staff_ids = [sid for sid in staff_ids if sid not in staff_name_map]
                if missing_staff_ids:
                    try:
                        profiles_res = supabase.table("profiles").select("id, full_name").in_("id", missing_staff_ids).execute()
                        if profiles_res.data:
                            for profile in profiles_res.data:
                                staff_name_map[profile['id']] = profile.get('full_name', 'Unknown Staff')
                    except Exception as e:
                        logger.warning(f"Failed to fetch staff names from profiles: {e}")
            
            # Get attachments for these administrative records
            attachments_map = {}
            if admin_ids:
                try:
                    attachments_res = (
                        supabase.table("administrative_attachments")
                        .select("id, administrative_id, filename, file_size")
                        .in_("administrative_id", admin_ids)
                        .execute()
                    )
                    if attachments_res.data:
                        for attachment in attachments_res.data:
                            admin_id = attachment.get("administrative_id")
                            if admin_id not in attachments_map:
                                attachments_map[admin_id] = []
                            attachments_map[admin_id].append({
                                'id': attachment.get('id'),
                                'filename': attachment.get('filename'),
                                'file_size': attachment.get('file_size')
                            })
                except Exception as e:
                    logger.warning(f"Failed to fetch attachments: {e}")
            
            # Format broadcasts for display
            for record in broadcasts_res.data:
                record_id = record.get('id')
                staff_id = record.get('staff_id')
                uploaded_by = staff_name_map.get(staff_id, 'Unknown Staff')
                
                # Format timestamp
                created_at = record.get('created_at', '')
                formatted_time = _format_creation_time(created_at)
                
                broadcasts.append({
                    'id': record_id,
                    'record_type': record.get('record_type'),
                    'title': record.get('title'),
                    'description': record.get('description'),
                    'uploaded_by': uploaded_by,
                    'created_at': formatted_time,
                    'attachments': attachments_map.get(record_id, [])
                })
                
    except Exception as e:
        logger.error(f"Error loading administrative broadcasts: {e}")

    staff_user_id = None
    if user_session:
        staff_user_id = user_session.get('user_id') or user_session.get('id')

    return render_template(
        'staff/staff-dashboard.html',
        patient_queue=patient_queue,
        waiting_count=waiting_count,
        in_progress_count=in_progress_count,
        staff_name=staff_name,
        broadcasts=broadcasts,
        staff_user_id=staff_user_id
    )

@app.route('/staff/create-appointment', methods=['GET', 'POST'])
@login_required
def staff_create_appointment():
    from datetime import date
    
    user_session = session.get('user')
    staff_id = user_session.get('user_id') or user_session.get('id')
    staff_name = _get_staff_display_name(user_session)
    
    # Get today's date
    today = date.today().strftime('%Y-%m-%d')
    
    # Fetch real doctors from database
    doctors = []
    try:
        doctors_res = supabase.table("doctor_profile").select("id, full_name, specialty").execute()
        if doctors_res.data:
            doctors = [
                {
                    "id": str(doc.get('id')),
                    "name": doc.get('full_name', 'N/A'),
                    "specialty": doc.get('specialty', 'General Practitioner')
                }
                for doc in doctors_res.data
            ]
    except Exception as e:
        logger.error(f"Error fetching doctors for staff appointment: {e}")
    
    # Time slots for today
    time_slots = [
        {"value": "09:00", "label": "9:00 AM"},
        {"value": "09:30", "label": "9:30 AM"},
        {"value": "10:00", "label": "10:00 AM"},
        {"value": "10:30", "label": "10:30 AM"},
        {"value": "11:00", "label": "11:00 AM"},
        {"value": "11:30", "label": "11:30 AM"},
        {"value": "12:00", "label": "12:00 PM"},
        {"value": "14:00", "label": "2:00 PM"},
        {"value": "14:30", "label": "2:30 PM"},
        {"value": "15:00", "label": "3:00 PM"},
        {"value": "15:30", "label": "3:30 PM"},
        {"value": "16:00", "label": "4:00 PM"},
        {"value": "16:30", "label": "4:30 PM"},
        {"value": "17:00", "label": "5:00 PM"},
    ]
    
    # Visit types (same as patient booking)
    visit_types = [
        {"value": "general", "label": "General Consultation"},
        {"value": "followup", "label": "Follow-up"},
        {"value": "emergency", "label": "Emergency"},
        {"value": "specialist", "label": "Specialist Consultation"},
    ]
    
    if request.method == 'POST':
        try:
            # Extract form data
            patient_id = request.form.get('patient_id', '').strip()
            patient_name = request.form.get('patient_name', '').strip()
            doctor_id = request.form.get('doctor_id', '').strip()
            appointment_time = request.form.get('time', '').strip()
            visit_type = request.form.get('visit_type', '').strip()
            notes = request.form.get('notes', '').strip()
            
            # Validate required fields
            if not all([patient_id, doctor_id, appointment_time, visit_type]):
                flash('Please fill in all required fields', 'error')
                return render_template('staff/create-appointment.html',
                                     doctors=doctors,
                                     time_slots=time_slots,
                                     visit_types=visit_types,
                                     today=today,
                                     staff_name=staff_name)
            
            # Validate UUIDs
            if not _is_valid_uuid(patient_id) or not _is_valid_uuid(doctor_id):
                flash('Invalid patient or doctor selection', 'error')
                return render_template('staff/create-appointment.html',
                                     doctors=doctors,
                                     time_slots=time_slots,
                                     visit_types=visit_types,
                                     today=today,
                                     staff_name=staff_name)
            
            # Normalize appointment_time display to AM/PM (match self-book)
            appointment_time_display = appointment_time
            if appointment_time and "AM" not in appointment_time and "PM" not in appointment_time:
                try:
                    appointment_time_display = datetime.strptime(appointment_time, "%H:%M").strftime("%I:%M %p")
                except Exception:
                    appointment_time_display = appointment_time

            # Combine date and time (AM/PM display format)
            appointment_datetime = f"{today} {appointment_time_display}"
            
            # Create appointment with walk-in method
            appointment_data = {
                "patient_id": patient_id,
                "doctor_id": doctor_id,
                "appointment_date": today,
                "appointment_time": appointment_time_display,
                "appointment_datetime": appointment_datetime,
                "visit_type": visit_type,
                "notes": notes,
                "status": "waiting",
                "method": "walk-in",
                "staff_id": staff_id,
                "classification": "internal",
                "classification_method": "Automatic",
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            
            # Insert into database
            insert_res = supabase.table("appointments").insert(appointment_data).execute()
            
            if insert_res.data:
                logger.info(f"Walk-in appointment created by staff {staff_id} for patient {patient_id}")
                
                log_phi_event(
                    action="CREATE_WALKIN_APPOINTMENT",
                    classification="restricted",
                    record_id=insert_res.data[0].get('id') if isinstance(insert_res.data, list) else None,
                    target_user_id=patient_id,
                    allowed=True,
                    extra={"doctor_id": doctor_id, "staff_id": staff_id, "method": "walk-in"}
                )
                
                flash(f'Walk-in appointment created successfully for {patient_name}!', 'success')
                return redirect(url_for('staff_dashboard'))
            else:
                flash('Failed to create appointment. Please try again.', 'error')
                
        except Exception as e:
            logger.error(f"Error creating walk-in appointment: {e}")
            flash(f'Error creating appointment: {str(e)}', 'error')
    
    return render_template('staff/create-appointment.html',
                         doctors=doctors,
                         time_slots=time_slots,
                         visit_types=visit_types,
                         today=today,
                         staff_name=staff_name)

@app.route('/staff/billing', methods=['GET', 'POST'])
@login_required
def staff_billing():
    user_session = session.get('user')
    staff_name = _get_staff_display_name(user_session)
    # Mock patient data
    patients = [
        {"id": "P001", "name": "John Doe", "nric": "S1234567A", "phone": "91234567", "dob": "1985-05-15", "email": "john.doe@email.com"},
        {"id": "P002", "name": "Jane Smith", "nric": "S2345678B", "phone": "92345678", "dob": "1990-08-22", "email": "jane.smith@email.com"},
        {"id": "P003", "name": "Ahmad Hassan", "nric": "S3456789C", "phone": "93456789", "dob": "1978-12-10", "email": "ahmad.hassan@email.com"},
        {"id": "P004", "name": "Mary Tan", "nric": "S4567890D", "phone": "94567890", "dob": "1995-03-18", "email": "mary.tan@email.com"},
        {"id": "P005", "name": "Kumar Raj", "nric": "S5678901E", "phone": "95678901", "dob": "1982-07-25", "email": "kumar.raj@email.com"},
    ]
    
    recent_invoices = [
        {"id": "INV-2024-001", "patient_name": "John Doe", "nric_masked": "S****567A", "date": "2024-12-15", "amount": 150.00, "status": "Paid"},
        {"id": "INV-2024-002", "patient_name": "Jane Smith", "nric_masked": "S****678B", "date": "2024-12-14", "amount": 320.50, "status": "Pending"},
        {"id": "INV-2024-003", "patient_name": "Ahmad Hassan", "nric_masked": "S****789C", "date": "2024-12-13", "amount": 95.00, "status": "Paid"},
        {"id": "INV-2024-004", "patient_name": "Mary Tan", "nric_masked": "S****890D", "date": "2024-12-12", "amount": 200.00, "status": "Overdue"},
    ]
    
    if request.method == 'POST':
        flash('Invoice generated successfully!', 'success')
        return redirect(url_for('staff_billing'))
    
    return render_template('staff/staff-billing.html',
                         patients=patients,
                         recent_invoices=recent_invoices,
                         staff_name=staff_name)

@app.route('/staff/upload', methods=['GET', 'POST'])
@login_required
def staff_upload():
    user = session.get('user')
    staff_id = user.get('user_id') or user.get('id')

    if request.method == 'POST':
        file = request.files.get('documents')
        if not file or file.filename == '':
            flash("No file selected", "error")
            return redirect(request.url)

        # A. RUN DLP SCAN
        dlp_results = run_dlp_security_service(file, user)

        # B. LOG TO AUDIT TABLE (Hash Chain Logic)
        try:
            log_phi_event(
                action=f"UPLOAD_{dlp_results['classification'].upper()}",
                classification=dlp_results['classification'],
                record_id=file.filename,
                extra={
                    "audit_id": dlp_results['audit_id'],
                    "phi_tags": dlp_results['phi_tags']
                }
            )
        except Exception as e:
            logger.error(f"Audit Log Failed: {e}")

        # C. SAVE TO STAFF DOCUMENTS
        file.seek(0, 2)
        size_kb = f"{file.tell() // 1024} KB"
        file.seek(0)

        doc_data = {
            "user_id": staff_id,
            "filename": file.filename,
            "classification": dlp_results['classification'],
            "phi_tags": dlp_results['phi_tags'],
            "audit_id": dlp_results['audit_id'],
            "size": size_kb,
            "dlp_status": dlp_results['dlp_status'],
            "created_at": datetime.now().isoformat()
        }

        try:
            supabase.table("staff_documents").insert(doc_data).execute()
            flash(f"Upload Success. Status: {dlp_results['classification'].title()}", "success")
        except Exception as e:
            logger.error(f"Doc Table Insert Failed: {e}")
            flash("System error saving document metadata.", "error")

        return redirect(url_for('staff_upload'))

    docs = get_staff_docs(staff_id)
    return render_template('staff/document-upload.html', documents=docs)

def get_staff_docs(staff_id):
    res = supabase.table("staff_documents").select("*").eq("user_id", staff_id).execute()
    return res.data if res.data else []

    

    

@app.route('/staff/admin-work', methods=['GET', 'POST'])
@login_required
def staff_admin_work():
    user_session = session.get('user')
    staff_name = _get_staff_display_name(user_session)
    
    if request.method == 'POST':
        try:
            # Get form data
            record_type = request.form.get('record_type')
            title = request.form.get('title')
            description = request.form.get('description')
            classification = request.form.get('classification', 'internal')
            
            # Determine classification method
            raw_method = 'auto' if classification == 'internal' else 'manual'
            classification_method = _normalize_method(raw_method)
            
            # Insert administrative record
            admin_record = {
                "staff_id": user_session['id'],
                "record_type": record_type,
                "title": title,
                "description": description,
                "classification": classification,
                "classification_method": classification_method,
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            
            admin_result = supabase.table("administrative").insert(admin_record).execute()
            admin_id = admin_result.data[0]['id'] if admin_result.data else None
            
            # Handle file attachments if present
            if 'attachments' in request.files:
                files = request.files.getlist('attachments')
                for file in files:
                    if file and file.filename != '':
                        from werkzeug.utils import secure_filename
                        
                        # Get original file size before encryption
                        file.seek(0, 2)
                        original_file_size = file.tell()
                        file.seek(0)
                        
                        # Get mime type
                        mime_type = file.content_type
                        
                        # Create secure filename with .enc extension for encrypted files
                        filename = secure_filename(file.filename)
                        encrypted_filename = filename + '.enc'
                        
                        # Read file data and encrypt using AES-256-GCM
                        file_data = file.read()
                        encrypted_data, dek_encrypted = encrypt_file(file_data)
                        
                        # Create upload directory if it doesn't exist
                        upload_dir = os.path.join(app.instance_path, 'uploads', 'administrative', str(admin_id))
                        os.makedirs(upload_dir, exist_ok=True)
                        
                        # Save encrypted file to disk
                        file_path = os.path.join(upload_dir, encrypted_filename)
                        with open(file_path, 'wb') as f:
                            f.write(encrypted_data)
                        
                        # Store metadata in database (including DEK for decryption)
                        attachment_data = {
                            "administrative_id": admin_id,
                            "filename": filename,  # Original filename for display
                            "file_path": f"administrative/{admin_id}/{encrypted_filename}",
                            "file_size": original_file_size,  # Original size for display
                            "mime_type": mime_type,
                            "dek_encrypted": dek_encrypted,  # Store wrapped DEK for decryption
                            "is_encrypted": True,
                            "uploaded_at": datetime.now(timezone.utc).isoformat()
                        }
                        
                        supabase.table("administrative_attachments").insert(attachment_data).execute()
            
            # Log to audit
            supabase.table("audit_logs").insert({
                "user_name": user_session.get('full_name', 'Staff'),
                "action": "ADMIN_RECORD_CREATE",
                "status": "Success",
                "entity_id": str(admin_id),
                "details": {
                    "record_type": record_type,
                    "title": title,
                    "classification": classification
                },
                "timestamp": datetime.now(timezone.utc).isoformat()
            }).execute()
            
            flash('Administrative record submitted successfully!', 'success')
            return redirect(url_for('staff_admin_work'))
            
        except Exception as e:
            logger.error(f"Error creating administrative record: {str(e)}")
            flash('Error submitting administrative record. Please try again.', 'error')
            return redirect(url_for('staff_admin_work'))
    
    return render_template('staff/admin-work.html',
                         staff_name=staff_name)

@app.route('/public/announcement/attachment/<attachment_id>')
def download_public_announcement_attachment(attachment_id):
    """Download a public announcement attachment (no login required, with decryption if encrypted)."""
    try:
        # Fetch attachment metadata and verify it's from a public announcement
        attachment_res = (
            supabase.table("administrative_attachments")
            .select("*, administrative!inner(classification)")
            .eq("id", attachment_id)
            .single()
            .execute()
        )
        
        if not attachment_res.data:
            flash('Attachment not found', 'error')
            return redirect(url_for('index'))
        
        attachment = attachment_res.data
        
        # Verify the attachment is from a public announcement
        if attachment.get('administrative', {}).get('classification') != 'public':
            flash('This attachment is not publicly accessible', 'error')
            return redirect(url_for('index'))
        
        # Construct full file path
        file_path = os.path.join(
            app.instance_path, 
            'uploads', 
            attachment['file_path']
        )
        
        # Check if file exists
        if not os.path.exists(file_path):
            flash('File not found on disk', 'error')
            return redirect(url_for('index'))
        
        # Check if file is encrypted
        is_encrypted = attachment.get('is_encrypted', False)
        dek_encrypted = attachment.get('dek_encrypted')
        
        if is_encrypted and dek_encrypted:
            # Read and decrypt the file
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            try:
                decrypted_data = decrypt_file(encrypted_data, dek_encrypted)
            except ValueError as e:
                logger.error(f"Failed to decrypt public attachment {attachment_id}: {e}")
                flash('Error decrypting file', 'error')
                return redirect(url_for('index'))
            
            # Send decrypted file from memory
            from io import BytesIO
            return send_file(
                BytesIO(decrypted_data),
                as_attachment=True,
                download_name=attachment['filename'],
                mimetype=attachment['mime_type']
            )
        else:
            # Legacy unencrypted file - send directly
            return send_file(
                file_path,
                as_attachment=True,
                download_name=attachment['filename'],
                mimetype=attachment['mime_type']
            )
        
    except Exception as e:
        logger.error(f"Error downloading public attachment: {str(e)}")
        flash('Error downloading file', 'error')
        return redirect(url_for('index'))

@app.route('/staff/admin-work/attachment/<attachment_id>')
@login_required
def download_administrative_attachment(attachment_id):
    """Download an administrative work attachment (with decryption if encrypted)."""
    try:
        # Fetch attachment metadata from database
        attachment_res = (
            supabase.table("administrative_attachments")
            .select("*")
            .eq("id", attachment_id)
            .single()
            .execute()
        )
        
        if not attachment_res.data:
            flash('Attachment not found', 'error')
            return redirect(url_for('staff_admin_work'))
        
        attachment = attachment_res.data
        
        # Construct full file path
        file_path = os.path.join(
            app.instance_path, 
            'uploads', 
            attachment['file_path']
        )
        
        # Check if file exists
        if not os.path.exists(file_path):
            flash('File not found on disk', 'error')
            return redirect(url_for('staff_admin_work'))
        
        # Check if file is encrypted
        is_encrypted = attachment.get('is_encrypted', False)
        dek_encrypted = attachment.get('dek_encrypted')
        
        if is_encrypted and dek_encrypted:
            # Read and decrypt the file
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            try:
                decrypted_data = decrypt_file(encrypted_data, dek_encrypted)
            except ValueError as e:
                logger.error(f"Failed to decrypt attachment {attachment_id}: {e}")
                flash('Error decrypting file', 'error')
                return redirect(url_for('staff_admin_work'))
            
            # Send decrypted file from memory
            from io import BytesIO
            return send_file(
                BytesIO(decrypted_data),
                as_attachment=True,
                download_name=attachment['filename'],
                mimetype=attachment['mime_type']
            )
        else:
            # Legacy unencrypted file - send directly
            return send_file(
                file_path,
                as_attachment=True,
                download_name=attachment['filename'],
                mimetype=attachment['mime_type']
            )
        
    except Exception as e:
        logger.error(f"Error downloading attachment: {str(e)}")
        flash('Error downloading file', 'error')
        return redirect(url_for('staff_admin_work'))

@app.route('/staff/data-erasure', methods=['GET', 'POST'])
@login_required
def staff_data_erasure():
    user_session = session.get('user')
    staff_id = user_session.get('user_id') or user_session.get('id')

    if request.method == 'POST':
        selected_docs = request.form.getlist('documents')
        reason = request.form.get('reason', '').strip()

        if not selected_docs:
            flash('Please select at least one document to erase.', 'error')
            return redirect(url_for('staff_data_erasure'))

        if not reason:
            flash('Reason for erasure is required.', 'error')
            return redirect(url_for('staff_data_erasure'))

        try:
            payload = {
                "requester_id": staff_id,
                "requester_role": "staff",
                "status": "pending",
                "reason": reason,
                "documents": selected_docs,
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            insert_res = supabase.table("data_erasure_requests").insert(payload).execute()

            if not insert_res.data:
                flash('Failed to submit erasure request. Please try again.', 'error')
            else:
                flash('Erasure request submitted successfully.', 'success')

            return redirect(url_for('staff_data_erasure'))
        except Exception as e:
            logger.error(f"Error submitting erasure request: {e}")
            flash('Error submitting erasure request.', 'error')
            return redirect(url_for('staff_data_erasure'))

    documents = []
    patient_ids = set()
    doctor_ids = set()
    admin_ids = set()
    
    try:
        # Fetch administrative records (only internal and public)
        admin_res = (
            supabase.table("administrative")
            .select("id, created_at, title, record_type, classification, staff_id")
            .eq("staff_id", staff_id)
            .in_("classification", ["internal", "public"])
            .order("created_at", desc=True)
            .execute()
        )
        if admin_res.data:
            # First, collect all admin IDs
            for row in admin_res.data:
                admin_ids.add(row.get('id'))
            
            # Fetch attachments for all admin records
            attachments_map = {}
            if admin_ids:
                try:
                    attachments_res = (
                        supabase.table("administrative_attachments")
                        .select("id, administrative_id, filename, file_size, uploaded_at")
                        .in_("administrative_id", list(admin_ids))
                        .order("uploaded_at", desc=True)
                        .execute()
                    )
                    if attachments_res.data:
                        for attachment in attachments_res.data:
                            admin_id = attachment.get('administrative_id')
                            if admin_id not in attachments_map:
                                attachments_map[admin_id] = []
                            attachments_map[admin_id].append({
                                "id": attachment.get('id'),
                                "filename": attachment.get('filename', 'Unknown'),
                                "file_size": attachment.get('file_size', 0),
                                "uploaded_at": attachment.get('uploaded_at', '')
                            })
                except Exception as e:
                    logger.warning(f"Failed to fetch administrative attachments: {e}")
            
            # Build documents list with attachments embedded
            for row in admin_res.data:
                admin_id = row.get('id')
                attachments = attachments_map.get(admin_id, [])
                doc_entry = {
                    "value": f"administrative:{admin_id}",
                    "title": row.get('title', 'Untitled'),
                    "type": "administrative",
                    "record_type": row.get('record_type', 'general'),
                    "classification": row.get('classification', 'internal'),
                    "created_at": _format_creation_time(row.get('created_at', '')),
                    "attachments": attachments
                }
                documents.append(doc_entry)

        # Fetch walk-in appointments (only internal and public, created by this staff)
        appointments_res = (
            supabase.table("appointments")
            .select("id, created_at, patient_id, doctor_id, classification, method, staff_id")
            .eq("method", "walk-in")
            .eq("staff_id", staff_id)
            .in_("classification", ["internal", "public"])
            .order("created_at", desc=True)
            .execute()
        )
        if appointments_res.data:
            for row in appointments_res.data:
                patient_id = row.get('patient_id')
                doctor_id = row.get('doctor_id')
                if patient_id:
                    patient_ids.add(patient_id)
                if doctor_id:
                    doctor_ids.add(doctor_id)
                documents.append({
                    "value": f"appointments:{row.get('id')}",
                    "title": "Walk-in Appointment",
                    "type": "appointment",
                    "patient_id": patient_id,
                    "doctor_id": doctor_id,
                    "classification": row.get('classification', 'internal'),
                    "created_at": _format_creation_time(row.get('created_at', ''))
                })
    except Exception as e:
        logger.error(f"Error loading documents for erasure: {e}")

    # Fetch patient names and NRICs
    patient_name_map = {}
    patient_nric_map = {}
    if patient_ids:
        try:
            patient_res = (
                supabase.table("patient_profile")
                .select("id, full_name, nric_encrypted, dek_encrypted")
                .in_("id", list(patient_ids))
                .execute()
            )
            if patient_res.data:
                for row in patient_res.data:
                    patient_id = row.get('id')
                    patient_name_map[patient_id] = row.get('full_name', 'Unknown')
                    
                    # Decrypt NRIC using envelope decryption
                    try:
                        nric_decrypted = envelope_decrypt_field(row.get('dek_encrypted', ''), row.get('nric_encrypted', ''))
                        if nric_decrypted:
                            masked_nric = re.sub(r'^(.)(.*?)(....)$', r'\1****\3', str(nric_decrypted))
                            patient_nric_map[patient_id] = masked_nric
                        else:
                            patient_nric_map[patient_id] = "N/A"
                    except Exception as e:
                        logger.warning(f"Could not decrypt NRIC for patient {patient_id}: {e}")
                        patient_nric_map[patient_id] = "N/A"
        except Exception as e:
            logger.warning(f"Failed to fetch patient data for erasure list: {e}")

    # Fetch doctor names
    doctor_name_map = {}
    if doctor_ids:
        try:
            doctor_res = (
                supabase.table("doctor_profile")
                .select("id, full_name")
                .in_("id", list(doctor_ids))
                .execute()
            )
            if doctor_res.data:
                for row in doctor_res.data:
                    doctor_name_map[row.get('id')] = row.get('full_name', 'Unknown')
        except Exception as e:
            logger.warning(f"Failed to fetch doctor data for erasure list: {e}")

    # Update documents with patient and doctor names
    for doc in documents:
        if doc.get('type') == 'appointment':
            doc["patient_name"] = patient_name_map.get(doc.get("patient_id"), "Unknown")
            doc["masked_nric"] = patient_nric_map.get(doc.get("patient_id"), "N/A")
            doc["doctor_name"] = doctor_name_map.get(doc.get("doctor_id"), "Unassigned")

    # Fetch pending/approved erasure requests and extract already-requested document IDs
    requested_doc_ids = set()
    try:
        all_requests_res = (
            supabase.table("data_erasure_requests")
            .select("documents, status")
            .eq("requester_id", staff_id)
            .in_("status", ["pending", "approved"])
            .execute()
        )
        if all_requests_res.data:
            for row in all_requests_res.data:
                docs = row.get('documents') or []
                if isinstance(docs, list):
                    requested_doc_ids.update(docs)
    except Exception as e:
        logger.warning(f"Failed to fetch pending/approved erasure requests: {e}")

    # Filter out documents that already have pending or approved erasure requests
    documents = [doc for doc in documents if doc.get("value") not in requested_doc_ids]

    # Fetch recent erasure requests
    recent_requests = []
    try:
        requests_res = (
            supabase.table("data_erasure_requests")
            .select("id, reason, status, created_at, documents, rejection_reason, rejected_at")
            .eq("requester_id", staff_id)
            .order("created_at", desc=True)
            .limit(5)
            .execute()
        )
        if requests_res.data:
            for row in requests_res.data:
                docs = row.get('documents') or []
                docs_count = len(docs) if isinstance(docs, list) else 0
                recent_requests.append({
                    "id": row.get('id'),
                    "reason": row.get('reason'),
                    "status": row.get('status', 'pending'),
                    "created_at": _format_creation_time(row.get('created_at', '')),
                    "rejection_reason": row.get('rejection_reason', ''),
                    "rejected_at": _format_creation_time(row.get('rejected_at', '')) if row.get('rejected_at') else None,
                    "documents_count": docs_count
                })
    except Exception as e:
        logger.error(f"Error loading erasure requests: {e}")

    staff_name = _get_staff_display_name(user_session)
    return render_template(
        'staff/data-erasure.html',
        documents=documents,
        recent_requests=recent_requests,
        staff_name=staff_name
    )

@app.route('/logout')
def logout():
    user_session = session.get('user')
    if user_session:
        # Log logout event before clearing session
        log_phi_event(
            action="LOGOUT",
            classification="internal",
            record_id=user_session.get('user_id') or user_session.get('id'),
            target_user_id=user_session.get('user_id') or user_session.get('id'),
            allowed=True,
            user_name=user_session.get('full_name') or user_session.get('email'),
            resource_description="User Session",
            extra={"role": user_session.get('role')}
        )
    session.pop('user', None)
    session.pop('login_password', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=8081)
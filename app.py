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
        
        audit_record = {
            "timestamp": entry.get("timestamp"),
            "user_id": entry.get("user_id"),
            "user_name": entry.get("role"),
            "action": entry.get("action"),
            "entity_type": entry.get("classification"),
            "entity_id": entry.get("record_id"),
            "old_value": None,
            "new_value": new_value_data,
            "ip_address": entry.get("ip"),
            "user_agent": user_agent,
            "status": "Success" if entry.get("allowed") else "Denied",
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
) -> dict:
    user_session = session.get("user") or {}
    entry = {
        "event_id": str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_id": user_session.get("user_id") or user_session.get("id"),
        "role": user_session.get("role"),
        "clearance_level": user_session.get("clearance_level", "Restricted"),
        "action": action,
        "classification": classification,
        "record_id": record_id,
        "target_user_id": target_user_id,
        "allowed": allowed,
        "ip": request.remote_addr,
        "storage": "append_only_file",
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
                "created_at": datetime.now(timezone.utc).isoformat()
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
    # Normalize role to handle 'Patient' or 'patient'
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
    
    # If role is 'doctor' or 'admin', we return the record unmasked

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
    
    # For pharmacy/counter: mask NRIC and remove notes
    if user_role in ('pharmacy', 'counter'):
        raw_nric = masked_out.get('nric') or ""
        masked_out['nric'] = re.sub(r"^([A-Z])\d{4}(\d{3}[A-Z])$", r"\1****\2", raw_nric)
        masked_out.pop('address', None)
        masked_out.pop('notes', None)
        return masked_out
    return masked_out

# --- Data Loss Prevention (DLP) ---
def run_dlp_security_service(file, user_session):
    """
    Scans file for PHI content and assigns classification label based on findings.
    
    Classification Logic:
    - CRITICAL PHI detected (NRIC, Medical Records) → Confidential
    - SENSITIVE PHI detected (Names, Contact Info) → Restricted  
    - No PHI detected → Internal
    
    All documents are uploaded regardless of classification.
    """
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
    
    # NRIC Check (Singapore NRIC/FIN pattern)
    if re.search(r"[STFG]\d{7}[A-Z]", text, re.IGNORECASE):
        logger.info("DLP: NRIC pattern detected in document")
        findings.append({"id": "NRIC_FIN", "name": "NRIC/Medical Record Number", "type": "CRITICAL"})
    
    # Phone Check (Singapore mobile numbers)
    if re.search(r"[89]\d{7}", text):
        logger.info("DLP: Phone number detected in document")
        findings.append({"id": "PHONE_SG", "name": "Contact Information", "type": "SENSITIVE"})
    
    # NLP Name Detection (Person and Organization entities)
    doc_nlp = nlp(text)
    for ent in doc_nlp.ents:
        if ent.label_ in ["PERSON", "ORG"]:
            logger.info(f"DLP: {ent.label_} entity detected: {ent.text}")
            findings.append({"id": "NLP_DETECTION", "name": "Patient Name/Identity", "type": "SENSITIVE"})
            break  # Only add once to avoid duplicates

    # Generate audit tracking ID
    audit_id = f"AUDIT-{time.strftime('%Y%m%d')}-{secrets.token_hex(3).upper()}"
    
    # Create PHI tags summary
    phi_tags = ", ".join(list(set([f['name'] for f in findings]))) if findings else "No PHI Detected"
    
    # Assign classification based on findings
    # CRITICAL findings (NRIC, Medical Records) → Confidential
    # SENSITIVE findings (Names, Phone) → Restricted
    # No findings → Internal
    classification = "internal"  # Default
    
    if any(f['type'] == 'CRITICAL' for f in findings):
        classification = "confidential"
        sensitivity_level = "High - Contains Critical PHI"
    elif any(f['type'] == 'SENSITIVE' for f in findings):
        classification = "restricted"
        sensitivity_level = "Medium - Contains Sensitive Information"
    else:
        classification = "internal"
        sensitivity_level = "Low - No PHI Detected"
    
    # Return classification and metadata
    return {
        "audit_id": audit_id,
        "classification": classification,
        "sensitivity_level": sensitivity_level,
        "phi_tags": phi_tags,
        "findings": findings,
        "findings_count": len(findings)
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
                'address': data.get('address', ''),
                'dob': data.get('dob') if data.get('dob') else None
            }
            
            # Generate DEK and encrypt fields (no existing DEK for new user)
            dek_encrypted, encrypted_fields = envelope_encrypt_fields(None, phi_fields)
            
            profile_entry = {
                "id": auth_res.user.id, 
                "full_name": data.get('fullName'),
                "email": data.get('email'),
                "nric_encrypted": encrypted_fields.get('nric_encrypted'),
                "phone_encrypted": encrypted_fields.get('phone_encrypted'),
                "address_encrypted": encrypted_fields.get('address_encrypted'),
                "dob_encrypted": encrypted_fields.get('dob_encrypted'),
                "dek_encrypted": dek_encrypted,
                "clinic_id": None,
            }
            
            supabase.table("patient_profile").insert(profile_entry).execute()

            supabase.table("profiles").insert({
                "id": auth_res.user.id,
                "full_name": data.get('fullName'),
                "clearance_level": "Restricted",
                "nric": data.get('nric'),
                "mobile_number": data.get('phone'),
                "role": "patient"
            }).execute()
            
            logger.info(f"User registered with encrypted PHI: {auth_res.user.id}")
            
            session.pop('reg_otp', None)
            session.pop('temp_reg_data', None)
            return jsonify({"success": True})
            
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
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
                        'full_name': profile.get('full_name', ''),
                    }
                    session['login_password'] = password
                    
                    logger.info(f"User logged in: {auth_res.user.id}, role: {role}")
                    
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
        # Fetch all consultations from database
        consultations_res = (
            supabase.table("consultations")
            .select("id, patient_id, doctor_name, diagnosis, classification, created_at")
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
        
        # Fetch consultation from database
        consultation_res = (
            supabase.table("consultations")
            .select("*")
            .eq("id", consultation_id)
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
        
        logger.info(f"Consultation {consultation_id} retrieved for viewing")

        log_phi_event(
            action="VIEW_CONSULTATION",
            classification=consultation.get("classification", "restricted"),
            record_id=consultation_id,
            target_user_id=consultation.get("patient_id"),
            allowed=True
        )
        
        return render_template('doctor/view-consultation.html', consultation=consultation)
        
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
    
    if request.method == 'POST':
        patient_name = request.form.get('patient_name', '').strip()
        patient_id = request.form.get('patient_id', '').strip()
        classification = request.form.get('classification', 'confidential').strip()
        start_date_str = request.form.get('start_date', '').strip()
        duration = request.form.get('duration', '1').strip()
        
        if not patient_id:
            flash('Please select a patient from the search results', 'error')
            return render_template('doctor/write-mc.html', 
                                   patient=patient, 
                                   doctor=doctor, 
                                   today=today)
        
        if not start_date_str:
            flash('Please select a start date', 'error')
            return render_template('doctor/write-mc.html', 
                                   patient=patient, 
                                   doctor=doctor, 
                                   today=today)
        
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
            default_classification = "confidential"
            classification_method = "Automatic" if classification == default_classification else "Manual"
            
            # Create MC record in database
            mc_data = {
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
                        "duration": duration_days,
                        "start_date": start_date.isoformat(),
                        "end_date": end_date.isoformat()
                    }
                )
                
                flash(f'Medical Certificate issued successfully for {duration_days} day(s)!', 'success')
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
                               today=today)
    
    return render_template('doctor/write-mc.html', 
                           patient=patient, 
                           doctor=doctor, 
                           today=today)


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

    if request.method == 'POST':
        user_session = session.get('user')
        doctor_id = user_session.get('user_id') or user_session.get('id')
        patient_id = request.form.get('patient_id', '').strip()
        patient_name = request.form.get('patient_name', '').strip()
        classification = request.form.get('classification', 'internal').strip()
        default_classification = "internal"
        classification_method = "Automatic" if classification == default_classification else "Manual"

        if not patient_id:
            flash('Please select a patient from the search results', 'error')
            return render_template('doctor/write-prescription.html', patient=patient)

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
            return render_template('doctor/write-prescription.html', patient=patient)

        try:
            prescription_data = {
                "patient_id": patient_id,
                "doctor_id": doctor_id,
                "medications": medications,
                "classification": classification,
                "classification_method": classification_method,
                "created_at": datetime.now(timezone.utc).isoformat()
            }

            insert_res = supabase.table("prescriptions").insert(prescription_data).execute()
            if not insert_res.data:
                flash('Failed to generate prescription. Please try again.', 'error')
                return render_template('doctor/write-prescription.html', patient=patient)

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
            return render_template('doctor/write-prescription.html', patient=patient)

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
#@login_required
def admin_dashboard():
    #user = session.get('user')
    #if user.get('role') not in ('admin', 'clinic_manager'):
    #    abort(403)
    return render_template('admin/admin-dashboard.html')

@app.route('/admin/audit-logs')
#@login_required
def admin_audit_logs():
    #user = session.get('user')
    #if user.get('role') not in ('admin', 'clinic_manager'):
    #    abort(403)
    return render_template('admin/audit-logs.html')

@app.route('/admin/user-management')
#@login_required
def admin_user_management():
    #user = session.get('user')
    #if user.get('role') not in ('admin', 'clinic_manager'):
    #    abort(403)
    return render_template('admin/user-management.html')

@app.route('/admin/backup-recovery')
#@login_required
def admin_backup_recovery():
    #user = session.get('user')
    #if user.get('role') not in ('admin', 'clinic_manager'):
    #    abort(403)
    return render_template('admin/backup-recovery.html')

@app.route('/admin/data-retention')
#@login_required
def admin_data_retention():
    #user = session.get('user')
    #if user.get('role') not in ('admin', 'clinic_manager'):
    #    abort(403)
    return render_template('admin/data-retention.html')


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
#@login_required
def admin_security_classification_matrix():
    """Display the Classification Summary Matrix for all records."""
    #user = session.get('user')
    #if user.get('role') not in ('admin', 'clinic_manager'):
    #    abort(403)
    
    # Fetch detailed classification counts from database
    classification_counts = {
        'restricted': 0,
        'confidential': 0,
        'internal': 0,
        'public': 0,
        'total': 0
    }
    
    classification_details = {
        'restricted': {'consultations': 0, 'medical_certificates': 0, 'prescriptions': 0, 'appointments': 0, 'administrative': 0},
        'confidential': {'consultations': 0, 'medical_certificates': 0, 'prescriptions': 0, 'appointments': 0, 'administrative': 0},
        'internal': {'consultations': 0, 'medical_certificates': 0, 'prescriptions': 0, 'appointments': 0, 'administrative': 0},
        'public': {'consultations': 0, 'medical_certificates': 0, 'prescriptions': 0, 'appointments': 0, 'administrative': 0}
    }
    
    # Records for the detailed overview table
    records = []
    
    try:
        # Fetch consultations with classification
        consultations_res = supabase.table("consultations").select("id, created_at, classification, doctor_id, classification_method").execute()
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
        
        # Fetch medical certificates with classification
        mc_res = supabase.table("medical_certificates").select("id, created_at, classification, doctor_id, classification_method").execute()
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

        # Fetch prescriptions with classification
        prescriptions_res = supabase.table("prescriptions").select("id, created_at, classification, doctor_id, classification_method").execute()
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

        # Fetch appointments with classification
        try:
            appointments_res = supabase.table("appointments").select(
                "id, created_at, classification, classification_method, method, staff_id, patient_id"
            ).execute()
        except Exception as e:
            logger.warning(f"Appointments query with staff_id failed, retrying without staff_id: {e}")
            appointments_res = supabase.table("appointments").select(
                "id, created_at, classification, classification_method, method, patient_id"
            ).execute()
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
        
        # Fetch administrative records with classification
        administrative_res = supabase.table("administrative").select("id, created_at, classification, staff_id, classification_method").execute()
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
                    'role': 'Staff'
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
    return render_template('patient/appointment-history.html')

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
        
        # Fetch medical certificates for this patient
        mc_res = supabase.table("medical_certificates").select("*").eq("patient_id", user_id).execute()
        
        certificates = []
        if mc_res.data:
            for mc in mc_res.data:
                # Generate MC Number
                mc_number = str(int(hashlib.sha256(f"{mc.get('id', '')}{user_id}".encode()).hexdigest(), 16) % 10000000000).zfill(10)
                
                cert_dict = {
                    'id': mc.get('id'),
                    'status': mc.get('status', 'active'),
                    'doctor': mc.get('doctor_name', 'Doctor'),
                    'issue_date': mc.get('issued_at', '').split('T')[0] if mc.get('issued_at') else '',
                    'duration': f"{mc.get('duration_days', 1)} day(s)",
                    'start_date': mc.get('start_date', '').split('T')[0] if mc.get('start_date') else '',
                    'end_date': mc.get('end_date', '').split('T')[0] if mc.get('end_date') else '',
                    'mc_number': mc_number
                }
                certificates.append(cert_dict)
        
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
        # Verify the certificate belongs to the logged-in patient
        mc_res = supabase.table("medical_certificates").select("*").eq("id", id).single().execute()
        
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
        
        # Generate MC Number (randomly generated, 10 digits format)
        mc_number = str(int(hashlib.sha256(f"{mc_data.get('id', '')}{user_id}".encode()).hexdigest(), 16) % 10000000000).zfill(10)
        
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
        
        # MC Number
        draw_text(page, f"MC No.    :{mc_number}", margin, y_pos, size=7)
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
            allowed=True
        )
        
        # Return PDF file
        filename = f"Medical_Certificate_{mc_number}_{issue_date}.pdf"
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
    return render_template('patient/prescriptions.html')

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
                'dob': request.form.get('dob', '') or ''
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
                "dek_encrypted": dek_encrypted,
                # plaintext fields
                "full_name": non_phi['full_name'],
                "gender": non_phi['gender'],
                "nationality": non_phi['nationality'],
                "blood_type": non_phi['blood_type'],
                "email": non_phi['email'],
                "postal_code": non_phi['postal_code'],
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

            # 4) sync profiles table for non-PHI summary fields
            profiles_update = {
                "full_name": non_phi['full_name'],
                "mobile_number": phi_fields['phone']
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

        # Now pass to template
        return render_template('patient/personal-particulars.html', 
                       profile=display_profile, 
                       patient_profile=display_profile)

    except Exception as e:
        logger.exception("Load Error")
        flash("Error loading profile", "error")
        return redirect(url_for('patient_dashboard'))

@app.route('/upload-documents', methods=['GET', 'POST'])
@login_required
def upload_documents():
    user = session.get('user')
    user_id = user.get('user_id') or user.get('id')

    if request.method == 'POST':
        try:
            if 'documents' not in request.files:
                flash("No file part", "error")
                return redirect(request.url)
            
            file = request.files['documents']
            if file.filename == '':
                flash("No selected file", "error")
                return redirect(request.url)

            # Run DLP scan to detect PHI and assign classification
            dlp_result = run_dlp_security_service(file, user)
            classification = dlp_result.get('classification', 'confidential')
            sensitivity_level = dlp_result.get('sensitivity_level', 'Unknown')
            
            # Get file size for metadata
            file.seek(0, 2)
            size_bytes = file.tell()
            file.seek(0)

            # Create document record in database
            doc_data = {
                "user_id": user_id,
                "filename": file.filename,
                "size": f"{size_bytes // 1024} KB",
                "created_at": datetime.now().strftime("%Y-%m-%d"),
                "classification": classification,
                "dlp_status": f"DLP Classified: {classification.upper()} - {sensitivity_level}",
                "phi_tags": dlp_result.get('phi_tags', 'None Detected'),
                "audit_id": dlp_result.get('audit_id', 'N/A')
            }

            # Save document to patient_documents table
            insert_result = supabase.table("patient_documents").insert(doc_data).execute()
            document_id = None
            if insert_result.data:
                document_id = insert_result.data[0].get('id') if isinstance(insert_result.data, list) else insert_result.data.get('id')

            # Log to audit trail (hash chain + triple storage)
            log_phi_event(
                action="UPLOAD_PATIENT_DOCUMENT",
                classification=classification,
                record_id=str(document_id) if document_id else file.filename,
                target_user_id=user_id,
                allowed=True,
                extra={
                    "filename": file.filename,
                    "size_kb": size_bytes // 1024,
                    "dlp_classification": classification,
                    "sensitivity_level": sensitivity_level,
                    "dlp_scan_results": {
                        "phi_detected": dlp_result.get('phi_tags', 'None'),
                        "findings_count": len(dlp_result.get('findings', [])),
                        "audit_id": dlp_result.get('audit_id', 'N/A')
                    }
                }
            )
            
            flash(f"Document '{file.filename}' uploaded successfully. DLP Classification: {classification.upper()} ({sensitivity_level}).", "success")
            return redirect(url_for('upload_documents'))
        
        except Exception as e:
            logger.error(f"Error uploading document: {str(e)}")
            flash(f"Error uploading document: {str(e)}", "error")
            return redirect(request.url)

    # GET Request: Fetch documents to show in list
    docs = get_patient_docs(user_id)
    return render_template('patient/upload-documents.html', documents=docs)

def get_patient_docs(user_id):
    res = supabase.table("patient_documents").select("*").eq("user_id", user_id).execute()
    return res.data if res.data else []

@app.route('/delete-document/<id>', methods=['POST'])
@login_required
def delete_document(id):
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
                "status, created_at, visit_type, method"
            )
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
    user_session = session.get('user')
    staff_name = _get_staff_display_name(user_session)
    # Mock patient data
    patients = [
        {"id": "P001", "name": "John Doe", "nric": "S1234567A", "phone": "91234567"},
        {"id": "P002", "name": "Jane Smith", "nric": "S2345678B", "phone": "92345678"},
        {"id": "P003", "name": "Ahmad Hassan", "nric": "S3456789C", "phone": "93456789"},
        {"id": "P004", "name": "Mary Tan", "nric": "S4567890D", "phone": "94567890"},
        {"id": "P005", "name": "Kumar Raj", "nric": "S5678901E", "phone": "95678901"},
    ]
    
    uploaded_files = [
        {"id": "1", "name": "lab-results-2024.pdf", "type": "Lab Results", "size": "1.2 MB", "patient": "John Doe", "uploaded_at": "2024-12-15"},
        {"id": "2", "name": "xray-scan.jpg", "type": "X-Ray", "size": "2.5 MB", "patient": "Jane Smith", "uploaded_at": "2024-12-14"},
    ]
    
    if request.method == 'POST':
        flash('Document uploaded successfully!', 'success')
        return redirect(url_for('staff_upload'))
    
    return render_template('staff/document-upload.html',
                         patients=patients,
                         uploaded_files=uploaded_files,
                         staff_name=staff_name)

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
                        
                        # Get file size
                        file.seek(0, 2)
                        file_size = file.tell()
                        file.seek(0)
                        
                        # Get mime type
                        mime_type = file.content_type
                        
                        # Create secure filename
                        filename = secure_filename(file.filename)
                        
                        # Create upload directory if it doesn't exist
                        upload_dir = os.path.join(app.instance_path, 'uploads', 'administrative', str(admin_id))
                        os.makedirs(upload_dir, exist_ok=True)
                        
                        # Save file to disk
                        file_path = os.path.join(upload_dir, filename)
                        file.save(file_path)
                        
                        # Store metadata in database
                        attachment_data = {
                            "administrative_id": admin_id,
                            "filename": filename,
                            "file_path": f"administrative/{admin_id}/{filename}",
                            "file_size": file_size,
                            "mime_type": mime_type,
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
    """Download a public announcement attachment (no login required)."""
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
        
        # Send file to user
        from flask import send_file
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
    """Download an administrative work attachment."""
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
        
        # Send file to user
        from flask import send_file
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

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('login_password', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=8081)
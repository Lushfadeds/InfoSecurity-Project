import os
import re
import secrets
import logging
from datetime import datetime, timezone
from functools import wraps
import pymupdf as fitz
import spacy
import time

from flask import (
    Flask, render_template, request, redirect, 
    url_for, session, abort, jsonify, flash
)
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail, Message
from supabase import create_client, Client
from dotenv import load_dotenv

# Import envelope encryption module
from crypto_fields import (
    envelope_encrypt_fields,
    envelope_decrypt_field,
    envelope_decrypt_fields,
    get_profile_with_decryption,
    can_access_record,
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

# --- Access Control Helpers ---
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

    if user_role in ('doctor', 'admin', 'clinic_manager'):
        # doctors/admins see full (doctors shouldn't see staff restricted fields — handled elsewhere)
        return record
    
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
    """Processes file for PHI and returns metadata for UI badges."""
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
        return {"action": "BLOCK", "error": "Extraction Failed"}

    findings = []
    
    # NRIC Check (Added re.IGNORECASE)
    if re.search(r"[STFG]\d{7}[A-Z]", text, re.IGNORECASE):
        print("!!! TRIGGERED: NRIC Pattern Found") # DEBUG
        findings.append({"id": "NRIC_FIN", "name": "NRIC, Medical Record", "type": "CRITICAL"})
    
    # Phone Check
    if re.search(r"[89]\d{7}", text):
        print(f"!!! TRIGGERED: Phone Pattern Found in text") # DEBUG
        findings.append({"id": "PHONE_SG", "name": "Contact Info", "type": "SENSITIVE"})
    
    # NLP Name Detection
    doc_nlp = nlp(text)
    for ent in doc_nlp.ents:
        if ent.label_ in ["PERSON", "ORG"]:
            print(f"!!! TRIGGERED NLP: {ent.text} ({ent.label_})") # DEBUG
            findings.append({"id": "NLP_DETECTION", "name": "Patient Name/Identity", "type": "SENSITIVE"})

    # Action Logic
    action = "PASS"
    if any(f['type'] == 'CRITICAL' for f in findings):
        action = "BLOCK"
    elif findings:
        action = "FLAG"

    # UI Badge Data
    audit_id = f"AUDIT-{time.strftime('%Y%m%d')}-{secrets.token_hex(2).upper()}"
    phi_tags = ", ".join(list(set([f['name'] for f in findings]))) if findings else "None Detected"
    
    return {
        "action": action,
        "audit_id": audit_id,
        # Swapped: Restricted is usually the highest level
        "classification": "Restricted" if action != "PASS" else "Internal", 
        "dlp_status": "DLP Passed" if action != "BLOCK" else "DLP Blocked",
        "phi_tags": phi_tags,
        "findings": findings
    }



@app.context_processor
def inject_globals():
    from datetime import timezone
    return {'current_user': session.get('user'), 'current_year': datetime.now(timezone.utc).year}

# --- Routes ---
@app.route('/')
def index():
    return render_template('public/index.html')

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
def doctor_dashboard():
    # Mock data for pending tasks and appointments
    pending_tasks = [
        {'message': 'Sign MC for John Doe (consultation completed)', 'link': '/doctor/write-mc'},
        {'message': '2 lab results ready for review', 'link': '/doctor/patient-lookup'},
    ]
    todays_appointments = [
        {'id': '1', 'time': '09:00 AM', 'patient': 'John Doe', 'nric': 'S****123A', 'reason': 'General consultation', 'status': 'Confirmed'},
        {'id': '2', 'time': '09:30 AM', 'patient': 'Jane Smith', 'nric': 'S****456B', 'reason': 'Follow-up', 'status': 'Checked-in'},
        {'id': '3', 'time': '10:00 AM', 'patient': 'Michael Tan', 'nric': 'S****789C', 'reason': 'Flu symptoms', 'status': 'Confirmed'},
    ]
    return render_template('doctor/doctor-dashboard.html', 
                           pending_tasks=pending_tasks, 
                           appointments=todays_appointments)


@app.route('/doctor/patient-lookup')
def doctor_patient_lookup():
    search_term = request.args.get('q', '')
    search_by = request.args.get('search_by', 'name')
    
    # Mock patient database
    all_patients = [
        {'id': '1', 'name': 'John Doe', 'nric': 'S****123A', 'dob': '15 May 1990', 'last_visit': '10 Dec 2024'},
        {'id': '2', 'name': 'Jane Smith', 'nric': 'S****456B', 'dob': '22 Aug 1985', 'last_visit': '28 Nov 2024'},
        {'id': '3', 'name': 'Alice Tan', 'nric': 'S****789C', 'dob': '10 Mar 1992', 'last_visit': '15 Dec 2024'},
        {'id': '4', 'name': 'Bob Lee', 'nric': 'S****234D', 'dob': '25 Jul 1988', 'last_visit': '08 Dec 2024'},
        {'id': '5', 'name': 'Mary Wong', 'nric': 'S****567E', 'dob': '18 Nov 1995', 'last_visit': '12 Dec 2024'},
    ]
    
    # Filter patients based on search
    if search_term:
        patients = [p for p in all_patients if search_term.lower() in p.get(search_by, '').lower()]
    else:
        patients = all_patients
    
    return render_template('doctor/patient-lookup.html', 
                           patients=patients, 
                           search_term=search_term, 
                           search_by=search_by)


@app.route('/doctor/consultation', methods=['GET', 'POST'])
@app.route('/doctor/consultation/<patient_id>', methods=['GET', 'POST'])
def doctor_consultation(patient_id=None):
    # Mock patient data
    patients = {
        '1': {'id': '1', 'name': 'John Doe', 'nric': 'S****123A', 'age': 34, 'gender': 'Male', 'contact': '+65 9123 4567'},
        '2': {'id': '2', 'name': 'Jane Smith', 'nric': 'S****456B', 'age': 39, 'gender': 'Female', 'contact': '+65 8765 4321'},
        '3': {'id': '3', 'name': 'Alice Tan', 'nric': 'S****789C', 'age': 32, 'gender': 'Female', 'contact': '+65 9234 5678'},
    }
    
    patient = patients.get(patient_id, patients['1'])
    
    previous_visits = [
        {'date': 'Dec 10, 2023', 'reason': 'Annual checkup'},
        {'date': 'Jun 15, 2023', 'reason': 'Flu symptoms'},
    ]
    
    if request.method == 'POST':
        try:
            # Extract consultation data from form
            diagnosis = request.form.get('diagnosis', '')
            notes = request.form.get('notes', '')
            treatment_plan = request.form.get('treatment_plan', '')
            classification = request.form.get('classification', 'restricted')
            
            # Validate classification
            valid_classifications = ['restricted', 'confidential', 'internal', 'public']
            if classification not in valid_classifications:
                classification = 'restricted'
            
            # Get current user (doctor) from session — allow fallback values for testing
            user_session = session.get('user') or {}
            doctor_id = user_session.get('user_id') or user_session.get('id') or 'test-doctor'
            doctor_name = user_session.get('full_name', 'Test Doctor')
            
            # Encrypt sensitive fields (clinical notes contain PHI)
            phi_fields = {
                'clinical_notes': notes
            }
            
            # Get doctor's DEK for encryption — skip profile lookup for test doctor_ids
            doctor_dek_encrypted = None
            # Only fetch profile if doctor_id looks like a UUID (contains hyphens and is 36 chars)
            if isinstance(doctor_id, str) and len(doctor_id) == 36 and '-' in doctor_id:
                try:
                    doctor_profile_res = (
                        supabase.table("profiles")
                        .select("dek_encrypted")
                        .eq("id", doctor_id)
                        .single()
                        .execute()
                    )
                
                    if doctor_profile_res.data:
                        doctor_dek_encrypted = doctor_profile_res.data.get('dek_encrypted')
                except Exception as profile_error:
                    logger.warning(f"Could not fetch doctor profile for DEK: {str(profile_error)}")
                    doctor_dek_encrypted = None
            else:
                logger.debug(f"Skipping DEK profile lookup for non-UUID doctor_id: {doctor_id}")
        
            # Encrypt the clinical notes
            dek_encrypted, encrypted_fields = envelope_encrypt_fields(doctor_dek_encrypted, phi_fields)
            
            # Prepare consultation record
            consultation_record = {
                "patient_id": patient_id,
                "doctor_id": doctor_id,
                "doctor_name": doctor_name,
                "diagnosis": diagnosis,
                "clinical_notes_encrypted": encrypted_fields.get('clinical_notes_encrypted', ''),
                "treatment_plan": treatment_plan,
                "classification": classification,
                "dek_encrypted": dek_encrypted,
                    "created_at": datetime.now(timezone.utc).isoformat()
            }
            
            # Handle file upload if present
            if 'document' in request.files:
                file = request.files['document']
                if file and file.filename:
                    # For now, store filename reference (actual file handling would be done with cloud storage)
                    consultation_record["document_filename"] = file.filename
                    logger.info(f"Document uploaded: {file.filename}")
            
            # Insert consultation record into database
            insert_res = supabase.table("consultations").insert(consultation_record).execute()
            
            if insert_res.data:
                logger.info(f"Consultation saved for patient {patient_id} by doctor {doctor_id} with classification: {classification}")
                flash(f'Consultation saved successfully as {classification.title()}!', 'success')
                return redirect(url_for('doctor_consultation', patient_id=patient_id))
            else:
                logger.error("Failed to insert consultation record")
                flash('Error saving consultation', 'error')
                
        except Exception as e:
            logger.error(f"Error saving consultation: {str(e)}")
            flash(f'Error saving consultation: {str(e)}', 'error')
    
    return render_template('doctor/consultation.html', 
                           patient=patient, 
                           previous_visits=previous_visits)


@app.route('/doctor/view-consultations')
def list_consultations():
    """List all saved consultations - redirects to password check."""
    return redirect(url_for('verify_consultation_password'))


@app.route('/doctor/verify-consultation-password', methods=['GET', 'POST'])
def verify_consultation_password():
    """Password verification page for viewing consultations."""
    CONSULTATION_PASSWORD = 'p@ssw0rd'  # Hardcoded password for security check
    
    if request.method == 'POST':
        entered_password = request.form.get('password', '')
        
        if entered_password == CONSULTATION_PASSWORD:
            # Password is correct - redirect to consultation list
            session['consultation_auth'] = True
            session['consultation_auth_time'] = datetime.now(timezone.utc).isoformat()
            flash('Password verified. You can now view consultations.', 'success')
            return redirect(url_for('consultations_list'))
        else:
            flash('Incorrect password. Please try again.', 'error')
    
    return render_template('doctor/verify-password.html')


@app.route('/doctor/consultations-list')
def consultations_list():
    """List all saved consultations (password protected)."""
    # Check if user has verified password in this session
    if not session.get('consultation_auth'):
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
        logger.info(f"Fetched {len(consultations)} consultations")
        
        return render_template('doctor/consultations-list.html', consultations=consultations)
        
    except Exception as e:
        logger.error(f"Error fetching consultations: {str(e)}")
        flash("Error loading consultations", "error")
        return redirect(url_for('doctor_dashboard'))


@app.route('/doctor/view-consultation/<consultation_id>')
def view_consultation(consultation_id):
    """View a saved consultation with decrypted clinical notes (password protected)."""
    # Check if user has verified password in this session
    if not session.get('consultation_auth'):
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
def doctor_write_mc():
    from datetime import date
    
    # Mock patient and doctor data
    patient = {'name': 'John Doe', 'nric': 'S****123A'}
    doctor = {'name': 'Dr. Sarah Tan', 'specialty': 'General Practitioner'}
    today = date.today().strftime('%d/%m/%Y')
    
    if request.method == 'POST':
        flash('MC issued successfully!', 'success')
        return redirect(url_for('doctor_dashboard'))
    
    return render_template('doctor/write-mc.html', 
                           patient=patient, 
                           doctor=doctor, 
                           today=today)


@app.route('/doctor/write-prescription', methods=['GET', 'POST'])
def doctor_write_prescription():
    # Mock patient data
    patient = {'name': 'John Doe', 'nric': 'S****123A'}
    
    if request.method == 'POST':
        flash('Prescription generated successfully!', 'success')
        return redirect(url_for('doctor_dashboard'))
    
    return render_template('doctor/write-prescription.html', patient=patient)


@app.route('/doctor/profile')
def doctor_profile():
    # Mock doctor data
    doctor = {
        'name': 'Dr. Sarah Tan',
        'specialty': 'General Practitioner',
        'mcr_number': 'M12345',
        'email': 'sarah.tan@pinkhealth.sg'
    }
    return render_template('doctor/doctor-profile.html', doctor=doctor)


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

@app.route('/book-appointment')
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
    
    doctors_list = [
        {"id": 1, "name": "Dr. Sarah Tan", "specialty": "General Practitioner", "experience": "10 years", "availability": "Mon - Fri"},
        {"id": 2, "name": "Dr. Michael Lim", "specialty": "Cardiologist", "experience": "15 years", "availability": "Tue - Thu"}
    ]
    if request.method == 'POST':
        # Handle the booking save logic here later
        return render_template('patient/book-appointment.html', doctors=doctors_list, booking_success=True)
    
    return render_template('patient/book-appointment.html', doctors=doctors_list, user=masked_data)

@app.route('/appointment-history')
@login_required
def appointment_history():
    return render_template('patient/appointment-history.html')

@app.route('/medical-certificates')
@login_required
def medical_certificates():
    return render_template('patient/medical-certificates.html')

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

    if request.method == 'POST':
        if 'documents' not in request.files:
            flash("No file part", "error")
            return redirect(request.url)
        
        file = request.files['documents']
        if file.filename == '':
            flash("No selected file", "error")
            return redirect(request.url)

        # 1. Run Security Scan
        dlp_result = run_dlp_security_service(file, user)

        # 2. Log to Audit Table (Always)
        supabase.table("audit_logs").insert({
            "user_name": user.get('full_name'),
            "action": f"UPLOAD_{dlp_result['action']}",
            "status": "Blocked" if dlp_result['action'] == "BLOCK" else "Success",
            "entity_id": file.filename,
            "details": dlp_result,
            "timestamp": datetime.now().isoformat()
        }).execute()

        # 3. If Blocked, show error
        if dlp_result['action'] == "BLOCK":
            return render_template('patient/upload-documents.html', 
                                   upload_error=f"Security Policy Violation: Sensitive data detected.",
                                   documents=get_patient_docs(user['id']))

        # 4. If Passed/Flagged, save to Document Table for UI List

        file.seek(0, 2) # Move to end
        size_bytes = file.tell() # Get position (size)
        file.seek(0) # Reset to beginning

        doc_data = {
            "user_id": user['id'],
            "name": file.filename,
            "size": f"{size_bytes // 1024} KB",
            "created_at": datetime.now().strftime("%Y-%m-%d"),
            "classification": dlp_result['classification'],
            "dlp_status": dlp_result['dlp_status'],
            "phi_tags": dlp_result['phi_tags'],
            "audit_id": dlp_result['audit_id']
        }

        supabase.table("patient_documents").insert(doc_data).execute()
        
        flash("File uploaded and scanned successfully.", "success")
        return redirect(url_for('upload_documents'))

    # GET Request: Fetch documents to show in list
    docs = get_patient_docs(user['id'])
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
    # Mock patient queue data
    patient_queue = [
        {"id": "1", "name": "John Doe", "nric": "S****123A", "appointment_time": "09:00 AM", "status": "Waiting"},
        {"id": "2", "name": "Jane Smith", "nric": "S****456B", "appointment_time": "09:30 AM", "status": "In Consultation"},
        {"id": "3", "name": "Michael Tan", "nric": "S****789C", "appointment_time": "10:00 AM", "status": "Waiting"},
    ]
    
    recent_activity = [
        {"description": "Appointment created for John Doe", "time": "2 hours ago"},
        {"description": "Payment received from Jane Smith", "time": "4 hours ago"},
        {"description": "Documents uploaded for Michael Tan", "time": "1 day ago"},
    ]
    
    return render_template('staff/staff-dashboard.html', 
                         patient_queue=patient_queue,
                         recent_activity=recent_activity,
                         staff_name="Alice Wong")

@app.route('/staff/create-appointment', methods=['GET', 'POST'])
@login_required
def staff_create_appointment():
    # Mock patient data
    patients = [
        {"id": "1", "name": "John Doe", "nric": "S1234567A", "nric_masked": "S****567A", "phone": "+65 9123 4567", "email": "john.doe@example.com", "dob": "1990-05-15"},
        {"id": "2", "name": "Jane Smith", "nric": "S2345678B", "nric_masked": "S****678B", "phone": "+65 8765 4321", "email": "jane.smith@example.com", "dob": "1985-08-22"},
        {"id": "3", "name": "Alice Tan", "nric": "S3456789C", "nric_masked": "S****789C", "phone": "+65 9234 5678", "email": "alice.tan@example.com", "dob": "1992-03-10"},
        {"id": "4", "name": "Bob Lee", "nric": "S4567890D", "nric_masked": "S****890D", "phone": "+65 8876 5432", "email": "bob.lee@example.com", "dob": "1988-07-25"},
        {"id": "5", "name": "Mary Wong", "nric": "S5678901E", "nric_masked": "S****901E", "phone": "+65 9345 6789", "email": "mary.wong@example.com", "dob": "1995-11-18"},
    ]
    
    doctors = [
        {"id": "1", "name": "Dr. Sarah Tan", "specialty": "General Practitioner"},
        {"id": "2", "name": "Dr. James Wong", "specialty": "Cardiologist"},
        {"id": "3", "name": "Dr. Michelle Lee", "specialty": "Dermatologist"},
    ]
    
    time_slots = [
        {"value": "10:30", "label": "Next Available (10:30 AM)"},
        {"value": "11:00", "label": "11:00 AM"},
        {"value": "11:30", "label": "11:30 AM"},
        {"value": "12:00", "label": "12:00 PM"},
        {"value": "14:00", "label": "2:00 PM"},
        {"value": "14:30", "label": "2:30 PM"},
    ]
    
    if request.method == 'POST':
        # Handle appointment creation
        flash('Appointment created successfully!', 'success')
        return redirect(url_for('staff_dashboard'))
    
    return render_template('staff/create-appointment.html',
                         patients=patients,
                         doctors=doctors,
                         time_slots=time_slots,
                         staff_name="Alice Wong")

@app.route('/staff/billing', methods=['GET', 'POST'])
@login_required
def staff_billing():
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
                         staff_name="Alice Wong")

@app.route('/staff/upload', methods=['GET', 'POST'])
@login_required
def staff_upload():
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
                         staff_name="Alice Wong")

@app.route('/staff/admin-work', methods=['GET', 'POST'])
@login_required
def staff_admin_work():
    recent_records = [
        {"id": "1", "title": "Monthly Team Meeting Notes", "type": "Staff Memo", "date": "2024-12-15", "status": "Approved"},
        {"id": "2", "title": "Medical Leave Request", "type": "Leave Request", "date": "2024-12-10", "status": "Pending"},
        {"id": "3", "title": "Training Completion Report", "type": "Training Record", "date": "2024-12-05", "status": "Approved"},
    ]
    
    if request.method == 'POST':
        flash('Administrative record submitted successfully!', 'success')
        return redirect(url_for('staff_admin_work'))
    
    return render_template('staff/admin-work.html',
                         recent_records=recent_records,
                         staff_name="Alice Wong")

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=8081)
import os
import base64
from datetime import datetime
from functools import wraps
import re
from flask_mail import Mail, Message

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    abort,
    jsonify,
    flash
)

from supabase import (
    create_client,
    Client
)

from dotenv import load_dotenv

from flask_sqlalchemy import SQLAlchemy
from passlib.hash import pbkdf2_sha256
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
import base64 as _b64
try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except Exception:
    boto3 = None

load_dotenv()
# --- App + config --------------------------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-change-me')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')


supabase: Client = create_client(
    os.environ.get('SUPABASE_URL'),
    os.environ.get('SUPABASE_PUBLISHABLE_KEY')
)

mail = Mail(app)


# --- Access control helpers ----------------------------------------------
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return fn(*args, **kwargs)

    return wrapper


def role_required(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            u = session.get('user')
            if not u or u.get('role') not in roles:
                abort(403)
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def can_access_record(user_session: dict, record: dict, action: str = 'read') -> bool:
    """Simple MAC+ABAC style check.

    user_session: dict from session containing user_id, role, clearance_level, patient_id, clinic_id
    record: dict must include 'patient_id' and optional 'clinic_id' and 'classification'
    """
    if not user_session:
        return False

    role = user_session.get('role')
    clearance = user_session.get('clearance_level')
    user_patient_id = user_session.get('patient_id')

    classification = record.get('classification', 'Restricted')

    # MAC: simple mapping clearance -> allowed max classification
    order = ['Public', 'Internal', 'Confidential', 'Restricted']
    try:
        clearance_idx = order.index(clearance)
        classification_idx = order.index(classification)
    except ValueError:
        return False

    if clearance_idx < classification_idx:
        return False

    # ABAC: patient access
    if role == 'patient':
        # patients can only access their own records
        return user_patient_id is not None and record.get('patient_id') == user_patient_id

    if role in ('doctor', 'pharmacy', 'counter'):
        # doctors can access patients in their clinic if clinic matches — simplified
        if record.get('clinic_id') and user_session.get('clinic_id'):
            return record.get('clinic_id') == user_session.get('clinic_id')
        # doctors: if no clinic specified, allow for example
        return True

    if role in ('admin', 'clinic_manager'):
        # Admins can access more broadly
        return True

    return False


def apply_field_masking(user_session: dict, record: dict) -> dict:
    """Return a copy of record with fields masked according to user's role/clearance."""
    out = record.copy()
    role = user_session.get('role') if user_session else None

    nric_regex = r"^([A-Z])(\d{4})(\d{3}[A-Z])$"
    mask_replacement = r"\1****\3"

    if role == 'patient':
        raw_nric = out.get('nric') or out.get('nric_masked') or ""
        # If the NRIC matches the standard format, apply regex sub
        if re.match(nric_regex, raw_nric):
            out['nric'] = re.sub(nric_regex, mask_replacement, raw_nric)
        else:
            # Fallback for non-standard lengths
            out['nric'] = f"{raw_nric[0]}****{raw_nric[-4:]}" if len(raw_nric) >= 9 else "****"
        return out
    
    if role in ('doctor', 'admin', 'clinic_manager'):
        # doctors/admins see full (doctors shouldn't see staff restricted fields — handled elsewhere)
        return out

    # For pharmacy/counter: mask NRIC and remove notes
    if role in ('pharmacy', 'counter'):
        raw_nric = out.get('nric') or ""
        out['nric'] = re.sub(nric_regex, mask_replacement, raw_nric)
        out.pop('address', None)
        out.pop('notes', None)
        return out
    return out

  



# --- Context helpers ----------------------------------------------------
@app.context_processor
def inject_globals():
    current_user = session.get('user')
    return {'current_user': current_user, 'current_year': datetime.utcnow().year}


# --- Routes --------------------------------------------------------------
@app.route('/')
def index():
    return render_template('public/index.html')


@app.route('/about')
def about():
    return render_template('public/about.html')


@app.route('/contact', methods=['GET', 'POST'])
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
        return jsonify({"success": False, "message": "Email failed to send."}), 500

@app.route('/final_register', methods=['POST'])
def final_register():
    user_otp = request.form.get('otp')
    
    if user_otp != session.get('reg_otp'):
        return jsonify({"success": False, "message": "Invalid verification code"}), 400
    
    data = session.get('temp_reg_data')
    
    try:
        # 1. Create Supabase Auth User
        auth_res = supabase.auth.sign_up({
            "email": data['email'], 
            "password": data['password'],
            "options": {
                "email_confirm": False 
            }
        })
        
        if auth_res.user:
            # 2. Prepare Masked NRIC
            raw_nric = data.get('nric', '')
            
            # 3. Insert into 'profiles' table
            # IMPORTANT: Ensure 'mobile_number' and 'nric_masked' columns are added in Supabase!
            profile_entry = {
               "id": auth_res.user.id,
                "full_name": data.get('fullName'),
                "role": "patient",
                "clearance_level": "Restricted",
                "nric": raw_nric,               # SAVE THE REAL NRIC HERE
                "mobile_number": data.get('phone')
            }
            
            supabase.table("profiles").insert(profile_entry).execute()
            
            session.pop('reg_otp', None)
            session.pop('temp_reg_data', None)
            
            return jsonify({"success": True})
            
    except Exception as e:
        # If DB insert fails, we should ideally delete the auth user so they can try again
        # Note: This requires Service Role Key if using admin methods, 
        # for now, just printing the error for you to see.
        print(f"DEBUG ERROR: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email')
        return render_template('auth/reset-password.html', submitted=True, email=email)
    return render_template('auth/reset-password.html', submitted=False)




@app.route('/patient-dashboard')
def patient_dashboard():
    user_data = session.get('user')
    masked_data = apply_field_masking(user_data, user_data)
    return render_template('patient/patient-dashboard.html', user=masked_data)


@app.route('/doctor-dashboard')
def doctor_dashboard():
    patient_record = supabase.table("profiles").select("*").eq("id", "some_patient_id").single().execute()
    return render_template('doctor/doctor-dashboard.html', patient=patient_record.data)



@app.route('/pharmacy-dashboard')
def pharmacy_dashboard():
    return render_template('pharmacy/pharmacy-dashboard.html')

# --- Admin Routes ---------------------------------------------------------
@app.route('/admin/admin-dashboard')
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


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        try:
            # 1. Sign in with Supabase Auth
            auth_res = supabase.auth.sign_in_with_password({"email": email, "password": password})
            
            if auth_res.user:
                # 2. Get the user's role from the 'profiles' table
                profile_res = (
                    supabase.table("profiles")
                    .select("*")
                    .eq("id", auth_res.user.id)
                    .single()
                    .execute()
                )
                
                if profile_res.data:
                    # 3. Save profile to session for your friend's access control
                    session['user'] = profile_res.data
                    
                    # 4. Redirect based on role
                    role = profile_res.data.get('role')
                    if role == "patient":
                        return redirect(url_for("patient_dashboard"))
                    elif role == "doctor":
                        return redirect(url_for("doctor_dashboard"))
                    # Add other roles as needed...

        except Exception as e:
            print(f"Login failed: {e}")
            flash("Invalid email or password", "error")
            
    # Keep 'auth/' since your login.html is in that folder
    return render_template("auth/login.html")


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=8081)
    

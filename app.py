import os
import re
import secrets
from datetime import datetime
from functools import wraps
from flask_wtf.csrf import CSRFProtect

from flask import (
    Flask, render_template, request, redirect, 
    url_for, session, abort, jsonify, flash
)
from flask_mail import Mail, Message
from supabase import create_client, Client
from dotenv import load_dotenv

from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
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


# --- App + config --------------------------------------------------------
# Load environment variables
load_dotenv()

app = Flask(__name__)
csrf = CSRFProtect(app)
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

# Initialize Supabase
supabase: Client = create_client(
    os.environ.get('SUPABASE_URL'),
    os.environ.get('SUPABASE_PUBLISHABLE_KEY')
)

# Initialize Mail after config is set
mail = Mail(app)

# --- Access Control Helpers ---
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return wrapper

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

@app.context_processor
def inject_globals():
    return {'current_user': session.get('user'), 'current_year': datetime.utcnow().year}

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
            profile_entry = {
                "id": auth_res.user.id,
                "full_name": data.get('fullName'),
                "role": "patient",
                "clearance_level": "Restricted",
                "nric": data.get('nric'),
                "mobile_number": data.get('phone')
            }
            supabase.table("profiles").insert(profile_entry).execute()
            
            session.pop('reg_otp', None)
            session.pop('temp_reg_data', None)
            return jsonify({"success": True})
            
    except Exception as e:
        print(f"SUPABASE ERROR: {str(e)}")
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

@app.route('/patient-dashboard')
@login_required
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

@app.route('/admin-dashboard')
@login_required
def admin_dashboard():
    user = session.get('user')
    if user.get('role') not in ('admin', 'clinic_manager'):
        abort(403)
    return render_template('admin/admin-dashboard.html')

@app.route('/book-appointment')
@login_required
def book_appointment():
    user_data = session.get('user')
    masked_data = apply_field_masking(user_data, user_data)
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

@app.route('/personal-particulars')
@login_required
def personal_particulars():
    user_data = session.get('user')
    # You MUST pass 'profiles' here because your HTML expects it
    return render_template('patient/personal-particulars.html', profile=user_data)

@app.route('/upload-documents')
@login_required
def upload_documents():
    return render_template('patient/upload-documents.html')

@app.route('/billing-payment')
@login_required
def billing_payment():
    return render_template('patient/billing-payment.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=8081)
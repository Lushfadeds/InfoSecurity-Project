import os
import base64
from datetime import datetime
from functools import wraps

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


# --- App + config --------------------------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-change-me')

load_dotenv()

supabase: Client = create_client(
    os.environ.get('SUPABASE_URL'),
    os.environ.get('SUPABASE_PUBLISHABLE_KEY')
)


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

    def mask_nric(nric: str) -> str:
        if not nric or len(nric) < 4:
            return '****'
        return nric[:3] + '****' + nric[-1:]

    # If requester is patient and is the owner, don't mask
    if role == 'patient' and user_session.get('patient_id') == record.get('patient_id'):
        return out

    # For pharmacy/counter: mask NRIC and remove notes
    if role == 'pharmacy':
        if 'nric' in out:
            out['nric'] = mask_nric(out.get('nric'))
        out.pop('notes', None)
        out.pop('address', None)
        return out

    if role == 'counter':
        out.pop('notes', None)
        out.pop('address', None)
        if 'nric' in out:
            out['nric'] = mask_nric(out.get('nric'))
        return out

    if role in ('doctor', 'admin', 'clinic_manager'):
        # doctors/admins see full (doctors shouldn't see staff restricted fields — handled elsewhere)
        return out

    # default: mask sensitive fields
    if 'nric' in out:
        out['nric'] = mask_nric(out.get('nric'))
    out.pop('address', None)
    out.pop('notes', None)
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


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email')
        return render_template('auth/reset-password.html', submitted=True, email=email)
    return render_template('auth/reset-password.html', submitted=False)


@app.route('/patient-dashboard')
def patient_dashboard():
    return render_template('patient/patient-dashboard.html')


@app.route('/doctor-dashboard')
def doctor_dashboard():
    return render_template('doctor/doctor-dashboard.html', response=response)



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


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash("Please enter credentials", "error")
            return render_template("auth/login.html")

        try:
            auth_response = supabase.auth.sign_in_with_password({
                "email": email,
                "password": password
            })
        except Exception:
            flash("Invalid email or password", "error")
            return render_template("auth/login.html")

        user = auth_response.user
        
        profile = (
            supabase
            .table("profiles")
            .select("role")
            .eq("id", user.id)
            .single()
            .execute()
        )

        role = profile.data.get('role') if profile.data else None

        if not role:
            flash("Unauthorized user", "error")
            return render_template("auth/login.html")
        else:
            if role == "patient":
                return redirect(url_for("patient_dashboard"))
            elif role == "doctor":
                return redirect(url_for("doctor_dashboard"))
            elif role == "staff":
                return redirect(url_for("staff_dashboard"))
            elif role == "admin":
                return redirect(url_for("admin_dashboard"))

        flash("Unauthorized role", "error")
        return render_template("auth/login.html")

    return render_template("auth/login.html")


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=8080)
    

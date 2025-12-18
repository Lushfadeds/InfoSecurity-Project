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
)
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
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Field encryption key (must be 32 url-safe base64 bytes). Provide via env var
encrypt_key = os.environ.get('APP_ENCRYPT_KEY')
if not encrypt_key:
    # For dev only: generate and show a warning. Fernet.generate_key() already
    # returns a URL-safe base64-encoded 32-byte key, so don't re-encode it.
    print('WARNING: APP_ENCRYPT_KEY not set — generating temporary key (do not use in production)')
    generated = Fernet.generate_key()  # returns bytes
    encrypt_key = generated.decode()
    print(f'Generated temporary APP_ENCRYPT_KEY: {encrypt_key}')

fernet = Fernet(encrypt_key.encode())

db = SQLAlchemy(app)


# --- Models --------------------------------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(32), nullable=False, default='patient')
    clearance_level = db.Column(db.String(32), nullable=False, default='Restricted')
    is_active = db.Column(db.Boolean, default=True)
    # optional links
    clinic_id = db.Column(db.Integer, nullable=True)

    def set_password(self, password: str):
        # use PBKDF2-SHA256 to avoid native bcrypt dependency issues on some systems
        self.password_hash = pbkdf2_sha256.hash(password)

    def verify_password(self, password: str) -> bool:
        try:
            return pbkdf2_sha256.verify(password, self.password_hash)
        except Exception:
            return False

    @property
    def patient_id(self):
        # convenience property to return linked patient_profile id if present
        try:
            return self.patient_profile.id if self.patient_profile else None
        except Exception:
            return None


class PatientProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True)
    # Encrypted fields stored as base64 text
    nric_encrypted = db.Column(db.Text, nullable=True)
    address_encrypted = db.Column(db.Text, nullable=True)
    dob_encrypted = db.Column(db.Text, nullable=True)
    phone_encrypted = db.Column(db.Text, nullable=True)
    gender = db.Column(db.String(16), nullable=True)
    # envelope encrypted DEK (ciphertext blob base64) used to decrypt the fields
    dek_encrypted = db.Column(db.Text, nullable=True)

    user = db.relationship('User', backref=db.backref('patient_profile', uselist=False))


class StaffProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True)
    full_name = db.Column(db.String(255))
    nric_encrypted = db.Column(db.Text, nullable=True)
    address_encrypted = db.Column(db.Text, nullable=True)
    dob_encrypted = db.Column(db.Text, nullable=True)
    phone_encrypted = db.Column(db.Text, nullable=True)
    gender = db.Column(db.String(16), nullable=True)
    job_title = db.Column(db.String(64), nullable=True)
    department = db.Column(db.String(64), nullable=True)
    staff_id = db.Column(db.String(64), nullable=True)
    professional_reg_no = db.Column(db.String(128), nullable=True)
    employment_start = db.Column(db.Date, nullable=True)
    employment_status = db.Column(db.String(32), nullable=True)

    dek_encrypted = db.Column(db.Text, nullable=True)

    user = db.relationship('User', backref=db.backref('staff_profile', uselist=False))


# --- Encryption helpers --------------------------------------------------
def encrypt_field(value: str) -> str:
    # Deprecated: kept for compatibility. Prefer envelope_encrypt_value(profile, field_name, value)
    if value is None:
        return None
    if isinstance(value, str):
        value = value.encode()
    token = fernet.encrypt(value)
    return base64.b64encode(token).decode()


def decrypt_field(value: str) -> str:
    # Deprecated: kept for compatibility. Prefer envelope_decrypt_value(profile, field_name, requester_session)
    if not value:
        return None
    try:
        token = base64.b64decode(value)
        data = fernet.decrypt(token)
        return data.decode()
    except Exception:
        return None


# --- Envelope encryption + KMS helpers ----------------------------------
KMS_KEY_ID = os.environ.get('AWS_KMS_KEY_ID')
APP_KEK = os.environ.get('APP_KEK')  # dev fallback (base64 key) if KMS not available


def get_kms_client():
    if not boto3:
        return None
    return boto3.client('kms')


def generate_data_key():
    """Generate a DEK.

    If AWS KMS key id is configured, use GenerateDataKey to get plaintext DEK and encrypted DEK.
    Otherwise fall back to a locally generated random DEK and wrap it with APP_KEK (dev only).
    Returns (dek_plain_bytes, dek_encrypted_base64)
    """
    if KMS_KEY_ID and boto3:
        kms = get_kms_client()
        try:
            resp = kms.generate_data_key(KeyId=KMS_KEY_ID, KeySpec='AES_256')
            plaintext = resp['Plaintext']  # bytes
            ciphertext = resp['CiphertextBlob']  # bytes
            return plaintext, _b64.b64encode(ciphertext).decode()
        except (BotoCoreError, ClientError) as e:
            print('KMS generate_data_key failed:', e)
            # fall through to local generation

    # Local fallback: generate random 32-byte DEK and encrypt with APP_KEK (Fernet) if provided
    dek = secrets.token_bytes(32)
    if APP_KEK:
        try:
            k = Fernet(APP_KEK.encode())
            wrapped = k.encrypt(dek)
            return dek, _b64.b64encode(wrapped).decode()
        except Exception:
            pass

    # Last resort: return dek and store it unencrypted (NOT for production)
    print('WARNING: DEK generated and NOT KEK-wrapped; set AWS_KMS_KEY_ID or APP_KEK in production')
    return dek, _b64.b64encode(dek).decode()


def decrypt_data_key(dek_encrypted_b64: str):
    """Given encrypted DEK (base64), return plaintext dek bytes.

    If KMS is configured, call KMS.decrypt with CiphertextBlob.
    Otherwise attempt to unwrap with APP_KEK (Fernet) or assume stored plaintext (dev).
    """
    if not dek_encrypted_b64:
        return None
    blob = _b64.b64decode(dek_encrypted_b64)
    if KMS_KEY_ID and boto3:
        kms = get_kms_client()
        try:
            resp = kms.decrypt(CiphertextBlob=blob)
            return resp['Plaintext']
        except (BotoCoreError, ClientError) as e:
            print('KMS decrypt failed:', e)
            return None

    if APP_KEK:
        try:
            k = Fernet(APP_KEK.encode())
            return k.decrypt(blob)
        except Exception:
            pass

    # fallback: assume blob is plaintext dek
    return blob


def aesgcm_encrypt(raw_bytes: bytes, dek: bytes) -> str:
    # AESGCM expects 12-byte nonce
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(dek)
    ct = aesgcm.encrypt(nonce, raw_bytes, None)
    out = nonce + ct
    return _b64.b64encode(out).decode()


def aesgcm_decrypt(b64_cipher: str, dek: bytes):
    try:
        blob = _b64.b64decode(b64_cipher)
        nonce = blob[:12]
        ct = blob[12:]
        aesgcm = AESGCM(dek)
        pt = aesgcm.decrypt(nonce, ct, None)
        return pt.decode()
    except Exception:
        return None


# convenience wrapper to encrypt a value for a profile (creates DEK if missing)
def envelope_encrypt_profile_fields(profile, fields: dict):
    """Encrypt fields (mapping field_name->plaintext string) onto the profile object.

    The profile object must have attribute `dek_encrypted` to hold the wrapped DEK.
    This stores encrypted ciphertext strings into corresponding `<field>_encrypted` columns.
    """
    if not profile:
        return
    # ensure DEK exists
    dek_plain = None
    if not getattr(profile, 'dek_encrypted', None):
        dek_plain, dek_enc = generate_data_key()
        profile.dek_encrypted = dek_enc
    else:
        dek_plain = decrypt_data_key(profile.dek_encrypted)

    if dek_plain is None:
        raise RuntimeError('Unable to obtain plaintext DEK for profile')

    for fname, val in fields.items():
        if val is None:
            setattr(profile, f"{fname}_encrypted", None)
            continue
        if isinstance(val, str):
            raw = val.encode()
        else:
            raw = val
        cipher_b64 = aesgcm_encrypt(raw, dek_plain)
        setattr(profile, f"{fname}_encrypted", cipher_b64)


def envelope_decrypt_profile_field(profile, field_name: str, requester_session: dict = None):
    """JIT decrypt a single field from profile after authorization checks.

    requester_session is used to run MAC/ABAC before decryption. If provided and
    access is denied, returns masked or None.
    """
    # check access at record-level if requester_session provided
    if requester_session is not None:
        record = {'patient_id': getattr(profile, 'id', None), 'clinic_id': getattr(profile, 'clinic_id', None), 'classification': 'Restricted'}
        if not can_access_record(requester_session, record):
            # return masked value or None per policy
            if field_name == 'nric':
                return '***MASKED***'
            return None

    cipher = getattr(profile, f"{field_name}_encrypted", None)
    if not cipher:
        return None
    dek_plain = decrypt_data_key(profile.dek_encrypted)
    if not dek_plain:
        return None
    return aesgcm_decrypt(cipher, dek_plain)



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
    # public landing page
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
@login_required
def doctor_dashboard():
    user = session.get('user')
    if user.get('role') != 'doctor':
        abort(403)
    return render_template('doctor/doctor-dashboard.html')


@app.route('/staff-dashboard')
@login_required
def staff_dashboard():
    user = session.get('user')
    if user.get('role') not in ('counter', 'staff'):
        abort(403)
    return render_template('staff/staff-dashboard.html')


@app.route('/pharmacy-dashboard')
@login_required
def pharmacy_dashboard():
    user = session.get('user')
    if user.get('role') != 'pharmacy':
        abort(403)
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
    # unified login for patients and staff
    if request.method == 'POST':
        # Determine whether this is a login or signup submission
        form_type = request.form.get('form_type') or request.form.get('action') or 'login'

        if form_type == 'signup':
            # Only allow patient self-registration
            email = request.form.get('email')
            password = request.form.get('password')
            if not email or not password:
                return render_template('auth/login.html', submitted=False, signup_error='Email and password are required')

            if User.query.filter_by(email=email).first():
                return render_template('auth/login.html', submitted=False, signup_error='Email already registered')

            u = User(email=email, role='patient', clearance_level='Restricted')
            u.set_password(password)

            # optional profile fields
            nric = request.form.get('nric') or None
            address = request.form.get('address') or None
            dob = request.form.get('dob') or None
            phone = request.form.get('phone') or None
            gender = request.form.get('gender') or None

            p = PatientProfile(user=u, gender=gender)
            envelope_encrypt_profile_fields(p, {
                'nric': nric,
                'address': address,
                'dob': dob,
                'phone': phone,
            })

            db.session.add(u)
            db.session.add(p)
            db.session.commit()

            # Auto-login the newly created patient
            payload = {
                'user_id': u.id,
                'role': u.role,
                'clearance_level': u.clearance_level,
                'patient_id': u.patient_id,
                'clinic_id': u.clinic_id,
            }
            session['user'] = payload
            return redirect(url_for('portal_patient'))

        # Default: handle login
        email = request.form.get('username') or request.form.get('email')
        password = request.form.get('password')
        if not email or not password:
            return render_template('auth/login.html', submitted=False, error='Missing credentials')

        user = User.query.filter_by(email=email).first()
        if not user or not user.verify_password(password) or not user.is_active:
            return render_template('auth/login.html', submitted=False, error='Invalid credentials')

        # Build session payload (like a JWT body)
        payload = {
            'user_id': user.id,
            'role': user.role,
            'clearance_level': user.clearance_level,
            'patient_id': user.patient_id,
            'clinic_id': user.clinic_id,
        }
        session['user'] = payload

        # Redirect based on role
        if user.role == 'patient':
            return redirect(url_for('portal_patient'))
        if user.role in ('doctor', 'pharmacy', 'counter'):
            return redirect(url_for('portal_staff'))
        if user.role in ('admin', 'clinic_manager'):
            return redirect(url_for('portal_admin'))

        return redirect(url_for('index'))

    return render_template('auth/login.html', submitted=False)


# Signup is handled inside the `/login` route as a modal; standalone signup
# route removed to restrict self-registration to patients only.


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))


@app.route('/portal/patient')
@login_required
def portal_patient():
    user = session.get('user')
    if user.get('role') != 'patient':
        abort(403)
    # pull patient's profile and decrypt fields for display
    profile = None
    if user.get('patient_id'):
        p = PatientProfile.query.get(user.get('patient_id'))
        if p:
            profile = {
                'nric': envelope_decrypt_profile_field(p, 'nric', user),
                'address': envelope_decrypt_profile_field(p, 'address', user),
                'dob': envelope_decrypt_profile_field(p, 'dob', user),
                'phone': envelope_decrypt_profile_field(p, 'phone', user),
                'gender': p.gender,
            }
    return render_template('portal_patient.html', profile=profile)


@app.route('/portal/staff')
@login_required
def portal_staff():
    user = session.get('user')
    if user.get('role') not in ('doctor', 'pharmacy', 'counter'):
        abort(403)
    return render_template('portal_staff.html', user=user)


@app.route('/portal/admin')
@login_required
@role_required('admin', 'clinic_manager')
def portal_admin():
    user = session.get('user')
    return render_template('portal_admin.html', user=user)


@app.route('/profile')
@login_required
def profile():
    # Show profile information for the currently authenticated user
    u = session.get('user')
    if not u:
        abort(403)

    profile_data = None
    # If patient, show decrypted patient profile
    if u.get('role') == 'patient' and u.get('patient_id'):
        p = PatientProfile.query.get(u.get('patient_id'))
        if p:
            profile_data = {
                'type': 'patient',
                'nric': envelope_decrypt_profile_field(p, 'nric', u),
                'address': envelope_decrypt_profile_field(p, 'address', u),
                'dob': envelope_decrypt_profile_field(p, 'dob', u),
                'phone': envelope_decrypt_profile_field(p, 'phone', u),
                'gender': p.gender,
            }
    else:
        # try to load staff profile by the session user id
        # session stores user_id; find staff profile by user_id
        staff = StaffProfile.query.filter_by(user_id=u.get('user_id')).first()
        if staff:
            profile_data = {
                'type': 'staff',
                'full_name': staff.full_name,
                'job_title': staff.job_title,
                'department': staff.department,
                'phone': envelope_decrypt_profile_field(staff, 'phone', u),
            }

    return render_template('profile.html', profile=profile_data)


# --- Utility: small init helper to create DB and demo users ----------------
def init_db(with_demo=True):
    db.create_all()
    if not with_demo:
        return

    if User.query.count() == 0:
        # create demo users (password = 'password')
        u1 = User(email='patient@example.org', role='patient', clearance_level='Restricted')
        u1.set_password('password')
        p1 = PatientProfile(user=u1)
        envelope_encrypt_profile_fields(p1, {
            'nric': 'S1234567A',
            'address': '1 Demo Street, Singapore',
            'dob': '1990-01-01',
            'phone': '+65-81234567',
        })

        u2 = User(email='doctor@example.org', role='doctor', clearance_level='Confidential', clinic_id=1)
        u2.set_password('password')
        s2 = StaffProfile(user=u2, full_name='Dr Example')
        envelope_encrypt_profile_fields(s2, {
            'nric': 'S9876543B',
            'address': '2 Clinic Road',
            'dob': '1980-02-02',
        })

        admin = User(email='admin@example.org', role='admin', clearance_level='Restricted')
        admin.set_password('password')

        db.session.add_all([u1, p1, u2, s2, admin])
        db.session.commit()
        print('Demo users created: patient@example.org, doctor@example.org, admin@example.org (password: password)')


if __name__ == '__main__':
    # Create DB and demo records if missing inside the application context
    with app.app_context():
        init_db(with_demo=True)

    app.run(debug=True)
    

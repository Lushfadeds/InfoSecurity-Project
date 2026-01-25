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


@app.route('/patient/book-appointment', methods=['GET', 'POST'])
def book_appointment():
    if request.method == 'POST':
        # Handle booking submission
        flash('Appointment booked successfully!', 'success')
        return render_template('patient/book-appointment.html', booking_success=True, doctors=[])
    
    # Mock doctors data
    doctors = [
        {'id': 1, 'name': 'Dr. Sarah Tan', 'specialty': 'General Practice', 'experience': '15 years experience', 'availability': 'Mon-Fri'},
        {'id': 2, 'name': 'Dr. James Wong', 'specialty': 'Cardiology', 'experience': '20 years experience', 'availability': 'Mon, Wed, Fri'},
        {'id': 3, 'name': 'Dr. Michelle Lee', 'specialty': 'Dermatology', 'experience': '10 years experience', 'availability': 'Tue, Thu'},
    ]
    return render_template('patient/book-appointment.html', doctors=doctors)


@app.route('/patient/appointments')
def appointment_history():
    # Mock appointments data
    appointments = [
        {'id': 1, 'token_id': 'APT-****-1210', 'date': '2024-12-10', 'time': '10:00 AM', 'doctor': 'Dr. Sarah Tan', 'specialty': 'General Practice', 'visit_type': 'General Consultation', 'status': 'Completed', 'notes': 'Follow up in 2 weeks if symptoms persist.', 'documents': ['Lab-Results.pdf']},
        {'id': 2, 'token_id': 'APT-****-1215', 'date': '2024-12-15', 'time': '2:30 PM', 'doctor': 'Dr. James Wong', 'specialty': 'Cardiology', 'visit_type': 'Follow-up', 'status': 'Upcoming', 'notes': None, 'documents': []},
    ]
    return render_template('patient/appointment-history.html', appointments=appointments)


@app.route('/patient/prescriptions')
def prescriptions():
    # Mock prescriptions data
    prescriptions = [
        {
            'id': 1, 'token_id': 'RX-****-1122', 'date': '2024-11-22', 'doctor': 'Dr. James Wong', 
            'status': 'Active', 'valid_until': '2025-05-22', 'refills_available': True,
            'medications': [
                {'name': 'Amlodipine 5mg', 'dosage': '1 tablet', 'frequency': 'Once daily', 'duration': '30 days', 'refills_remaining': 2},
                {'name': 'Atorvastatin 20mg', 'dosage': '1 tablet', 'frequency': 'Once daily at night', 'duration': '30 days', 'refills_remaining': 2},
            ]
        },
        {
            'id': 2, 'token_id': 'RX-****-0915', 'date': '2024-09-15', 'doctor': 'Dr. Sarah Tan',
            'status': 'Expired', 'valid_until': '2024-12-15', 'refills_available': False,
            'medications': [
                {'name': 'Amoxicillin 500mg', 'dosage': '1 capsule', 'frequency': 'Three times daily', 'duration': '7 days', 'refills_remaining': 0},
            ]
        },
    ]
    return render_template('patient/prescriptions.html', prescriptions=prescriptions)


@app.route('/patient/prescriptions/download/<int:id>')
def download_prescription(id):
    # TODO: Generate and return prescription PDF
    flash('Prescription downloaded', 'success')
    return redirect(url_for('prescriptions'))


@app.route('/patient/request-refill', methods=['GET', 'POST'])
def request_refill():
    rx_id = request.args.get('rx', 1)
    
    # Mock prescription data
    prescription = {
        'id': rx_id, 'doctor': 'Dr. James Wong', 'valid_until': '2025-05-22',
        'medications': [
            {'name': 'Amlodipine 5mg', 'dosage': '1 tablet', 'frequency': 'Once daily', 'duration': '30 days', 'refills_remaining': 2},
            {'name': 'Atorvastatin 20mg', 'dosage': '1 tablet', 'frequency': 'Once daily at night', 'duration': '30 days', 'refills_remaining': 2},
        ]
    }
    
    if request.method == 'POST':
        delivery_method = 'Pickup' if request.form.get('delivery_method') == 'pickup' else 'Home Delivery'
        request_id = f'REF-{datetime.now().strftime("%Y%m%d%H%M%S")}'
        return render_template('patient/request-refill.html', prescription=prescription, refill_success=True, 
                               delivery_method=delivery_method, request_id=request_id)
    
    return render_template('patient/request-refill.html', prescription=prescription)


@app.route('/patient/medical-certificates')
def medical_certificates():
    # Mock MC data
    certificates = [
        {'id': 1, 'token_id': 'MC-****-1210', 'issue_date': '2024-12-10', 'doctor': 'Dr. Sarah Tan', 'condition': 'Acute Upper Respiratory Tract Infection', 'duration': '2 days', 'start_date': '2024-12-10', 'end_date': '2024-12-11', 'status': 'Issued', 'verification_code': 'MC-PINK-1210-4567'},
        {'id': 2, 'token_id': 'MC-****-0915', 'issue_date': '2024-09-15', 'doctor': 'Dr. Sarah Tan', 'condition': 'Acute Gastroenteritis', 'duration': '1 day', 'start_date': '2024-09-15', 'end_date': '2024-09-15', 'status': 'Issued', 'verification_code': 'MC-PINK-0915-2341'},
    ]
    return render_template('patient/medical-certificates.html', certificates=certificates, patient_name='John Doe', nric_masked='S****567A')


@app.route('/patient/medical-certificates/download/<int:id>')
def download_mc(id):
    # TODO: Generate and return MC PDF
    flash('Medical Certificate downloaded', 'success')
    return redirect(url_for('medical_certificates'))


@app.route('/patient/billing')
def billing_payment():
    # Mock invoices data
    invoices = [
        {
            'id': 'INV-2024-1234', 'token_id': 'INV-****-1234', 'date': '2024-12-10', 'description': 'General Consultation',
            'items': [{'name': 'Consultation Fee', 'amount': 50.00}, {'name': 'Medications', 'amount': 35.00}, {'name': 'Medical Certificate', 'amount': 15.00}],
            'subtotal': 100.00, 'gst': 9.00, 'total': 109.00, 'status': 'Pending', 'paid_date': None
        },
        {
            'id': 'INV-2024-1122', 'token_id': 'INV-****-1122', 'date': '2024-11-22', 'description': 'Cardiology Consultation',
            'items': [{'name': 'Specialist Consultation', 'amount': 120.00}, {'name': 'ECG Test', 'amount': 80.00}, {'name': 'Medications', 'amount': 65.00}],
            'subtotal': 265.00, 'gst': 23.85, 'total': 288.85, 'status': 'Paid', 'paid_date': '2024-11-22'
        },
    ]
    return render_template('patient/billing-payment.html', invoices=invoices)


@app.route('/patient/billing/download/<id>')
def download_invoice(id):
    # TODO: Generate and return invoice/receipt PDF
    flash('Invoice downloaded', 'success')
    return redirect(url_for('billing_payment'))


@app.route('/patient/make-payment', methods=['GET', 'POST'])
def make_payment():
    invoice_id = request.args.get('invoice', 'INV-2024-1234')
    
    # Mock invoice data
    invoice = {
        'id': invoice_id, 'date': '2024-12-10', 'description': 'General Consultation',
        'items': [{'name': 'Consultation Fee', 'amount': 50.00}, {'name': 'Medications', 'amount': 35.00}, {'name': 'Medical Certificate', 'amount': 15.00}],
        'subtotal': 100.00, 'gst': 9.00, 'total': 109.00
    }
    
    if request.method == 'POST':
        transaction_id = f'TXN-{datetime.now().strftime("%Y%m%d%H%M%S")}'
        return render_template('patient/make-payment.html', invoice=invoice, payment_success=True, transaction_id=transaction_id)
    
    return render_template('patient/make-payment.html', invoice=invoice)


@app.route('/patient/billing/receipt/<id>')
def download_receipt(id):
    # TODO: Generate and return receipt PDF
    flash('Receipt downloaded', 'success')
    return redirect(url_for('billing_payment'))


@app.route('/patient/profile', methods=['GET', 'POST'])
def personal_particulars():
    # Mock profile data
    profile = {
        'full_name': 'John Doe', 'nric': 'S1234567A', 'nric_masked': 'S****567A',
        'dob': '1990-05-15', 'gender': 'Male', 'nationality': 'Singaporean', 'blood_type': 'O+',
        'phone': '+65 9123 4567', 'phone_masked': '+65 91** ****',
        'email': 'john.doe@email.com', 'email_masked': 'j***@email.com',
        'address': '123 Orchard Road #12-34, Singapore 238888', 'address_masked': '123 O****** Road #**-**, Singapore ******',
        'postal_code': '238888',
        'emergency_name': 'Jane Doe', 'emergency_relationship': 'Spouse', 'emergency_phone': '+65 9876 5432'
    }
    
    if request.method == 'POST':
        # Handle profile update
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('personal_particulars'))
    
    return render_template('patient/personal-particulars.html', profile=profile)


@app.route('/patient/upload', methods=['GET', 'POST'])
def upload_documents():
    # Mock documents data
    documents = [
        {'id': 1, 'name': 'Lab-Results-Blood-Test.pdf', 'upload_date': '2024-12-05', 'size': '245 KB'},
        {'id': 2, 'name': 'Referral-Letter-Specialist.pdf', 'upload_date': '2024-11-20', 'size': '189 KB'},
    ]
    
    if request.method == 'POST':
        # Handle file upload
        flash('Documents uploaded successfully!', 'success')
        return redirect(url_for('upload_documents'))
    
    return render_template('patient/upload-documents.html', documents=documents)


@app.route('/patient/documents/download/<int:id>')
def download_document(id):
    # TODO: Return actual file download
    flash('Document downloaded', 'success')
    return redirect(url_for('upload_documents'))


@app.route('/patient/documents/delete/<int:id>', methods=['POST'])
def delete_document(id):
    # TODO: Delete document
    flash('Document deleted', 'success')
    return redirect(url_for('upload_documents'))


@app.route('/doctor-dashboard')
def doctor_dashboard():
    return render_template('doctor/doctor-dashboard.html')



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
    app.run(debug=True, port=8081)
    

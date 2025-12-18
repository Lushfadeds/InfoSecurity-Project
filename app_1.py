# Just to test out routing

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


# --- App + config --------------------------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-change-me')


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


#@app.route('/reset-password', methods=['GET', 'POST'])
#def reset_password():
#    if request.method == 'POST':
#        email = request.form.get('email')
#        return render_template('auth/reset-password.html', submitted=True, email=email)
#    return render_template('auth/reset-password.html', submitted=False)


@app.route('/patient-dashboard')
def patient_dashboard():
    return render_template('patient/patient-dashboard.html')


@app.route('/doctor-dashboard')
def doctor_dashboard():
    return render_template('doctor/doctor-dashboard.html')


@app.route('/staff-dashboard')
def staff_dashboard():
    return render_template('staff/staff-dashboard.html')


@app.route('/pharmacy-dashboard')
def pharmacy_dashboard():
    return render_template('pharmacy/pharmacy-dashboard.html')


@app.route('/admin-dashboard')
def admin_dashboard():
    return render_template('admin/admin-dashboard.html')


#@app.route('/login', methods=['GET', 'POST'])
#def login():
#    # unified login for patients and staff
#    if request.method == 'POST':
#        # Determine whether this is a login or signup submission
#        form_type = request.form.get('form_type') or request.form.get('action') or 'login'
#
#        if form_type == 'signup':
#            # Only allow patient self-registration
#            email = request.form.get('email')
#            password = request.form.get('password')
#            if not email or not password:
#                return render_template('auth/login.html', submitted=False, signup_error='Email and password are required')
#
#            if User.query.filter_by(email=email).first():
#                return render_template('auth/login.html', submitted=False, signup_error='Email already registered')
#
#            u = User(email=email, role='patient', clearance_level='Restricted')
#            u.set_password(password)
#
#            # optional profile fields
#            nric = request.form.get('nric') or None
#            address = request.form.get('address') or None
#            dob = request.form.get('dob') or None
#            phone = request.form.get('phone') or None
#            gender = request.form.get('gender') or None
#
#            p = PatientProfile(user=u, gender=gender)
#            envelope_encrypt_profile_fields(p, {
#                'nric': nric,
#                'address': address,
#                'dob': dob,
#                'phone': phone,
#            })
#
#            db.session.add(u)
#            db.session.add(p)
#            db.session.commit()
#
#            # Auto-login the newly created patient
#            payload = {
#                'user_id': u.id,
#                'role': u.role,
#                'clearance_level': u.clearance_level,
#                'patient_id': u.patient_id,
#                'clinic_id': u.clinic_id,
#            }
#            session['user'] = payload
#            return redirect(url_for('portal_patient'))
#
#        # Default: handle login
#        email = request.form.get('username') or request.form.get('email')
#        password = request.form.get('password')
#        if not email or not password:
#            return render_template('auth/login.html', submitted=False, error='Missing credentials')
#
#        user = User.query.filter_by(email=email).first()
#        if not user or not user.verify_password(password) or not user.is_active:
#            return render_template('auth/login.html', submitted=False, error='Invalid credentials')
#
#        # Build session payload (like a JWT body)
#        payload = {
#            'user_id': user.id,
#            'role': user.role,
#            'clearance_level': user.clearance_level,
#            'patient_id': user.patient_id,
#            'clinic_id': user.clinic_id,
#        }
#        session['user'] = payload
#
#        # Redirect based on role
#        if user.role == 'patient':
#            return redirect(url_for('portal_patient'))
#        if user.role in ('doctor', 'pharmacy', 'counter'):
#            return redirect(url_for('portal_staff'))
#        if user.role in ('admin', 'clinic_manager'):
#            return redirect(url_for('portal_admin'))
#
#        return redirect(url_for('index'))
#
    return render_template('auth/login.html', submitted=False)


# Signup is handled inside the `/login` route as a modal; standalone signup
# route removed to restrict self-registration to patients only.


#@app.route('/logout')
#def logout():
#    session.pop('user', None)
#    return redirect(url_for('index'))



if __name__ == '__main__':
    # Create DB and demo records if missing inside the application context
    #with app.app_context():
    #    init_db(with_demo=True)
    app.run(debug=True)
    

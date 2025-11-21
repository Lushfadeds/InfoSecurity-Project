from flask import Flask, render_template, request
from datetime import datetime
import subprocess
import shutil
import os

app = Flask(__name__)


@app.context_processor
def inject_current_year():
    """Provide current_year to all templates to avoid relying on a non-existent 'date' filter."""
    return {"current_year": datetime.utcnow().year}


@app.route('/')
def index():
    # The index page includes a React root that will be filled by the built bundle
    return render_template('index.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')
        # In a real app you'd store/send the message. For this template we just show a thank-you.
        return render_template('contact.html', submitted=True, name=name)
    return render_template('contact.html', submitted=False)


@app.route('/login', methods=['GET', 'POST'])
def login():
    # Basic login page (no auth implemented) — shows a form and can host React widget
    if request.method == 'POST':
        username = request.form.get('username')
        return render_template('login.html', submitted=True, username=username)
    return render_template('login.html', submitted=False)


@app.route('/dashboard')
def dashboard():
    # Main application dashboard — shows the React widget and server-rendered summary
    return render_template('dashboard.html')


@app.route('/patients')
def patients():
    # Patients list page (static example)
    sample_patients = [
        {'id': 1, 'name': 'Alice Smith', 'status': 'Checked-in'},
        {'id': 2, 'name': 'Bob Johnson', 'status': 'In treatment'},
        {'id': 3, 'name': 'Carlos Diaz', 'status': 'Discharged'}
    ]
    return render_template('patients.html', patients=sample_patients)


@app.route('/profile')
def profile():
    # Example profile page — in a full app this would be user-specific
    example_profile = {
        'name': 'Dr. Jane Doe',
        'role': 'Attending Physician',
        'email': 'jane.doe@example.org'
    }
    return render_template('profile.html', profile=example_profile)


def build_frontend():
    """Run `npm run build` in the `frontend` folder (if npm is available).

    This attempts to build the React frontend into `static/react`. If Node/npm are not
    installed or the frontend directory is missing, it prints helpful messages and continues.
    """
    repo_root = os.path.dirname(os.path.abspath(__file__))
    frontend_dir = os.path.join(repo_root, 'frontend')
    # Allow skipping via env var
    if os.environ.get('SKIP_FRONTEND_BUILD'):
        print('SKIP_FRONTEND_BUILD set — skipping frontend build')
        return

    if not os.path.isdir(frontend_dir):
        print('No `frontend` directory found — skipping frontend build')
        return

    npm_path = shutil.which('npm')
    if not npm_path:
        print('`npm` not found on PATH — please install Node.js and npm to build the frontend')
        return

    try:
        print('Running `npm install` in frontend (if needed) — this may take a moment')
        subprocess.run([npm_path, 'install'], cwd=frontend_dir, check=True)
    except subprocess.CalledProcessError as e:
        print('`npm install` failed:', e)
        return

    try:
        print('Building frontend with `npm run build`...')
        # Use npm run build with prefix to ensure script runs in the frontend folder
        subprocess.run([npm_path, 'run', 'build', '--prefix', frontend_dir], check=True)
        print('Frontend build finished — static files written to `static/react`')
    except subprocess.CalledProcessError as e:
        print('Frontend build failed:', e)


if __name__ == '__main__':
    # Build frontend before launching Flask (optional — can be skipped by env var)
    try:
        build_frontend()
    except Exception as exc:
        print('Error when trying to build frontend:', exc)

    app.run(debug=True)

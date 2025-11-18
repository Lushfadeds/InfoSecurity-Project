## Flask template

This repository includes a minimal Flask template to get you started quickly.

Files included:

- `app.py` — minimal Flask application entrypoint
- `templates/` — Jinja2 templates (`base.html`, `index.html`)
- `static/style.css` — simple stylesheet
- `requirements.txt` — dependencies

Quick start (Windows PowerShell):

```powershell
python -m venv venv
# Activate the virtualenv (PowerShell)
venv\Scripts\Activate.ps1
# If execution policy blocks running the script, you can either open PowerShell as Administrator and run:
#   Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
# or use CMD activation instead:
#   venv\Scripts\activate
pip install -r requirements.txt
# Run the app
$env:FLASK_APP = "app.py"
python -m flask run
```

Open http://127.0.0.1:5000 in your browser.

Notes:
- For CMD use `venv\Scripts\activate` to activate the venv.
- To enable debug auto-reload, set `$env:FLASK_ENV = "development"` in PowerShell before running.

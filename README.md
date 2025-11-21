glenden is here
    
    
                             _,,aaaaa,,_
                          _,dP"''    `""""Ya,_
                       ,aP"'                `"Yb,_
                     ,8"'                       `"8a,
                   ,8"                             `"8,_
                 ,8"                                  "Yb,
               ,8"                                      `8,
              dP'                                        8I
            ,8"                           bg,_          ,P'
           ,8'                              "Y8"Ya,,,,ad"
          ,d"                            a,_ I8   `"""'
         ,8'                              ""888
         dP     __                           `Yb,
        dP'  _,d8P::::Y8b,                     `Ya
   ,adba8',d88P::;;::;;;:"b:::Ya,_               Ya
  dP":::"Y88P:;P"""YP"""Yb;::::::"Ya,             "Y,
  8:::::::Yb;d" _  "_    dI:::::::::"Yb,__,,gd88ba,db
  Yb:::::::"8(,8P _d8   d8:::::::::::::Y88P"::::::Y8I
  `Yb;:::::::""::"":b,,dP::::::::::::::::::;aaa;:::8(
    `Y8a;:::::::::::::::::::::;;::::::::::8P""Y8)::8I
      8b"ba::::::::::::::::;adP:::::::::::":::dP::;8'
      `8b;::::::::::::;aad888P::::::::::::::;dP::;8'
       `8b;::::::::""""88"  d::::::::::b;:::::;;dP'
         "Yb;::::::::::Y8bad::::::::::;"8Paaa""'
           `"Y8a;;;:::::::::::::;;aadP""
               ``""Y88bbbdddd88P""8b,
                        _,d8"::::::"8b,
                      ,dP8"::::::;;:::"b,
                    ,dP"8:::::::Yb;::::"b,
                  ,8P:dP:::::::::Yb;::::"b,
               _,dP:;8":::::::::::Yb;::::"b
     ,aaaaaa,,d8P:::8":::::::::::;dP:::::;8
  ,ad":;;:::::"::::8"::::::::::;dP::::::;dI
 dP";adP":::::;:;dP;::::aaaad88"::::::adP:8b,___
d8:::8;;;aadP"::8'Y8:d8P"::::::::::;dP";d"'`Yb:"b
8I:::;""":::::;dP I8P"::::::::::;a8"a8P"     "b:P
Yb::::"8baa8"""'  8;:;d"::::::::d8P"'         8"
 "YbaaP::8;P      `8;d::;a::;;;;dP           ,8
    `"Y8P"'         Yb;;d::;aadP"           ,d'
                     "YP:::"P'             ,d'
                       "8bdP'    _        ,8'
      Normand         ,8"`""Yba,d"      ,d"
      Veilleux       ,P'     d"8'     ,d"
                    ,8'     d'8'     ,P'
                    (b      8 I      8,
                     Y,     Y,Y,     `b,
               ____   "8,__ `Y,Y,     `Y""b,
           ,adP""""b8P""""""""Ybdb,        Y,
         ,dP"    ,dP'            `""       `8
        ,8"     ,P'                        ,P
        8'      8)                        ,8'
        8,      Yb                      ,aP'
        `Ya      Yb                  ,ad"'
          "Ya,___ "Ya             ,ad"'
            ``""""""`Yba,,,,,,,adP"'
                       `"""""""'## Flask template

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
                       `"""""""'
                       HELLO, I am a blue person

Running with the React frontend
 - This project contains a small React frontend in the `frontend/` folder. When you run `python app.py` the Flask entrypoint will attempt to run `npm install` and `npm run build` in that folder, writing the built files into `static/react`.

Quick run (PowerShell):

```powershell
# Activate your venv first

pip install -r requirements.txt
cd InfoSecurity-Project
python app.py
```

Notes:
- Make sure Node.js and npm are installed and available on PATH so the build step can run.
- If you want to skip the frontend build (for example if you already built it), set the environment variable `SKIP_FRONTEND_BUILD=1` before running `python app.py`.

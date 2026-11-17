PHISHGUARD PROFESSIONAL - FLASK PROJECT

FEATURES
- Email phishing screening with explainable local rules and optional sender hint.
- Dedicated URL pattern scanner.
- SQLite scan history and dashboard metrics.
- PDF scan reports.
- Phishing awareness quiz.
- Offline threat-intelligence reference page (brand lookalikes, URL shorteners, selected TLD heuristics).
- No paid AI API and no external reputation API required.

WINDOWS / VS CODE SETUP
1. Extract this ZIP.
2. Open the PhishGuard_Professional folder in VS Code.
3. Open Terminal > New Terminal. Confirm terminal path is the project folder.
4. Create virtual environment:
   py -3 -m venv .venv
5. Activate:
   .\.venv\Scripts\Activate.ps1
   If PowerShell blocks activation, use:
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   .\.venv\Scripts\python.exe app.py
6. Install dependencies:
   python -m pip install -r requirements.txt
7. Start:
   python app.py
8. Open:
   http://127.0.0.1:5000

DEPENDENCIES
Flask and ReportLab. No OpenAI SDK or API key is used.

IMPORTANT
The scanner is heuristic, not AI and not a confirmed malware verdict.
The threat-intelligence page uses a small offline reference list. It does NOT
query live feeds or prove a domain is safe or malicious.
URLs are not opened, crawled or submitted to external services.
Scan content is stored in phishguard.db on this computer.
This is a local educational demo. Do not expose the Flask debug server publicly.
For production deployment add authentication, CSRF protection, HTTPS, secure
secret management, access controls, retention/deletion controls and testing.

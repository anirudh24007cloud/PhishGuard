import os
import re
import json
import sqlite3
import ipaddress
from datetime import datetime, timedelta
from urllib.parse import urlparse, unquote
from difflib import SequenceMatcher
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, abort
from io import BytesIO

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-this-local-secret-before-deployment")
DB_PATH = os.path.join(os.path.dirname(__file__), "phishguard.db")
MAX_TEXT_LENGTH = 20000

# Offline reference list for lookalike-domain checks. This is not a complete list.
TRUSTED_BRANDS = [
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "paypal.com", "facebook.com", "instagram.com", "netflix.com",
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "srisriuniversity.edu.in"
]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "shorturl.at"}
RISKY_TLDS = {".zip", ".mov", ".click", ".top", ".xyz", ".work", ".support", ".country", ".gq", ".tk"}

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            kind TEXT NOT NULL,
            subject TEXT NOT NULL,
            risk TEXT NOT NULL,
            score INTEGER NOT NULL,
            details TEXT NOT NULL
        )""")

def extract_urls(text):
    pattern = r"""(?i)\b(?:https?://|www\.)[^\s<>"']+"""
    return [u.rstrip(".,;:!?)]}") for u in re.findall(pattern, text or "")]

def normalize_host(host):
    host = (host or "").lower().strip(".")
    try:
        return host.encode("idna").decode("ascii")
    except Exception:
        return host

def url_analysis(url):
    clean = unquote(url.strip())
    parsed = urlparse(clean if clean.lower().startswith(("http://", "https://")) else "http://" + clean)
    host = normalize_host(parsed.hostname or "")
    findings, score = [], 0

    def add(points, label, detail):
        nonlocal score
        score += points
        findings.append({"label": label, "detail": detail, "points": points})

    if not host or "." not in host:
        add(18, "Unusual hostname", "The link does not contain a typical public domain name.")
    if clean.lower().startswith("http://"):
        add(10, "Unencrypted HTTP", "The URL uses HTTP rather than HTTPS. This alone does not prove it is malicious.")
    try:
        ipaddress.ip_address(host)
        add(25, "IP-address host", "The link uses a raw IP address instead of a domain name.")
    except ValueError:
        pass
    if "@" in clean:
        add(22, "At-sign in URL", "An @ symbol can make the apparent destination confusing.")
    if len(clean) > 100:
        add(10, "Long URL", "The URL is unusually long and deserves closer inspection.")
    if host.count("-") >= 2:
        add(8, "Hyphen-heavy domain", "The hostname contains multiple hyphens.")
    if host.startswith("xn--") or ".xn--" in host:
        add(20, "Punycode hostname", "The hostname uses internationalized encoding; inspect it carefully for lookalike characters.")
    if any(host.endswith(tld) for tld in RISKY_TLDS):
        add(12, "Uncommon high-risk TLD", "This top-level domain is sometimes abused. The TLD alone is not proof of phishing.")
    if host in SHORTENERS:
        add(12, "URL shortener", "The final destination is hidden behind a URL-shortening service.")
    labels = host.split(".")
    if len(labels) > 4:
        add(8, "Many subdomains", "The hostname has several subdomain levels.")
    for brand in TRUSTED_BRANDS:
        brand_name = brand.split(".")[0]
        if brand in host:
            continue
        host_core = labels[-2] if len(labels) >= 2 else host
        similarity = SequenceMatcher(None, host_core, brand_name).ratio()
        if similarity >= 0.78 and host_core != brand_name:
            add(18, "Possible lookalike brand", f"The hostname resembles the brand name '{brand_name}'. Confirm the exact official domain.")
            break
    if not findings:
        findings.append({"label":"No obvious URL pattern warning", "detail":"No listed heuristic warning was found. This is not a reputation check or a safety guarantee.", "points":0})
    score = min(score, 100)
    risk = "High" if score >= 55 else "Medium" if score >= 25 else "Low"
    return {"url":url, "host":host, "score":score, "risk":risk, "findings":findings}

def analyze_message(text):
    low = text.lower()
    findings, score = [], 0
    rules = [
        (12, r"\b(urgent|immediately|act now|within 24 hours|final warning)\b", "Urgency or pressure", "The message pressures the recipient to act quickly."),
        (15, r"\b(password|passcode|otp|one[- ]time password|pin)\b", "Credential or OTP reference", "Sensitive login information is mentioned. Never disclose passwords, PINs or OTPs."),
        (12, r"\b(verify your account|verify your identity|confirm your details|update your details)\b", "Verification request", "The message asks the recipient to verify personal or account information."),
        (14, r"\b(suspend(ed|ing)?|blocked|locked|deactivated|terminated)\b", "Account threat", "A threat involving account access may be used to create fear."),
        (10, r"\b(prize|winner|won|reward|claim now|gift card)\b", "Unexpected reward", "Unexpected prizes or rewards are commonly used as click bait."),
        (12, r"\b(payment|bank account|card number|refund|invoice|transaction)\b", "Financial topic", "The message discusses financial information or a payment action."),
        (10, r"\b(click here|open the link|tap here|login here)\b", "Generic link instruction", "The message encourages clicking without clearly explaining the destination."),
        (10, r"\b(confidential|do not tell|keep this secret)\b", "Secrecy request", "The message discourages independent verification.")
    ]
    for points, pattern, label, detail in rules:
        if re.search(pattern, low):
            score += points
            findings.append({"label":label,"detail":detail,"points":points})
    sender = request.form.get("sender", "").strip()[:250] if request else ""
    if sender:
        if re.search(r"(?i)(gmail|outlook|yahoo)\.(com|in)$", sender) and re.search(r"(?i)(bank|university|support|security|admin)", sender):
            score += 12
            findings.append({"label":"Possible sender mismatch","detail":"The sender name or address may not match the organisation it claims to represent.","points":12})
        if "@" not in sender or "." not in sender.split("@")[-1]:
            score += 5
            findings.append({"label":"Unusual sender format","detail":"The supplied sender address does not look like a conventional email address.","points":5})
    urls = [url_analysis(u) for u in extract_urls(text)]
    if urls:
        score += min(20, sum(5 + min(8, u["score"] // 5) for u in urls))
        findings.append({"label":"Links included","detail":f"The message contains {len(urls)} URL(s). Each URL received a separate heuristic review.","points":min(20, sum(5 + min(8, u["score"] // 5) for u in urls))})
    if re.search(r"(?i)(reply|send|share).{0,45}(password|otp|pin)", text):
        score += 18
        findings.append({"label":"Direct request for secrets","detail":"The wording appears to ask the recipient to send a password, OTP or PIN.","points":18})
    score = min(score, 100)
    risk = "High" if score >= 55 else "Medium" if score >= 25 else "Low"
    if not findings:
        findings.append({"label":"No common indicators found","detail":"The rules did not find common warning signs. This does not prove that the message is legitimate.","points":0})
    summary = {
        "High":"Several phishing indicators were found. Do not click links or share information; verify using a trusted channel.",
        "Medium":"Some warning signs were found. Check the sender and verify the request independently.",
        "Low":"Few listed warning signs were found. A low score does not guarantee that the message is safe."
    }[risk]
    return {"kind":"email","score":score,"risk":risk,"summary":summary,"findings":findings,"urls":urls,
            "tips":["Do not share passwords, PINs or OTPs.","Open the official website or app yourself instead of following message links.",
                    "Check the full sender address and exact domain spelling.","Contact the organisation through a trusted channel if unsure."]}

def save_scan(kind, subject, result):
    with db() as conn:
        cur = conn.execute("INSERT INTO scans(created_at,kind,subject,risk,score,details) VALUES(?,?,?,?,?,?)",
            (datetime.now().isoformat(timespec="seconds"), kind, subject[:250], result["risk"], result["score"], json.dumps(result)))
        return cur.lastrowid

def recent_scans(limit=8):
    with db() as conn:
        return conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

def stats():
    with db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        high = conn.execute("SELECT COUNT(*) FROM scans WHERE risk='High'").fetchone()[0]
        medium = conn.execute("SELECT COUNT(*) FROM scans WHERE risk='Medium'").fetchone()[0]
        low = conn.execute("SELECT COUNT(*) FROM scans WHERE risk='Low'").fetchone()[0]
        last7 = conn.execute("SELECT substr(created_at,1,10) day, COUNT(*) n FROM scans WHERE created_at >= ? GROUP BY day ORDER BY day",
                             ((datetime.now()-timedelta(days=6)).date().isoformat(),)).fetchall()
    days = [(datetime.now().date()-timedelta(days=i)).isoformat() for i in range(6,-1,-1)]
    day_map = {r["day"]:r["n"] for r in last7}
    return {"total":total,"high":high,"medium":medium,"low":low,"days":days,"counts":[day_map.get(d,0) for d in days]}

@app.route("/")
def dashboard():
    return render_template("dashboard.html", stats=stats(), scans=recent_scans(6))

@app.route("/email", methods=["GET","POST"])
def email_scanner():
    result = None
    message = sender = ""
    if request.method == "POST":
        message = request.form.get("message","")[:MAX_TEXT_LENGTH]
        sender = request.form.get("sender","")[:250]
        if not message.strip():
            flash("Paste an email or message before scanning.", "warning")
        else:
            result = analyze_message(message)
            result["sender"] = sender
            scan_id = save_scan("Email", (sender or "Email message"), result)
            result["scan_id"] = scan_id
    return render_template("email.html", result=result, message=message, sender=sender)

@app.route("/url", methods=["GET","POST"])
def url_scanner():
    result = None
    url = ""
    if request.method == "POST":
        url = request.form.get("url","").strip()[:2000]
        if not url:
            flash("Enter a URL to analyse.", "warning")
        else:
            result = url_analysis(url)
            result["summary"] = "Heuristic URL review only. The application did not visit this URL or check a live reputation database."
            result["tips"] = ["Do not enter credentials on an unexpected page.","Check the registered domain, not just words appearing in the URL.","Use the organisation's official app or manually typed website.","Treat shortened links and unexpected attachments cautiously."]
            result["kind"] = "url"
            # Keep a separate URL summary object. Do not store [result] here:
            # that would make result refer to itself and json.dumps() would fail.
            result["urls"] = [{
                "url": result["url"],
                "host": result["host"],
                "score": result["score"],
                "risk": result["risk"],
                "findings": result["findings"]
            }]
            scan_id = save_scan("URL", result["host"] or url, result)
            result["scan_id"] = scan_id
    return render_template("url.html", result=result, url=url)

@app.route("/history")
def history():
    return render_template("history.html", scans=recent_scans(100))

@app.route("/report/<int:scan_id>")
def report(scan_id):
    with db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row: abort(404)
    data = json.loads(row["details"])
    return render_template("report.html", scan=row, data=data)

@app.route("/report/<int:scan_id>/pdf")
def report_pdf(scan_id):
    with db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row: abort(404)
    data = json.loads(row["details"])
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
    except ImportError:
        flash("PDF package missing. Run: python -m pip install reportlab", "warning")
        return redirect(url_for("report", scan_id=scan_id))
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=18*mm, leftMargin=18*mm, topMargin=18*mm, bottomMargin=18*mm)
    styles = getSampleStyleSheet()
    story = [Paragraph("PhishGuard Security Scan Report", styles["Title"]), Spacer(1,8)]
    story.append(Paragraph(f"Scan ID: {row['id']} | Type: {row['kind']} | Date: {row['created_at']}", styles["Normal"]))
    story.append(Spacer(1,10))
    story.append(Paragraph(f"Subject: {row['subject']}", styles["Heading2"]))
    story.append(Paragraph(f"Risk: {row['risk']} | Heuristic score: {row['score']}/100", styles["Heading2"]))
    story.append(Paragraph(data.get("summary",""), styles["BodyText"]))
    story.append(Spacer(1,10))
    story.append(Paragraph("Findings", styles["Heading2"]))
    findings = data.get("findings",[])
    table_data = [["Indicator","Explanation","Points"]]
    for f in findings:
        table_data.append([Paragraph(f.get("label",""),styles["BodyText"]),Paragraph(f.get("detail",""),styles["BodyText"]),str(f.get("points",0))])
    table = Table(table_data, colWidths=[42*mm,112*mm,18*mm], repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#dce9f2")),("GRID",(0,0),(-1,-1),0.4,colors.grey),("VALIGN",(0,0),(-1,-1),"TOP"),("PADDING",(0,0),(-1,-1),6)]))
    story.append(table)
    story.append(Spacer(1,12))
    story.append(Paragraph("Recommendations", styles["Heading2"]))
    for tip in data.get("tips",[]): story.append(Paragraph("• "+tip, styles["BodyText"]))
    story.append(Spacer(1,10))
    story.append(Paragraph("Limitations: This report records local heuristic checks. It is not a malware scan, live domain reputation lookup, or guarantee of safety.", styles["Italic"]))
    doc.build(story)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"phishguard_scan_{scan_id}.pdf", mimetype="application/pdf")

QUIZ = [
 {"q":"Which action is safest when an unexpected email asks you to verify your university account?","opts":["Click the email link immediately","Open the university website using a saved or manually typed address","Reply with your password","Forward the message to classmates"],"a":1,"why":"Use a trusted route to the organisation rather than an unexpected message link."},
 {"q":"Should you ever share a one-time password (OTP) with someone claiming to be support?","opts":["Yes, if they sound official","Only during office hours","No, never disclose an OTP to another person","Yes, if the message says urgent"],"a":2,"why":"An OTP is an authentication secret and should not be disclosed to another person."},
 {"q":"What should you inspect in a suspicious link?","opts":["Only its display text","The actual hostname and spelling of the registered domain","The colour of the button","The sender's profile photo"],"a":1,"why":"The real hostname can reveal misleading or lookalike domains."},
 {"q":"A message says your account will be closed in ten minutes unless you act. What is this commonly using?","opts":["Urgency and fear","Encryption","A digital signature","A software update"],"a":0,"why":"Threats and short deadlines are common social-engineering pressure tactics."},
 {"q":"Does a low score from this PhishGuard rule-based scanner prove a message is safe?","opts":["Yes, always","Yes, if it has HTTPS","No, it only means few configured indicators were detected","Yes, if there are no spelling mistakes"],"a":2,"why":"Heuristic scanners can miss new, targeted or carefully written phishing messages."}
]

@app.route("/quiz", methods=["GET","POST"])
def quiz():
    questions = QUIZ
    score = None
    answers = {}
    if request.method == "POST":
        score = 0
        for i, q in enumerate(questions):
            try: choice = int(request.form.get(f"q{i}", "-1"))
            except ValueError: choice = -1
            answers[i] = choice
            if choice == q["a"]: score += 1
    return render_template("quiz.html", questions=questions, score=score, answers=answers)

@app.route("/intelligence")
def intelligence():
    return render_template("intelligence.html", brands=TRUSTED_BRANDS, shorteners=sorted(SHORTENERS), tlds=sorted(RISKY_TLDS))

@app.route("/about")
def about():
    return render_template("about.html")

@app.errorhandler(404)
def not_found(_):
    return render_template("base.html", standalone_message="The requested page was not found."), 404

init_db()
if __name__ == "__main__":
    app.run(debug=True)

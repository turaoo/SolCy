#!/usr/bin/env python3
"""
SolCy — Web App Backend
Runs on Flask. Stripe handles subscriptions.
"""

import os, json, hashlib, sqlite3, secrets, functools
from pathlib import Path
from datetime import datetime, timezone, timedelta
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, jsonify, send_file)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ── Import the analysis engine ────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
import arthur_analysis as engine

# ── Config ────────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

UPLOAD_FOLDER  = Path(__file__).parent / "uploads"
DB_PATH        = Path(__file__).parent / "solcy_web.db"
MAX_FILE_MB    = 50
STRIPE_PUB_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY", "")
STRIPE_SEC_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
VT_API_KEY     = os.environ.get("VT_API_KEY", "")

# Stripe price IDs — set these after creating products in your Stripe dashboard
STRIPE_PRICE_PRO  = os.environ.get("STRIPE_PRICE_PRO", "price_pro_monthly")
STRIPE_PRICE_TEAM = os.environ.get("STRIPE_PRICE_TEAM", "price_team_monthly")

PLANS = {
    "free":  {"name": "Free",  "scans": 5,   "price": 0,   "features": ["5 scans/month", "HTML report", "Hash lookup"]},
    "pro":   {"name": "Pro",   "scans": 999, "price": 19,  "features": ["Unlimited scans", "PDF + HTML reports", "VirusTotal integration", "MalwareBazaar", "AlienVault OTX", "CSV export", "Scan history"]},
    "team":  {"name": "Team",  "scans": 999, "price": 49,  "features": ["Everything in Pro", "5 team seats", "Folder scanning", "Priority support", "API access"]},
}

UPLOAD_FOLDER.mkdir(exist_ok=True)

# ── Database ───────────────────────────────────────────────────────────────────
def get_db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = get_db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        plan TEXT DEFAULT 'free',
        scans_used INTEGER DEFAULT 0,
        scans_reset TEXT,
        stripe_customer_id TEXT,
        stripe_subscription_id TEXT,
        created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        filename TEXT,
        severity TEXT,
        families TEXT,
        vt_malicious INTEGER,
        vt_total INTEGER,
        md5 TEXT,
        sha256 TEXT,
        report_json TEXT,
        created_at TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)
    con.commit(); con.close()

init_db()

# ── Auth helpers ───────────────────────────────────────────────────────────────
def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def get_current_user():
    if "user_id" not in session:
        return None
    con = get_db()
    user = con.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    con.close()
    return user

def can_scan(user):
    if user["plan"] in ("pro","team"):
        return True
    # Reset monthly counter
    reset = user["scans_reset"]
    now   = datetime.now(timezone.utc)
    if not reset or datetime.fromisoformat(reset) < now - timedelta(days=30):
        con = get_db()
        con.execute("UPDATE users SET scans_used=0, scans_reset=? WHERE id=?",
                    (now.isoformat(), user["id"]))
        con.commit(); con.close()
        return True
    return user["scans_used"] < PLANS[user["plan"]]["scans"]

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    user = get_current_user()
    return render_template("index.html", user=user, plans=PLANS,
                           stripe_pub_key=STRIPE_PUB_KEY)

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        email    = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        if not email or not password or len(password) < 8:
            flash("Valid email and password (8+ chars) required.", "error")
            return render_template("register.html")
        try:
            con = get_db()
            con.execute("""INSERT INTO users (email,password_hash,plan,scans_used,created_at)
                           VALUES (?,?,'free',0,?)""",
                        (email, generate_password_hash(password),
                         datetime.now(timezone.utc).isoformat()))
            con.commit()
            user = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            con.close()
            session["user_id"] = user["id"]
            flash("Account created! You're on the Free plan.", "success")
            return redirect(url_for("dashboard"))
        except sqlite3.IntegrityError:
            flash("Email already registered.", "error")
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email    = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        con = get_db()
        user = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        con.close()
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))
        flash("Invalid email or password.", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    user = get_current_user()
    con  = get_db()
    scans = con.execute(
        "SELECT * FROM scans WHERE user_id=? ORDER BY created_at DESC LIMIT 50",
        (user["id"],)
    ).fetchall()
    con.close()
    plan_info = PLANS.get(user["plan"], PLANS["free"])
    return render_template("dashboard.html", user=user, scans=scans,
                           plan=plan_info, plans=PLANS)

@app.route("/scan", methods=["POST"])
@login_required
def scan():
    user = get_current_user()
    if not can_scan(user):
        return jsonify({"error": f"Scan limit reached. Upgrade to Pro for unlimited scans."}), 403

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400

    f    = request.files["file"]
    if not f.filename:
        return jsonify({"error": "No file selected."}), 400

    filename  = secure_filename(f.filename)
    save_path = UPLOAD_FOLDER / f"{secrets.token_hex(8)}_{filename}"
    f.save(save_path)

    try:
        use_vt  = user["plan"] in ("pro","team") and VT_API_KEY
        use_mb  = user["plan"] in ("pro","team")
        report  = engine.analyze(
            str(save_path),
            as_json=False,
            vt_key=VT_API_KEY if use_vt else None,
            no_mb=not use_mb,
        )

        # Generate HTML report
        html_path = UPLOAD_FOLDER / f"{save_path.stem}_report.html"
        engine.export_html(report, str(html_path))

        # Generate PDF for pro/team
        pdf_path = None
        if user["plan"] in ("pro","team"):
            pdf_path = UPLOAD_FOLDER / f"{save_path.stem}_report.pdf"
            engine.export_pdf(report, str(pdf_path))

        # Save scan to DB
        vt  = report.get("virustotal", {})
        con = get_db()
        cur = con.execute("""INSERT INTO scans
            (user_id,filename,severity,families,vt_malicious,vt_total,md5,sha256,report_json,created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)""", (
            user["id"], filename, report["severity"],
            "; ".join(f["family"] for f in report["malware_classification"]),
            vt.get("malicious",0), vt.get("total",0),
            report["hashes"]["md5"], report["hashes"]["sha256"],
            json.dumps(report, default=str),
            datetime.now(timezone.utc).isoformat()
        ))
        scan_id = cur.lastrowid
        con.execute("UPDATE users SET scans_used=scans_used+1 WHERE id=?", (user["id"],))
        con.commit(); con.close()

        return jsonify({
            "scan_id":   scan_id,
            "severity":  report["severity"],
            "families":  [f["family"] for f in report["malware_classification"]],
            "verdict":   report["executive_summary"]["verdict"],
            "action":    report["executive_summary"]["action"],
            "detail":    report["executive_summary"]["detail"],
            "hashes":    report["hashes"],
            "vt":        {"malicious": vt.get("malicious",0), "total": vt.get("total",0), "names": vt.get("top_names",[])},
            "indicators": sum(len(v) for v in report["suspicious_strings"].values()),
            "entropy":   report["entropy"],
            "file_type": report["magic_type"],
            "html_ready": True,
            "pdf_ready":  pdf_path is not None,
            "report_stem": save_path.stem,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        try: save_path.unlink()
        except: pass

@app.route("/report/<stem>/html")
@login_required
def download_html(stem):
    path = UPLOAD_FOLDER / f"{stem}_report.html"
    if path.exists():
        return send_file(path, as_attachment=True, download_name="solcy_report.html")
    return "Report not found", 404

@app.route("/report/<stem>/pdf")
@login_required
def download_pdf(stem):
    user = get_current_user()
    if user["plan"] not in ("pro","team"):
        flash("PDF reports require a Pro or Team plan.", "error")
        return redirect(url_for("pricing"))
    path = UPLOAD_FOLDER / f"{stem}_report.pdf"
    if path.exists():
        return send_file(path, as_attachment=True, download_name="solcy_report.pdf")
    return "Report not found", 404

@app.route("/scan/<int:scan_id>")
@login_required
def scan_detail(scan_id):
    user = get_current_user()
    con  = get_db()
    scan = con.execute("SELECT * FROM scans WHERE id=? AND user_id=?",
                       (scan_id, user["id"])).fetchone()
    con.close()
    if not scan:
        flash("Scan not found.", "error")
        return redirect(url_for("dashboard"))
    report = json.loads(scan["report_json"])
    return render_template("scan_detail.html", scan=scan, report=report, user=user,
                           plan=PLANS.get(user["plan"], PLANS["free"]))

@app.route("/pricing")
def pricing():
    user = get_current_user()
    return render_template("pricing.html", user=user, plans=PLANS,
                           stripe_pub_key=STRIPE_PUB_KEY,
                           price_pro=STRIPE_PRICE_PRO,
                           price_team=STRIPE_PRICE_TEAM)

@app.route("/create-checkout", methods=["POST"])
@login_required
def create_checkout():
    try:
        import stripe
        stripe.api_key = STRIPE_SEC_KEY
        user  = get_current_user()
        plan  = request.json.get("plan")
        price = STRIPE_PRICE_PRO if plan == "pro" else STRIPE_PRICE_TEAM
        checkout = stripe.checkout.Session.create(
            payment_method_types=["card"],
            mode="subscription",
            customer_email=user["email"],
            line_items=[{"price": price, "quantity": 1}],
            success_url=request.host_url + "payment-success?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=request.host_url + "pricing",
            metadata={"user_id": user["id"], "plan": plan},
        )
        return jsonify({"url": checkout.url})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/payment-success")
@login_required
def payment_success():
    flash("Payment successful! Your plan has been upgraded.", "success")
    return redirect(url_for("dashboard"))

@app.route("/stripe-webhook", methods=["POST"])
def stripe_webhook():
    try:
        import stripe
        stripe.api_key = STRIPE_SEC_KEY
        payload = request.data
        sig     = request.headers.get("Stripe-Signature","")
        event   = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK)
        if event["type"] == "checkout.session.completed":
            s       = event["data"]["object"]
            user_id = s["metadata"].get("user_id")
            plan    = s["metadata"].get("plan","pro")
            sub_id  = s.get("subscription","")
            cus_id  = s.get("customer","")
            if user_id:
                con = get_db()
                con.execute("""UPDATE users SET plan=?,stripe_subscription_id=?,
                               stripe_customer_id=? WHERE id=?""",
                            (plan, sub_id, cus_id, user_id))
                con.commit(); con.close()
        elif event["type"] == "customer.subscription.deleted":
            cus_id = event["data"]["object"]["customer"]
            con = get_db()
            con.execute("UPDATE users SET plan='free' WHERE stripe_customer_id=?", (cus_id,))
            con.commit(); con.close()
    except Exception:
        pass
    return "", 200

if __name__ == "__main__":
    app.run(debug=True, port=5000)

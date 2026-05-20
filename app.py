"""
app.py — SecureAuth: AI/ML-Enhanced Multi-Factor Authentication System
TMS4853 Computer Security — Password Guessing Attack Mitigation

Improvements over the sample code:
  1. ✅ Real ML model (Random Forest) replacing rule-based engine
  2. ✅ Trained Decision Tree & Random Forest classifiers
  3. ✅ CAPTCHA after repeated failed attempts
  4. ✅ Hashed passwords (SHA-256) instead of plaintext
  5. ✅ Real email OTP delivery via Flask-Mail (SMTP)
  6. ✅ IP address tracking and risk assessment
  7. ✅ Behavioral biometrics (typing speed analysis)
  8. ✅ Unusual time toggle for demo/testing
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_mail import Mail, Message
import json
import os
import random
import time
import hashlib
import pickle
import numpy as np
from datetime import datetime

app = Flask(__name__)
app.secret_key = "tms4853_computer_security_secureauth_2026"

# ============================================================
# EMAIL CONFIGURATION (Gmail SMTP)
# ============================================================
# To use Gmail:
# 1. Enable 2-Step Verification at https://myaccount.google.com/security
# 2. Generate App Password at https://myaccount.google.com/apppasswords
# 3. Replace the values below
# ============================================================
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'naash2024@gmail.com'          
app.config['MAIL_PASSWORD'] = 'mkkv xxer jnmj sing'        
app.config['MAIL_DEFAULT_SENDER'] = ('SecureAuth MFA', 'naash2024@gmail.com')  

mail = Mail(app)

# ============================================================
# FILE PATHS & CONSTANTS
# ============================================================
# Use absolute paths so it works on PythonAnywhere (WSGI runs from different directory)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, "users.json")
OTP_FILE = os.path.join(BASE_DIR, "otp_store.json")
LOGIN_LOG_FILE = os.path.join(BASE_DIR, "login_log.json")
ML_MODEL_PATH = os.path.join(BASE_DIR, "ml_model", "risk_model.pkl")

BLOCK_THRESHOLD = 5
BLOCK_DURATION = 60    # seconds
OTP_EXPIRY = 300       # 5 minutes
CAPTCHA_THRESHOLD = 2  # show CAPTCHA after this many failed attempts

# In-memory trackers
login_tracker = {}
known_ips = {}            # username -> set of known IPs
typing_profiles = {}      # username -> list of typing speeds (chars/sec)
force_unusual_hour = {}   # session override for demo toggle

# ============================================================
# LOAD ML MODEL
# ============================================================
ml_model = None

def load_ml_model():
    global ml_model
    if os.path.exists(ML_MODEL_PATH):
        with open(ML_MODEL_PATH, "rb") as f:
            ml_model = pickle.load(f)
        print(f"[ML] Random Forest model loaded from {ML_MODEL_PATH}")
    else:
        print(f"[ML] No model found at {ML_MODEL_PATH}. Run 'python train_model.py' first.")
        print(f"[ML] Falling back to rule-based engine.")


# ============================================================
# UTILITY FUNCTIONS
# ============================================================
def load_json(filepath):
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            return json.load(f)
    return {}

def save_json(filepath, data):
    with open(filepath, "w") as f:
        json.dump(data, f, indent=4)

def hash_password(password):
    """Hash password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def load_users():
    return load_json(USERS_FILE)

def save_users(data):
    save_json(USERS_FILE, data)

def load_otp_store():
    return load_json(OTP_FILE)

def save_otp_store(data):
    save_json(OTP_FILE, data)

def load_login_log():
    if os.path.exists(LOGIN_LOG_FILE):
        with open(LOGIN_LOG_FILE, "r") as f:
            return json.load(f)
    return []

def save_login_log(log):
    with open(LOGIN_LOG_FILE, "w") as f:
        json.dump(log, f, indent=4)

def generate_otp():
    return str(random.randint(100000, 999999))

def generate_captcha():
    """Generate a simple math CAPTCHA."""
    a = random.randint(2, 15)
    b = random.randint(1, 10)
    ops = [('+', a + b), ('-', a - b), ('×', a * b)]
    op_symbol, answer = random.choice(ops)
    question = f"{a} {op_symbol} {b}"
    return question, str(answer)


# ============================================================
# IP ADDRESS TRACKING
# ============================================================
def get_client_ip():
    """Get real client IP, accounting for proxies."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers['X-Forwarded-For'].split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'

def is_ip_suspicious(username, ip_address):
    """Check if IP is new/unknown for this user."""
    if username not in known_ips:
        known_ips[username] = set()
    if ip_address in known_ips[username]:
        return 0  # known IP
    return 1  # new IP


def register_ip(username, ip_address):
    """Register an IP as known for a user after successful login."""
    if username not in known_ips:
        known_ips[username] = set()
    known_ips[username].add(ip_address)


# ============================================================
# BEHAVIORAL BIOMETRICS — Typing Speed Analysis
# ============================================================
def analyze_typing_speed(username, typing_speed):
    """
    Compare current typing speed against user's historical profile.
    Returns 1 if anomalous, 0 if normal.
    typing_speed = characters per second from the login form JS.
    """
    if typing_speed is None or typing_speed <= 0:
        return 0  # no data, assume normal

    if username not in typing_profiles:
        typing_profiles[username] = []

    profile = typing_profiles[username]

    if len(profile) < 3:
        # Not enough history — can't determine anomaly yet
        return 0

    avg_speed = sum(profile) / len(profile)
    std_speed = max((sum((s - avg_speed) ** 2 for s in profile) / len(profile)) ** 0.5, 0.5)

    # Anomaly if current speed deviates by more than 2 standard deviations
    deviation = abs(typing_speed - avg_speed) / std_speed
    return 1 if deviation > 2.0 else 0


def update_typing_profile(username, typing_speed):
    """Store typing speed after successful login."""
    if typing_speed and typing_speed > 0:
        if username not in typing_profiles:
            typing_profiles[username] = []
        typing_profiles[username].append(typing_speed)
        # Keep last 20 samples
        typing_profiles[username] = typing_profiles[username][-20:]


# ============================================================
# UNUSUAL HOUR CHECK (with demo toggle support)
# ============================================================
def is_unusual_hour(session_id=None):
    """
    Check if current hour is unusual (12AM-5AM).
    Can be overridden by the demo toggle.
    """
    # Check if demo toggle is active
    if session.get('force_unusual_hour'):
        return 1

    hour = datetime.now().hour
    return 1 if hour < 5 else 0


# ============================================================
# FEATURE EXTRACTION
# ============================================================
def initialize_user_tracker(username):
    if username not in login_tracker:
        login_tracker[username] = {
            "failed_attempts": 0,
            "last_attempt_time": 0,
            "blocked_until": 0
        }

def extract_features(username, device_id, password_correct, ip_address, typing_speed):
    """
    Extract 7 login behavior features for the ML risk engine.

    Features:
      1. failed_attempts       — consecutive failed logins
      2. short_interval        — 1 if < 5 seconds since last attempt
      3. unknown_device        — 1 if device not recognized
      4. unusual_hour          — 1 if 12AM-5AM (or demo toggle)
      5. password_match        — 1 if password correct
      6. ip_risk               — 1 if IP is new for this user
      7. typing_speed_anomaly  — 1 if typing speed deviates from profile
    """
    initialize_user_tracker(username)
    tracker = login_tracker[username]
    current_time = time.time()

    short_interval = 1 if current_time - tracker["last_attempt_time"] < 5 else 0
    unusual_hour = is_unusual_hour()

    users = load_users()
    unknown_device = 1
    if username in users:
        if device_id == users[username].get("known_device", ""):
            unknown_device = 0

    ip_risk = is_ip_suspicious(username, ip_address)
    typing_anomaly = analyze_typing_speed(username, typing_speed)

    features = {
        "failed_attempts": tracker["failed_attempts"],
        "short_interval": short_interval,
        "unknown_device": unknown_device,
        "unusual_hour": unusual_hour,
        "password_match": 1 if password_correct else 0,
        "ip_risk": ip_risk,
        "typing_speed_anomaly": typing_anomaly
    }

    tracker["last_attempt_time"] = current_time
    return features


# ============================================================
# RISK ENGINE — ML Model + Fallback Rule-Based
# ============================================================
def ml_risk_engine(features):
    """
    Use trained Random Forest model to predict risk level.
    Falls back to rule-based engine if model not available.
    """
    if ml_model is not None:
        # Prepare feature vector in the order the model expects
        X = np.array([[
            features["failed_attempts"],
            features["short_interval"],
            features["unknown_device"],
            features["unusual_hour"],
            features["password_match"],
            features["ip_risk"],
            features["typing_speed_anomaly"]
        ]])

        prediction = ml_model.predict(X)[0]
        probabilities = ml_model.predict_proba(X)[0]
        confidence = max(probabilities) * 100

        risk_map = {0: "low", 1: "medium", 2: "high"}
        risk_level = risk_map.get(prediction, "low")

        # Calculate a score from probabilities for display
        risk_score = round(probabilities[1] * 4 + probabilities[2] * 8, 1)

        return risk_level, risk_score, confidence, "Random Forest ML Model"
    else:
        return fallback_rule_engine(features)


def fallback_rule_engine(features):
    """
    Rule-based fallback if ML model is not trained yet.
    """
    score = 0
    if features["failed_attempts"] >= 3:
        score += 2
    if features["short_interval"] == 1:
        score += 2
    if features["unknown_device"] == 1:
        score += 1
    if features["unusual_hour"] == 1:
        score += 1
    if features["password_match"] == 0:
        score += 2
    if features["ip_risk"] == 1:
        score += 1
    if features["typing_speed_anomaly"] == 1:
        score += 1

    if score >= 6:
        return "high", score, 100.0, "Rule-Based Engine (fallback)"
    elif score >= 3:
        return "medium", score, 100.0, "Rule-Based Engine (fallback)"
    else:
        return "low", score, 100.0, "Rule-Based Engine (fallback)"


# ============================================================
# EMAIL OTP DELIVERY
# ============================================================
def send_otp_email(recipient_email, otp_code, username):
    """Send OTP via real email using Flask-Mail / Gmail SMTP."""
    try:
        msg = Message(
            subject="🔐 Your SecureAuth Verification Code",
            recipients=[recipient_email]
        )
        msg.html = f"""
        <div style="font-family:'Segoe UI',Arial,sans-serif;max-width:480px;margin:0 auto;background:#f8fafc;padding:32px;border-radius:12px;">
            <div style="text-align:center;margin-bottom:24px;">
                <div style="display:inline-block;background:linear-gradient(135deg,#2563eb,#7c3aed);padding:12px 24px;border-radius:8px;">
                    <span style="color:black;font-size:18px;font-weight:700;letter-spacing:1px;">SecureAuth MFA</span>
                </div>
            </div>
            <div style="background:white;padding:28px;border-radius:10px;box-shadow:0 1px 3px rgba(0,0,0,0.1);">
                <p style="color:#334155;font-size:15px;margin:0 0 16px;">Hello <strong>{username}</strong>,</p>
                <p style="color:#334155;font-size:15px;margin:0 0 20px;">Your one-time verification code is:</p>
                <div style="text-align:center;margin:24px 0;">
                    <span style="display:inline-block;background:#f1f5f9;border:2px dashed #2563eb;padding:16px 32px;border-radius:8px;font-size:32px;font-weight:700;letter-spacing:8px;color:#1e293b;">{otp_code}</span>
                </div>
                <p style="color:#64748b;font-size:13px;margin:20px 0 0;">This code expires in <strong>5 minutes</strong>. Do not share it with anyone.</p>
                <p style="color:#64748b;font-size:13px;margin:8px 0 0;">If you did not request this code, please ignore this email or contact support.</p>
            </div>
            <p style="text-align:center;color:#94a3b8;font-size:11px;margin-top:20px;">TMS4853 Computer Security — AI/ML-Enhanced MFA System</p>
        </div>
        """
        mail.send(msg)
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send OTP to {recipient_email}: {e}")
        return False


# ============================================================
# AUDIT LOG
# ============================================================
def log_login_attempt(username, risk_level, risk_score, features, success, ip_address, engine_type, confidence):
    log = load_login_log()
    log.append({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "username": username,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "features": features,
        "success": success,
        "ip_address": ip_address,
        "engine_type": engine_type,
        "confidence": round(confidence, 1)
    })
    save_login_log(log)


# ============================================================
# INITIALIZE DEFAULT USERS
# ============================================================
def init_users():
    if not os.path.exists(USERS_FILE):
        users = {
            "student1": {
                "password_hash": hash_password("Secure123!"),
                "email": "student1@example.com",
                "known_device": "laptop-01"
            },
            "student2": {
                "password_hash": hash_password("StrongPass456!"),
                "email": "student2@example.com",
                "known_device": "phone-02"
            }
        }
        save_users(users)
        print("[INIT] Created users.json with default users (hashed passwords)")


# ============================================================
# ROUTES
# ============================================================

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        device_id = request.form.get("device_id", "").strip()
        typing_speed = request.form.get("typing_speed", None)
        captcha_answer = request.form.get("captcha_answer", "").strip()

        # Parse typing speed
        try:
            typing_speed = float(typing_speed) if typing_speed else None
        except (ValueError, TypeError):
            typing_speed = None

        ip_address = get_client_ip()
        users = load_users()
        initialize_user_tracker(username)
        tracker = login_tracker[username]

        # --- Check if blocked ---
        if time.time() < tracker["blocked_until"]:
            remaining = int(tracker["blocked_until"] - time.time())
            return render_template("blocked.html", remaining=remaining)

        # --- CAPTCHA validation (if required) ---
        needs_captcha = tracker["failed_attempts"] >= CAPTCHA_THRESHOLD
        if needs_captcha:
            correct_captcha = session.get("captcha_answer", "")
            if captcha_answer != correct_captcha:
                # Generate new CAPTCHA
                q, a = generate_captcha()
                session["captcha_question"] = q
                session["captcha_answer"] = a
                return render_template(
                    "login.html",
                    error="Incorrect CAPTCHA. Please try again.",
                    show_captcha=True,
                    captcha_question=q,
                    failed_count=tracker["failed_attempts"]
                )

        # --- Password verification (hashed) ---
        password_correct = False
        if username in users:
            if hash_password(password) == users[username]["password_hash"]:
                password_correct = True

        # --- Extract features ---
        features = extract_features(username, device_id, password_correct, ip_address, typing_speed)

        # --- ML Risk Engine ---
        risk_level, risk_score, confidence, engine_type = ml_risk_engine(features)

        # --- WRONG PASSWORD ---
        if not password_correct:
            tracker["failed_attempts"] += 1
            log_login_attempt(username, risk_level, risk_score, features, False, ip_address, engine_type, confidence)

            if tracker["failed_attempts"] >= BLOCK_THRESHOLD:
                tracker["blocked_until"] = time.time() + BLOCK_DURATION
                return render_template("blocked.html", remaining=BLOCK_DURATION)

            # Check if CAPTCHA should appear now
            show_captcha = tracker["failed_attempts"] >= CAPTCHA_THRESHOLD
            captcha_q = None
            if show_captcha:
                q, a = generate_captcha()
                session["captcha_question"] = q
                session["captcha_answer"] = a
                captcha_q = q

            return render_template(
                "login.html",
                error=f"Invalid credentials. Risk: {risk_level.upper()} (score: {risk_score})",
                risk_level=risk_level,
                risk_score=risk_score,
                features=features,
                engine_type=engine_type,
                confidence=confidence,
                show_captcha=show_captcha,
                captcha_question=captcha_q,
                failed_count=tracker["failed_attempts"]
            )

        # --- CORRECT PASSWORD ---
        tracker["failed_attempts"] = 0

        # High risk → block even with correct password
        if risk_level == "high":
            tracker["blocked_until"] = time.time() + BLOCK_DURATION
            log_login_attempt(username, risk_level, risk_score, features, False, ip_address, engine_type, confidence)
            return render_template("blocked.html", remaining=BLOCK_DURATION)

        # Medium risk → delay
        if risk_level == "medium":
            time.sleep(3)

        # Register IP and typing profile on successful password
        register_ip(username, ip_address)
        update_typing_profile(username, typing_speed)

        # --- Generate & send OTP ---
        otp = generate_otp()
        otp_store = load_otp_store()
        otp_store[username] = {"code": otp, "created_at": time.time()}
        save_otp_store(otp_store)

        user_email = users[username].get("email", "")
        email_sent = send_otp_email(user_email, otp, username)

        if not email_sent:
            print(f"[FALLBACK OTP for {username}]: {otp}")

        # Store session data
        session["username"] = username
        session["risk_level"] = risk_level
        session["risk_score"] = risk_score
        session["features"] = features
        session["email_sent"] = email_sent
        session["user_email"] = user_email
        session["ip_address"] = ip_address
        session["engine_type"] = engine_type
        session["confidence"] = confidence

        log_login_attempt(username, risk_level, risk_score, features, "pending_otp", ip_address, engine_type, confidence)

        return redirect(url_for("otp_verification"))

    # GET — generate CAPTCHA if needed
    return render_template("login.html")


@app.route("/otp", methods=["GET", "POST"])
def otp_verification():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    risk_level = session.get("risk_level", "low")
    email_sent = session.get("email_sent", False)
    user_email = session.get("user_email", "")

    # Mask email
    if user_email and "@" in user_email:
        local, domain = user_email.split("@", 1)
        masked_email = local[:2] + "***@" + domain
    else:
        masked_email = "your registered email"

    if request.method == "POST":
        entered_otp = request.form.get("otp", "").strip()
        otp_store = load_otp_store()
        stored = otp_store.get(username, {})
        correct_otp = stored.get("code", "")
        created_at = stored.get("created_at", 0)

        if time.time() - created_at > OTP_EXPIRY:
            otp_store.pop(username, None)
            save_otp_store(otp_store)
            return render_template("otp.html", error="OTP has expired. Please login again.",
                risk_level=risk_level, masked_email=masked_email, email_sent=email_sent)

        if entered_otp == correct_otp:
            otp_store.pop(username, None)
            save_otp_store(otp_store)
            features = session.get("features", {})
            risk_score = session.get("risk_score", 0)
            ip_address = session.get("ip_address", "")
            engine_type = session.get("engine_type", "")
            confidence = session.get("confidence", 0)
            log_login_attempt(username, risk_level, risk_score, features, True, ip_address, engine_type, confidence)
            return render_template("success.html", username=username, risk_level=risk_level,
                risk_score=risk_score, features=features, engine_type=engine_type,
                confidence=confidence, ip_address=ip_address)

        return render_template("otp.html", error="Invalid OTP. Please try again.",
            risk_level=risk_level, masked_email=masked_email, email_sent=email_sent)

    return render_template("otp.html", risk_level=risk_level,
        masked_email=masked_email, email_sent=email_sent)


@app.route("/resend-otp")
def resend_otp():
    if "username" not in session:
        return redirect(url_for("login"))
    username = session["username"]
    users = load_users()
    if username not in users:
        return redirect(url_for("login"))

    otp = generate_otp()
    otp_store = load_otp_store()
    otp_store[username] = {"code": otp, "created_at": time.time()}
    save_otp_store(otp_store)

    user_email = users[username].get("email", "")
    email_sent = send_otp_email(user_email, otp, username)
    session["email_sent"] = email_sent
    if not email_sent:
        print(f"[FALLBACK OTP for {username}]: {otp}")
    return redirect(url_for("otp_verification"))


@app.route("/toggle-unusual-hour", methods=["POST"])
def toggle_unusual_hour():
    """API endpoint for the demo toggle."""
    current = session.get("force_unusual_hour", False)
    session["force_unusual_hour"] = not current
    return jsonify({"unusual_hour": session["force_unusual_hour"]})


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    logs = load_login_log()
    logs.reverse()
    return render_template("dashboard.html", logs=logs[:50])


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    init_users()
    load_ml_model()
    print("\n" + "=" * 60)
    print("  SecureAuth — AI/ML-Enhanced MFA System")
    print("  TMS4853 Computer Security")
    print("=" * 60)
    print("  Default users:")
    print("    student1 / Secure123!  (device: laptop-01)")
    print("    student2 / StrongPass456!  (device: phone-02)")
    print("-" * 60)
    if ml_model:
        print("  ✓ ML Engine: Random Forest Classifier (active)")
    else:
        print("  ⚠ ML Engine: Not found. Run 'python train_model.py' first")
        print("    Using rule-based fallback engine.")
    print("-" * 60)
    print("  ⚠ Update email settings in app.py for real OTP delivery")
    print("=" * 60 + "\n")
    app.run(debug=True, port=5000)

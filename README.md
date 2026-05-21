# SecureAuth — AI/ML-Enhanced Multi-Factor Authentication System
## TMS4853 Computer Security | UNIMAS — Password Guessing Attack Mitigation

---

## All 7 Improvements Implemented

| # | Improvement | Status | Details |
|---|-------------|--------|---------|
| 1 | Real ML Model | ✅ | Random Forest Classifier (81.4% accuracy) |
| 2 | Decision Tree & Random Forest | ✅ | Both trained, RF used as primary |
| 3 | CAPTCHA after failed attempts | ✅ | Math CAPTCHA appears after 2 failed logins |
| 4 | Hashed passwords | ✅ | SHA-256 hashed storage |
| 5 | Real email OTP | ✅ | Flask-Mail via Gmail SMTP |
| 6 | IP address tracking | ✅ | New/unknown IP flagged as risk feature |
| 7 | Behavioral biometrics | ✅ | Typing speed analysis with anomaly detection |

**Bonus:** Unusual Hour demo toggle on the left panel

---

## Quick Start

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Train the ML Model
```bash
python train_model.py
```
This trains a Random Forest and Decision Tree on 5,000 synthetic login behavior samples and saves the models to `ml_model/`.

### Step 3: Configure Email (Gmail SMTP)

Open `app.py` and update lines 34-36:
```python
app.config['MAIL_USERNAME'] = 'your_real@gmail.com'
app.config['MAIL_PASSWORD'] = 'xxxx xxxx xxxx xxxx'   # Gmail App Password
app.config['MAIL_DEFAULT_SENDER'] = ('SecureAuth MFA', 'your_real@gmail.com')
```

**How to get a Gmail App Password:**
1. Enable 2-Step Verification at https://myaccount.google.com/security
2. Go to https://myaccount.google.com/apppasswords
3. Generate an App Password for "Mail" → "Other (SecureAuth)"
4. Copy the 16-character password into `MAIL_PASSWORD`

### Step 4: Update User Emails
After first run, edit `users.json` and set real recipient emails.

### Step 5: Run
```bash
python app.py
```
Open http://localhost:5000

---

## Default Test Accounts

| Username | Password | Device ID |
|----------|----------|-----------|
| student1 | Secure123! | laptop-01 |
| student2 | StrongPass456! | phone-02 |

---

## 7 ML Features Used for Detection

| # | Feature | Description | Risk Weight |
|---|---------|-------------|-------------|
| 1 | `failed_attempts` | Consecutive failed logins | **High (36.2%)** |
| 2 | `password_match` | Whether password is correct | **High (19.7%)** |
| 3 | `short_interval` | Attempts < 5 seconds apart | **High (18.6%)** |
| 4 | `unknown_device` | Device not in user's profile | Medium (7.3%) |
| 5 | `typing_speed_anomaly` | Typing pattern deviation | Medium (6.3%) |
| 6 | `ip_risk` | New/unknown IP address | Medium (6.2%) |
| 7 | `unusual_hour` | Login between 12AM-5AM | Low (5.7%) |

Feature importances from the trained Random Forest model.

---

## System Workflow

```
User enters username + password + device ID
          ↓
JavaScript tracks typing speed (biometrics)
          ↓
System checks hashed password (SHA-256)
          ↓
System extracts 7 behavioral features
  (failed attempts, interval, device, hour, IP, typing, password)
          ↓
Random Forest ML model predicts: Low / Medium / High risk
          ↓
Low risk  → Email OTP verification
Medium    → 3-second delay + Email OTP
High risk → Temporary account block (60s)
          ↓
After 2 failed attempts → CAPTCHA required
After 5 failed attempts → Temporary block
          ↓
If OTP correct → Access Granted (shown with full security report)
Else → Access Denied
```

---

## Mitigation Mechanisms

### A. Password + Multi-Factor Authentication
Even if an attacker guesses the password, they need the OTP sent to the user's real email. This prevents credential stuffing and brute-force from succeeding.

### B. AI/ML-Based Suspicious Login Detection
The Random Forest classifier analyzes 7 behavioral features to estimate risk in real-time, replacing the basic rule-based engine with a trained ML model.

### C. CAPTCHA After Repeated Failures
After 2 failed attempts, a math-based CAPTCHA is required. This prevents automated tools from rapidly guessing passwords.

### D. Delay for Medium Risk
Suspicious but not critical logins are delayed by 3 seconds, significantly slowing down automated attacks.

### E. Temporary Blocking for High Risk
Repeated guessing or high-risk behavior triggers a 60-second account lock, cutting off the attacker's guess budget.

### F. IP Address Tracking
New/unknown IP addresses are flagged as a risk feature. Known IPs are registered after successful login.

### G. Behavioral Biometrics (Typing Speed)
The system monitors typing speed and compares it against the user's historical profile. Significant deviations (>2 standard deviations) are flagged as anomalous, helping detect bots or different users.

---

## Folder Structure

```
project/
├── app.py                         # Main Flask application (all 7 improvements)
├── train_model.py                 # ML model training script
├── requirements.txt               # Python dependencies
├── users.json                     # User database (auto-created, hashed passwords)
├── otp_store.json                 # OTP storage (auto-created)
├── login_log.json                 # Audit log (auto-created)
├── ml_model/
│   ├── risk_model.pkl             # Trained Random Forest model
│   ├── decision_tree_model.pkl    # Trained Decision Tree model
│   └── training_data.csv          # 5000-sample synthetic training dataset
├── templates/
│   ├── login.html                 # Login (with toggle, CAPTCHA, biometrics)
│   ├── otp.html                   # OTP verification
│   ├── blocked.html               # Account blocked
│   ├── success.html               # Success (full security report)
│   └── dashboard.html             # Audit log dashboard
├── static/
│   └── style.css                  # Cybersecurity dark theme
└── README.md
```

---

## Connection to Assignment 1 

This implementation directly addresses findings from the reviewed papers:

- **GuessFuse (Xie et al., 2024)**: Our ML risk engine mirrors how attackers fuse multiple guessing strategies. By using similar feature analysis defensively, we can detect and respond to these attack patterns.

- **NIST Guidelines**: Rate limiting (temporary blocking) as the primary defense against online attacks, which our system implements at 5 failed attempts.

- **Yusop et al. (2025)**: Addresses the limitation of human memory in password-based auth by adding MFA as a second layer, ensuring even guessed passwords aren't sufficient.

- **Kim & Lee (2024)**: Adaptive evaluation using ML rather than fixed rules, similar to how our Random Forest provides probabilistic risk scoring instead of rigid thresholds.

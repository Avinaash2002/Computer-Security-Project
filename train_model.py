"""
train_model.py — Train ML Classifiers for Suspicious Login Detection
TMS4853 Computer Security | UNIMAS

==========================================================================
DATA GENERATION METHODOLOGY
==========================================================================
No single public dataset provides all seven login-behavior features used
in this system. Existing datasets such as the LANL Comprehensive Cyber-
Security Events dataset (Kent, 2015) contain authentication logs with
timestamps, users, and success/failure, but lack device profiling, typing
biometrics, and per-session risk labels.

Following established practice in risk-based authentication research
(Wiefling et al., 2022; Freeman et al., 2016), we generate scenario-based
synthetic data that models realistic attack and legitimate login patterns.
Each scenario is parameterized using thresholds and behaviors documented
in published literature and standards:

  - NIST SP 800-63B (2017; Rev.4 2025): Rate limiting at ≤100 failed
    attempts, progressive delays, CAPTCHA after repeated failures,
    IP whitelisting for known addresses.

  - Xie et al. (2024) [GuessFuse]: Attackers generate high-probability
    guesses at scale; offline attacks can reach 10^7 guesses; different
    models capture different "views" of the password space.

  - Dunmore et al. (2023): PassGAN matched 51-71% of Hashcat passwords
    after training on RockYou (~14M leaked passwords), demonstrating
    realistic automated guessing at high speed.

  - Yusop et al. (2025): Human memory limits cause credential reuse
    across platforms, enabling credential stuffing with known pairs.

  - Wiefling et al. (2022): Risk-based authentication uses IP address,
    user agent, and geolocation as primary features; unknown features
    elevate risk scores.

  - Kim & Lee (2024): Adaptive password evaluation detects personally
    identifiable information (PI) and weak passwords missed by
    traditional rule-based metrics.

SCENARIO CATEGORIES:
  1. Legitimate user (normal behavior)
  2. Legitimate user (unusual conditions — travel, new device, late hours)
  3. Brute-force attack (rapid repeated guessing, Dunmore et al., 2023)
  4. Dictionary / AI-guided attack (GuessFuse-style, Xie et al., 2024)
  5. Credential stuffing (reused stolen credentials, Yusop et al., 2025)
  6. Slow / distributed attack (evasion of rate limiting)
  7. Bot / automated attack (inhuman typing speed patterns)

REFERENCES:
  Dunmore, A., Jang-Jaccard, J., Sabrina, F., & Kwak, J. (2023). A
    comprehensive survey of generative adversarial networks (GANs) in
    cybersecurity intrusion detection. IEEE Access, 11, 64018-64044.
  Kent, A.D. (2015). Comprehensive, Multi-Source Cyber-Security Events.
    Los Alamos National Laboratory. doi:10.17021/1179829
  Kim, S.J. & Lee, B.M. (2024). A novel approach to password strength
    evaluation using ChatGPT-based prompt metrics. IEEE Access.
  NIST (2017). SP 800-63B: Digital Identity Guidelines: Authentication
    and Lifecycle Management. doi:10.6028/NIST.SP.800-63b
  Wiefling, S., Jorgensen, P.R., Thunem, S., & Lo Iacono, L. (2022).
    Pump up password security! Evaluating and enhancing risk-based
    authentication on a real-world large-scale online service. ACM TOPS.
  Xie, Z., Shi, F., Zhang, M., et al. (2024). GuessFuse: Hybrid
    password guessing with multi-view. IEEE TIFS.
  Yusop, M.I.M., et al. (2025). Advancing passwordless authentication:
    A systematic review. IEEE Access, 13, 13919-13943.
==========================================================================

Features:
  1. failed_attempts        — consecutive failed logins for this user
  2. short_interval         — 1 if attempts < 5 seconds apart
  3. unknown_device         — 1 if device is not in user's profile
  4. unusual_hour           — 1 if login is between 12AM-5AM
  5. password_match         — 1 if password is correct
  6. ip_risk                — 1 if IP address is new/unknown for this user
  7. typing_speed_anomaly   — 1 if typing speed deviates > 2σ from profile

Labels:
  0 = Low risk    → proceed to MFA (OTP)
  1 = Medium risk → apply delay (3s) + MFA
  2 = High risk   → temporary account block
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier, export_text
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
import pickle
import os


# ============================================================
# SCENARIO-BASED DATA GENERATION
# ============================================================

def generate_scenario_data(n_total=6000, seed=42):
    """
    Generate login attempt data using 7 realistic scenarios.
    Each scenario produces feature vectors consistent with documented
    attack patterns or legitimate user behaviors.
    """
    np.random.seed(seed)
    records = []

    # Distribution: ~50% legitimate, ~50% various attacks
    # This reflects a system under active probing where defenders
    # need to distinguish real users from attackers.
    scenario_weights = {
        "legitimate_normal":     int(n_total * 0.30),
        "legitimate_unusual":    int(n_total * 0.10),
        "brute_force":           int(n_total * 0.15),
        "dictionary_ai_guided":  int(n_total * 0.15),
        "credential_stuffing":   int(n_total * 0.10),
        "slow_distributed":      int(n_total * 0.10),
        "bot_automated":         int(n_total * 0.10),
    }

    # -------------------------------------------------------
    # SCENARIO 1: Legitimate user, normal conditions
    # -------------------------------------------------------
    # Real user on known device, known IP, normal hours, correct password.
    # Expected: LOW risk
    for _ in range(scenario_weights["legitimate_normal"]):
        records.append({
            "failed_attempts":       np.random.choice([0, 0, 0, 1], p=[0.7, 0.15, 0.1, 0.05]),
            "short_interval":        0,
            "unknown_device":        0,
            "unusual_hour":          0,
            "password_match":        1,
            "ip_risk":               0,
            "typing_speed_anomaly":  0,
            "risk_label":            0  # Low
        })

    # -------------------------------------------------------
    # SCENARIO 2: Legitimate user, unusual conditions
    # -------------------------------------------------------
    # User traveling (new IP), new device, or late hours.
    # Still enters correct password with normal typing.
    # Expected: LOW to MEDIUM risk (triggers extra verification)
    # Based on Wiefling et al. (2022): unknown IP/UA elevates RBA score
    for _ in range(scenario_weights["legitimate_unusual"]):
        new_ip = np.random.choice([0, 1], p=[0.3, 0.7])
        new_device = np.random.choice([0, 1], p=[0.4, 0.6])
        late_hour = np.random.choice([0, 1], p=[0.5, 0.5])
        # Legitimate users sometimes mistype once or twice
        fails = np.random.choice([0, 1, 2], p=[0.5, 0.35, 0.15])

        # If multiple unusual signals, medium; otherwise low
        unusual_count = new_ip + new_device + late_hour
        label = 1 if unusual_count >= 2 else 0

        records.append({
            "failed_attempts":       fails,
            "short_interval":        0,
            "unknown_device":        new_device,
            "unusual_hour":          late_hour,
            "password_match":        1,
            "ip_risk":               new_ip,
            "typing_speed_anomaly":  0,  # Real user types normally
            "risk_label":            label
        })

    # -------------------------------------------------------
    # SCENARIO 3: Brute-force attack
    # -------------------------------------------------------
    # Rapid repeated attempts, wrong passwords, unknown device/IP.
    # Dunmore et al. (2023): automated tools try many passwords quickly.
    # NIST SP 800-63B: should be rate-limited after consecutive failures.
    # Expected: HIGH risk
    for _ in range(scenario_weights["brute_force"]):
        records.append({
            "failed_attempts":       np.random.randint(3, 9),  # Many failures
            "short_interval":        1,  # Rapid — automated tool
            "unknown_device":        1,  # Attacker's machine
            "unusual_hour":          np.random.choice([0, 1], p=[0.4, 0.6]),
            "password_match":        0,  # Guessing wrong passwords
            "ip_risk":               1,  # Unknown IP
            "typing_speed_anomaly":  1,  # Automated = abnormal speed
            "risk_label":            2   # High
        })

    # -------------------------------------------------------
    # SCENARIO 4: Dictionary / AI-guided attack (GuessFuse-style)
    # -------------------------------------------------------
    # Xie et al. (2024): AI models generate high-probability guesses.
    # Fewer attempts than brute force but more targeted.
    # Attacker may occasionally guess correctly due to AI optimization.
    # Expected: MEDIUM to HIGH risk
    for _ in range(scenario_weights["dictionary_ai_guided"]):
        # AI-guided attackers are more efficient — fewer but smarter guesses
        fails = np.random.randint(1, 5)
        # Occasionally the AI model guesses correctly (Xie et al. report
        # 0.09%–7.73% improvement in cracking rate over baselines)
        pw_correct = np.random.choice([0, 1], p=[0.85, 0.15])

        # Not as rapid as brute force — more deliberate
        rapid = np.random.choice([0, 1], p=[0.4, 0.6])

        label = 2 if (fails >= 3 or rapid == 1) else 1

        records.append({
            "failed_attempts":       fails,
            "short_interval":        rapid,
            "unknown_device":        1,  # Attacker's device
            "unusual_hour":          np.random.choice([0, 1], p=[0.5, 0.5]),
            "password_match":        pw_correct,
            "ip_risk":               1,
            "typing_speed_anomaly":  np.random.choice([0, 1], p=[0.3, 0.7]),
            "risk_label":            label
        })

    # -------------------------------------------------------
    # SCENARIO 5: Credential stuffing
    # -------------------------------------------------------
    # Yusop et al. (2025): attacker uses username+password pairs from
    # breaches. Correct password on first try but from unknown device/IP.
    # Expected: MEDIUM risk (correct password, but suspicious context)
    for _ in range(scenario_weights["credential_stuffing"]):
        records.append({
            "failed_attempts":       0,  # Has the real credentials
            "short_interval":        np.random.choice([0, 1], p=[0.5, 0.5]),
            "unknown_device":        1,  # Attacker's device
            "unusual_hour":          np.random.choice([0, 1], p=[0.6, 0.4]),
            "password_match":        1,  # Stolen correct password
            "ip_risk":               1,  # Unknown IP
            "typing_speed_anomaly":  np.random.choice([0, 1], p=[0.4, 0.6]),
            "risk_label":            1   # Medium — MFA should catch this
        })

    # -------------------------------------------------------
    # SCENARIO 6: Slow / distributed attack
    # -------------------------------------------------------
    # Attacker spaces attempts to evade rate limiting.
    # NIST SP 800-63B: rate limiting alone may not catch slow attacks.
    # Expected: LOW to MEDIUM risk (harder to detect)
    for _ in range(scenario_weights["slow_distributed"]):
        fails = np.random.randint(1, 4)
        records.append({
            "failed_attempts":       fails,
            "short_interval":        0,  # Deliberately slow
            "unknown_device":        np.random.choice([0, 1], p=[0.3, 0.7]),
            "unusual_hour":          np.random.choice([0, 1], p=[0.5, 0.5]),
            "password_match":        0,  # Still guessing
            "ip_risk":               1,  # Different IP each time
            "typing_speed_anomaly":  np.random.choice([0, 1], p=[0.5, 0.5]),
            "risk_label":            1 if fails >= 2 else 0
        })

    # -------------------------------------------------------
    # SCENARIO 7: Bot / automated tool
    # -------------------------------------------------------
    # Mirsky et al. (2023): classify password guessing as "offensive AI."
    # Inhuman typing speed is the strongest signal.
    # Expected: HIGH risk
    for _ in range(scenario_weights["bot_automated"]):
        records.append({
            "failed_attempts":       np.random.randint(2, 7),
            "short_interval":        1,  # Automated = rapid
            "unknown_device":        1,
            "unusual_hour":          np.random.choice([0, 1], p=[0.3, 0.7]),
            "password_match":        np.random.choice([0, 1], p=[0.9, 0.1]),
            "ip_risk":               1,
            "typing_speed_anomaly":  1,  # KEY: bot typing pattern
            "risk_label":            2   # High
        })

    df = pd.DataFrame(records)
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)
    return df


# ============================================================
# TRAIN AND EVALUATE
# ============================================================
def train_models():
    print("=" * 65)
    print("  ML Model Training — Suspicious Login Detection")
    print("  TMS4853 Computer Security | UNIMAS")
    print("=" * 65)
    print()
    print("  Data: Scenario-based simulation derived from attack models")
    print("         documented in the reviewed literature.")
    print("  Sources: NIST SP 800-63B, Xie et al. (2024), Dunmore et al.")
    print("           (2023), Yusop et al. (2025), Wiefling et al. (2022)")
    print()

    df = generate_scenario_data(n_total=6000)

    label_names = {0: "Low", 1: "Medium", 2: "High"}
    print(f"  Total samples: {len(df)}")
    print(f"  Label distribution:")
    for label, count in df["risk_label"].value_counts().sort_index().items():
        print(f"    {label_names[label]:8s} (class {label}): {count:5d} ({count/len(df)*100:.1f}%)")
    print()

    print("  Scenario breakdown:")
    print("    30% — Legitimate normal logins")
    print("    10% — Legitimate unusual conditions (travel, new device)")
    print("    15% — Brute-force attacks (Dunmore et al., 2023)")
    print("    15% — Dictionary/AI-guided attacks (Xie et al., 2024)")
    print("    10% — Credential stuffing (Yusop et al., 2025)")
    print("    10% — Slow/distributed attacks (NIST evasion)")
    print("    10% — Bot/automated attacks (Mirsky et al., 2023)")
    print()

    X = df.drop("risk_label", axis=1)
    y = df["risk_label"]
    feature_names = X.columns.tolist()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # --- Decision Tree ---
    print("-" * 50)
    print("  Model 1: Decision Tree Classifier")
    print("-" * 50)
    dt = DecisionTreeClassifier(max_depth=8, min_samples_split=10, random_state=42)
    dt.fit(X_train, y_train)
    dt_acc = dt.score(X_test, y_test)
    dt_cv = cross_val_score(dt, X, y, cv=5)
    print(f"  Test Accuracy:      {dt_acc:.4f} ({dt_acc*100:.1f}%)")
    print(f"  Cross-Val Accuracy: {dt_cv.mean():.4f} ± {dt_cv.std():.4f}")
    print()
    print(classification_report(y_test, dt.predict(X_test),
          target_names=["Low", "Medium", "High"], digits=3))

    # Print tree rules (first 30 lines)
    tree_rules = export_text(dt, feature_names=feature_names, max_depth=4)
    print("  Decision Tree Rules (top levels):")
    for line in tree_rules.split("\n")[:20]:
        print(f"    {line}")
    print("    ...")
    print()

    # --- Random Forest ---
    print("-" * 50)
    print("  Model 2: Random Forest Classifier (100 trees)")
    print("-" * 50)
    rf = RandomForestClassifier(
        n_estimators=100, max_depth=10, min_samples_split=10,
        random_state=42, n_jobs=-1
    )
    rf.fit(X_train, y_train)
    rf_acc = rf.score(X_test, y_test)
    rf_cv = cross_val_score(rf, X, y, cv=5)
    print(f"  Test Accuracy:      {rf_acc:.4f} ({rf_acc*100:.1f}%)")
    print(f"  Cross-Val Accuracy: {rf_cv.mean():.4f} ± {rf_cv.std():.4f}")
    print()
    print(classification_report(y_test, rf.predict(X_test),
          target_names=["Low", "Medium", "High"], digits=3))

    # Feature importances
    importances = rf.feature_importances_
    print("  Feature Importances (Random Forest):")
    print("  " + "-" * 48)
    for name, imp in sorted(zip(feature_names, importances), key=lambda x: -x[1]):
        bar = "█" * int(imp * 50)
        print(f"    {name:25s} {imp:.4f}  {bar}")
    print()

    # Confusion Matrix
    print("  Confusion Matrix (Random Forest):")
    cm = confusion_matrix(y_test, rf.predict(X_test))
    print(f"                    Predicted")
    print(f"                    Low   Med   High")
    for i, row_label in enumerate(["Low", "Med", "High"]):
        print(f"    Actual {row_label:4s}  {cm[i]}")
    print()

    # --- Save models ---
    base_dir = os.path.dirname(os.path.abspath(__file__))
    ml_dir = os.path.join(base_dir, "ml_model")
    os.makedirs(ml_dir, exist_ok=True)

    with open(os.path.join(ml_dir, "risk_model.pkl"), "wb") as f:
        pickle.dump(rf, f)
    print("  ✓ Random Forest saved  → ml_model/risk_model.pkl")

    with open(os.path.join(ml_dir, "decision_tree_model.pkl"), "wb") as f:
        pickle.dump(dt, f)
    print("  ✓ Decision Tree saved  → ml_model/decision_tree_model.pkl")

    df.to_csv(os.path.join(ml_dir, "training_data.csv"), index=False)
    print("  ✓ Training data saved  → ml_model/training_data.csv")

    # Save scenario documentation
    doc = """TRAINING DATA DOCUMENTATION
============================

This dataset contains {n} synthetic login attempt records generated
using scenario-based simulation. Each scenario models a realistic
attack pattern or legitimate user behavior documented in published
cybersecurity literature.

SCENARIOS AND CITATIONS:
1. Legitimate normal (30%) — Baseline normal user behavior
2. Legitimate unusual (10%) — User on new device/IP/late hour
   → Wiefling et al. (2022): unknown features elevate RBA scores
3. Brute-force attack (15%) — Rapid repeated wrong passwords
   → Dunmore et al. (2023): automated tools try many passwords quickly
   → NIST SP 800-63B: rate limit at ≤100 consecutive failures
4. Dictionary/AI-guided (15%) — Targeted guessing with fewer attempts
   → Xie et al. (2024): GuessFuse improves cracking by 0.09-7.73%
5. Credential stuffing (10%) — Correct stolen password, unknown context
   → Yusop et al. (2025): reused credentials from breach databases
6. Slow/distributed (10%) — Spaced attempts to evade rate limiting
   → NIST SP 800-63B: rate limiting alone may not detect slow attacks
7. Bot/automated (10%) — Inhuman typing patterns, rapid attempts
   → Mirsky et al. (2023): "offensive AI" for password guessing

FEATURES (7):
  failed_attempts, short_interval, unknown_device, unusual_hour,
  password_match, ip_risk, typing_speed_anomaly

LABELS (3):
  0 = Low risk, 1 = Medium risk, 2 = High risk

FULL REFERENCES:
  Dunmore, A. et al. (2023). IEEE Access, 11, 64018-64044.
  Kent, A.D. (2015). doi:10.17021/1179829 (LANL dataset reference)
  Kim, S.J. & Lee, B.M. (2024). IEEE Access.
  Mirsky, Y. et al. (2023). Computers & Security, 124.
  NIST (2017). SP 800-63B. doi:10.6028/NIST.SP.800-63b
  Wiefling, S. et al. (2022). ACM TOPS.
  Xie, Z. et al. (2024). IEEE TIFS.
  Yusop, M.I.M. et al. (2025). IEEE Access, 13, 13919-13943.
""".format(n=len(df))

    with open(os.path.join(ml_dir, "DATA_DOCUMENTATION.txt"), "w", encoding="utf-8") as f:
        f.write(doc)
    print("  ✓ Documentation saved  → ml_model/DATA_DOCUMENTATION.txt")

    print()
    print("=" * 65)
    best = "Random Forest" if rf_acc >= dt_acc else "Decision Tree"
    best_acc = max(rf_acc, dt_acc)
    print(f"  Training complete. Best model: {best} ({best_acc*100:.1f}%)")
    print("=" * 65)

    return rf


if __name__ == "__main__":
    train_models()

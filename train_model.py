'''/******************************************************************************
* FILE      : train_model.py
* Name      : Avinaash Loganathan
* Matric    : 83321
* Due Date  : 25 May 2026
* Project   : TMS4853 Computer Security
*
* How to execute:
*   1. Open terminal / command prompt
*   2. Navigate to the project directory
*   3. Install required libraries:
*        pip install numpy pandas scikit-learn
*   4. Run the training script:
*        python train_model.py
*
* DESCRIPTION:
*  This program trains machine learning classifiers for suspicious
*  login detection using scenario-based synthetic cybersecurity data.
*
*  The system simulates multiple authentication scenarios including:
*     - Legitimate user logins
*     - Brute-force attacks
*     - Credential stuffing
*     - AI-guided password guessing
*     - Slow/distributed attacks
*     - Automated bot behavior
*
*  Two machine learning models are trained:
*     1. Decision Tree Classifier
*     2. Random Forest Classifier
*
*  The models classify login attempts into:
*     0 = Low Risk
*     1 = Medium Risk
*     2 = High Risk
*
* Output:
*   - Console:
*       1. Model performance metrics
*       2. Classification report
*       3. Cross-validation accuracy
*       4. Confusion matrix
*       5. Feature importance ranking
*
*   - Saved Files:
*       1. ml_model/risk_model.pkl
*       2. ml_model/decision_tree_model.pkl
*       3. ml_model/training_data.csv
*
* LAST REVISED: 21/05/26
******************************************************************************/'''

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier, export_text
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
import pickle
import os

# SCENARIO-BASED DATA GENERATION

def generate_scenario_data(n_total=6000, seed=42):
    """
    Generate synthetic login-attempt records based on realistic
    cybersecurity attack and authentication scenarios.

    Each generated row represents one login session with:
      - User behavior indicators
      - Device/IP characteristics
      - Timing information
      - Risk classification label
    """

    # Set random seed for reproducibility
    np.random.seed(seed)

    # Store generated login records
    records = []
    
    # Scenario distribution
    # Roughly 50% legitimate traffic and 50% suspicious traffic.
    # This simulates an actively targeted authentication system.
    scenario_weights = {
        "legitimate_normal":     int(n_total * 0.30),
        "legitimate_unusual":    int(n_total * 0.10),
        "brute_force":           int(n_total * 0.15),
        "dictionary_ai_guided":  int(n_total * 0.15),
        "credential_stuffing":   int(n_total * 0.10),
        "slow_distributed":      int(n_total * 0.10),
        "bot_automated":         int(n_total * 0.10),
    }

    # SCENARIO 1:
    # Legitimate user under normal conditions
    # User logs in from:
    #   - known device
    #   - trusted IP address
    #   - normal active hours
    # Expected classification:
    # LOW risk
    for _ in range(scenario_weights["legitimate_normal"]):

        # Small chance of typing mistakes
        failed_attempts = np.random.choice(
            [0, 0, 0, 1],
            p=[0.7, 0.15, 0.1, 0.05]
        )

        records.append({
            "failed_attempts":       failed_attempts,
            "short_interval":        0,
            "unknown_device":        0,
            "unusual_hour":          0,
            "password_match":        1,
            "ip_risk":               0,
            "typing_speed_anomaly":  0,
            "risk_label":            0
        })

    # SCENARIO 2:
    # Legitimate user under unusual conditions
    # Example:
    #   - User travelling overseas
    #   - New device
    #   - Login late at night
    #
    # Real users still type normally and usually know
    # the correct password.
    for _ in range(scenario_weights["legitimate_unusual"]):

        new_ip = np.random.choice([0, 1], p=[0.3, 0.7])
        new_device = np.random.choice([0, 1], p=[0.4, 0.6])
        late_hour = np.random.choice([0, 1], p=[0.5, 0.5])

        # Genuine users may mistype once or twice
        fails = np.random.choice([0, 1, 2], p=[0.5, 0.35, 0.15])

        # More unusual signals increase risk level
        unusual_count = new_ip + new_device + late_hour
        label = 1 if unusual_count >= 2 else 0

        records.append({
            "failed_attempts":       fails,
            "short_interval":        0,
            "unknown_device":        new_device,
            "unusual_hour":          late_hour,
            "password_match":        1,
            "ip_risk":               new_ip,
            "typing_speed_anomaly":  0,
            "risk_label":            label
        })

    # SCENARIO 3:
    # Brute-force attack simulation
    # Characteristics:
    #   - Many failed attempts
    #   - Rapid login frequency
    #   - Unknown IP/device
    #   - Automated typing pattern
    for _ in range(scenario_weights["brute_force"]):

        records.append({
            "failed_attempts":       np.random.randint(3, 9),
            "short_interval":        1,
            "unknown_device":        1,
            "unusual_hour":          np.random.choice([0, 1], p=[0.4, 0.6]),
            "password_match":        0,
            "ip_risk":               1,
            "typing_speed_anomaly":  1,
            "risk_label":            2
        })

    # SCENARIO 4:
    # AI-guided / dictionary-based attack
    # More targeted compared to brute-force attacks.
    # Fewer attempts but more intelligent guessing.
    for _ in range(scenario_weights["dictionary_ai_guided"]):

        fails = np.random.randint(1, 5)

        # AI models occasionally guess correctly
        pw_correct = np.random.choice([0, 1], p=[0.85, 0.15])

        rapid = np.random.choice([0, 1], p=[0.4, 0.6])

        label = 2 if (fails >= 3 or rapid == 1) else 1

        records.append({
            "failed_attempts":       fails,
            "short_interval":        rapid,
            "unknown_device":        1,
            "unusual_hour":          np.random.choice([0, 1], p=[0.5, 0.5]),
            "password_match":        pw_correct,
            "ip_risk":               1,
            "typing_speed_anomaly":  np.random.choice([0, 1], p=[0.3, 0.7]),
            "risk_label":            label
        })

    # SCENARIO 5:
    # Credential stuffing attack
    # Attacker already possesses stolen credentials.
    # Password may be correct on first attempt.
    for _ in range(scenario_weights["credential_stuffing"]):

        records.append({
            "failed_attempts":       0,
            "short_interval":        np.random.choice([0, 1], p=[0.5, 0.5]),
            "unknown_device":        1,
            "unusual_hour":          np.random.choice([0, 1], p=[0.6, 0.4]),
            "password_match":        1,
            "ip_risk":               1,
            "typing_speed_anomaly":  np.random.choice([0, 1], p=[0.4, 0.6]),
            "risk_label":            1
        })

    # SCENARIO 6:
    # Slow / distributed attack
    # Attacker intentionally avoids rapid requests
    # to bypass rate-limiting systems.
    for _ in range(scenario_weights["slow_distributed"]):

        fails = np.random.randint(1, 4)

        records.append({
            "failed_attempts":       fails,
            "short_interval":        0,
            "unknown_device":        np.random.choice([0, 1], p=[0.3, 0.7]),
            "unusual_hour":          np.random.choice([0, 1], p=[0.5, 0.5]),
            "password_match":        0,
            "ip_risk":               1,
            "typing_speed_anomaly":  np.random.choice([0, 1], p=[0.5, 0.5]),
            "risk_label":            1 if fails >= 2 else 0
        })

    # SCENARIO 7:
    # Automated bot attack
    # Main indicator:
    #   abnormal typing speed patterns
    for _ in range(scenario_weights["bot_automated"]):

        records.append({
            "failed_attempts":       np.random.randint(2, 7),
            "short_interval":        1,
            "unknown_device":        1,
            "unusual_hour":          np.random.choice([0, 1], p=[0.3, 0.7]),
            "password_match":        np.random.choice([0, 1], p=[0.9, 0.1]),
            "ip_risk":               1,
            "typing_speed_anomaly":  1,
            "risk_label":            2
        })

    # Convert records into DataFrame
    df = pd.DataFrame(records)

    # Shuffle rows to avoid ordered patterns
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)

    return df

# TRAINING AND MODEL EVALUATION

def train_models():

    print("=" * 65)
    print("  ML Model Training — Suspicious Login Detection")
    print("  TMS4853 Computer Security | UNIMAS")
    print("=" * 65)
    print()

    # Generate training dataset
    df = generate_scenario_data(n_total=6000)

    label_names = {
        0: "Low",
        1: "Medium",
        2: "High"
    }

    # Display dataset statistics
    print(f"  Total samples: {len(df)}")
    print(f"  Label distribution:")

    for label, count in df["risk_label"].value_counts().sort_index().items():
        print(
            f"    {label_names[label]:8s} "
            f"(class {label}): {count:5d} "
            f"({count/len(df)*100:.1f}%)"
        )

    print()

    # Separate features and labels
    X = df.drop("risk_label", axis=1)
    y = df["risk_label"]

    feature_names = X.columns.tolist()

    # Split into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    # MODEL 1 — DECISION TREE

    print("-" * 50)
    print("  Model 1: Decision Tree Classifier")
    print("-" * 50)

    dt = DecisionTreeClassifier(
        max_depth=8,
        min_samples_split=10,
        random_state=42
    )

    # Train Decision Tree
    dt.fit(X_train, y_train)

    # Evaluate model accuracy
    dt_acc = dt.score(X_test, y_test)

    # Perform 5-fold cross validation
    dt_cv = cross_val_score(dt, X, y, cv=5)

    print(f"  Test Accuracy:      {dt_acc:.4f} ({dt_acc*100:.1f}%)")
    print(f"  Cross-Val Accuracy: {dt_cv.mean():.4f} ± {dt_cv.std():.4f}")
    print()

    # Display classification metrics
    print(classification_report(
        y_test,
        dt.predict(X_test),
        target_names=["Low", "Medium", "High"],
        digits=3
    ))

    # Export simplified tree rules
    tree_rules = export_text(
        dt,
        feature_names=feature_names,
        max_depth=4
    )

    print("  Decision Tree Rules (top levels):")

    for line in tree_rules.split("\n")[:20]:
        print(f"    {line}")

    print("    ...")
    print()

    # MODEL 2 — RANDOM FOREST

    print("-" * 50)
    print("  Model 2: Random Forest Classifier (100 trees)")
    print("-" * 50)

    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=10,
        random_state=42,
        n_jobs=-1
    )

    # Train Random Forest
    rf.fit(X_train, y_train)

    rf_acc = rf.score(X_test, y_test)

    # Cross-validation evaluation
    rf_cv = cross_val_score(rf, X, y, cv=5)

    print(f"  Test Accuracy:      {rf_acc:.4f} ({rf_acc*100:.1f}%)")
    print(f"  Cross-Val Accuracy: {rf_cv.mean():.4f} ± {rf_cv.std():.4f}")
    print()

    print(classification_report(
        y_test,
        rf.predict(X_test),
        target_names=["Low", "Medium", "High"],
        digits=3
    ))

    # Feature importance analysis

    importances = rf.feature_importances_

    print("  Feature Importances (Random Forest):")
    print("  " + "-" * 48)

    for name, imp in sorted(
        zip(feature_names, importances),
        key=lambda x: -x[1]
    ):

        bar = "█" * int(imp * 50)

        print(f"    {name:25s} {imp:.4f}  {bar}")

    print()

    # Confusion matrix
    
    print("  Confusion Matrix (Random Forest):")

    cm = confusion_matrix(y_test, rf.predict(X_test))

    print(f"                    Predicted")
    print(f"                    Low   Med   High")

    for i, row_label in enumerate(["Low", "Med", "High"]):
        print(f"    Actual {row_label:4s}  {cm[i]}")

    print()

    # SAVE TRAINED MODELS

    base_dir = os.path.dirname(os.path.abspath(__file__))

    ml_dir = os.path.join(base_dir, "ml_model")

    # Create directory if it does not exist
    os.makedirs(ml_dir, exist_ok=True)

    # Save Random Forest model
    with open(os.path.join(ml_dir, "risk_model.pkl"), "wb") as f:
        pickle.dump(rf, f)

    print("  ✓ Random Forest saved  → ml_model/risk_model.pkl")

    # Save Decision Tree model
    with open(os.path.join(ml_dir, "decision_tree_model.pkl"), "wb") as f:
        pickle.dump(dt, f)

    print("  ✓ Decision Tree saved  → ml_model/decision_tree_model.pkl")

    # Save generated training dataset
    df.to_csv(os.path.join(ml_dir, "training_data.csv"), index=False)

    print("  ✓ Training data saved  → ml_model/training_data.csv")

    print()
    print("=" * 65)

    best = "Random Forest" if rf_acc >= dt_acc else "Decision Tree"
    best_acc = max(rf_acc, dt_acc)

    print(f"  Training complete. Best model: {best} ({best_acc*100:.1f}%)")

    print("=" * 65)

    return rf

# main execution

if __name__ == "__main__":
    train_models()
    
    
    
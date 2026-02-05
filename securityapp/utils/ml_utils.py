import os
import pickle
import pandas as pd
from django.conf import settings

# ---------------------------
# Load ML Models
# ---------------------------
MODEL_PATH = os.path.join(settings.BASE_DIR, "securityapp", "ml_models", "model.pkl")

binary_model = None
attack_type_model = None

if os.path.exists(MODEL_PATH):
    with open(MODEL_PATH, "rb") as f:
        loaded = pickle.load(f)
    binary_model = loaded.get("model")
    attack_type_model = loaded.get("attack_type_model")
    print("✅ ML models loaded successfully")
else:
    print("⚠️ model.pkl not found — predictions will be skipped")

# ---------------------------
# Utility Functions
# ---------------------------
def map_binary_pred(pred):
    """Map model output (0/1 or Normal/Attack) to standardized label."""
    if pred in [1, "1", "Attack", "attack"]:
        return "Attack"
    return "Normal"

def prepare_features(data):
    """Convert form or API data into numeric features for ML model."""
    try:
        port = int(data.get("port", 80))
        protocol = 1 if data.get("protocol", "TCP").upper() == "TCP" else 0
        action = 1 if data.get("action", "ACCEPT").upper() == "ACCEPT" else 0
        packet_size = float(data.get("packet_size", 500))
        duration = float(data.get("duration", 1.0))
        login_attempts = int(data.get("login_attempts", 1))
        return [port, protocol, action, packet_size, duration, login_attempts]
    except Exception as e:
        print(f"⚠️ Feature preparation error: {e}")
        return [80, 1, 1, 500, 1.0, 1]

# ---------------------------
# Main Prediction Logic
# ---------------------------
def predict_attack(features):
    """Predict if input represents an attack and its type."""
    pred_label, attack_type, score = "Normal", "Normal", 1.0

    if not binary_model:
        print("⚠️ Binary model not loaded — skipping prediction")
        return pred_label, attack_type, score

    try:
        # Create DataFrame to avoid sklearn warnings
        columns = ["port", "protocol", "action", "packet_size", "duration", "login_attempts"]
        X_df = pd.DataFrame([features], columns=columns)

        # Predict Normal vs Attack
        raw_pred = binary_model.predict(X_df)[0]
        pred_label = map_binary_pred(raw_pred)

        # Confidence score (if model supports predict_proba)
        if hasattr(binary_model, "predict_proba"):
            proba = binary_model.predict_proba(X_df)[0]
            score = float(max(proba))

        # Predict attack type if needed
        if pred_label == "Attack":
            if attack_type_model:
                attack_type = str(attack_type_model.predict(X_df)[0])
            else:
                port, prot, act, pkt, dur, la = features
                if la >= 8:
                    attack_type = "Brute Force"
                elif pkt >= 1200 and dur < 0.6:
                    attack_type = "DDoS"
                elif pkt >= 1000 and dur < 0.2:
                    attack_type = "Flood"
                elif port < 1024 and pkt < 300:
                    attack_type = "Port Scan"
                else:
                    attack_type = "Unknown"

    except Exception as e:
        print(f"❌ Prediction error: {e}")

    return pred_label, attack_type, score

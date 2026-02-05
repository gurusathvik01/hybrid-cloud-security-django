import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import pickle

# -----------------------------
# 1️⃣ Generate Synthetic Dataset
# -----------------------------
np.random.seed(42)
num_samples = 1200

def generate_data(n, label, attack_type=None):
    data = {
        "port": np.random.choice([22, 80, 443, 8080, 3306, 25, 53], n),
        "protocol": np.random.choice(["TCP", "UDP"], n),
        "action": np.random.choice(["ACCEPT", "DROP"], n, p=[0.8, 0.2]),
        "packet_size": np.random.normal(500, 200, n).clip(50, 1500),
        "duration": np.random.exponential(scale=1.0, size=n),
        "login_attempts": np.random.poisson(2, n),
        "label": label,
        "attack_type": attack_type if attack_type else "Normal"
    }
    return pd.DataFrame(data)

# Normal traffic
df_normal = generate_data(400, "Normal")

# DDoS attack
df_ddos = generate_data(200, "Attack", "DDoS")
df_ddos["packet_size"] = np.random.normal(1400, 50, 200)
df_ddos["duration"] = np.random.exponential(scale=0.2, size=200)
df_ddos["login_attempts"] = np.random.poisson(1, 200)

# Flood attack
df_flood = generate_data(200, "Attack", "Flood")
df_flood["packet_size"] = np.random.normal(1300, 60, 200)
df_flood["duration"] = np.random.exponential(scale=0.1, size=200)
df_flood["login_attempts"] = np.random.poisson(1, 200)

# Port Scan
df_port = generate_data(200, "Attack", "Port Scan")
df_port["port"] = np.random.choice(range(20, 1024), 200)
df_port["duration"] = np.random.exponential(scale=0.5, size=200)
df_port["login_attempts"] = np.random.poisson(2, 200)

# Brute Force
df_brute = generate_data(200, "Attack", "Brute Force")
df_brute["login_attempts"] = np.random.poisson(8, 200)
df_brute["duration"] = np.random.exponential(scale=1.5, size=200)

# Combine all
df = pd.concat([df_normal, df_ddos, df_flood, df_port, df_brute], ignore_index=True)

# -----------------------------
# 2️⃣ Encode categorical values
# -----------------------------
df["protocol"] = df["protocol"].map({"TCP": 1, "UDP": 0})
df["action"] = df["action"].map({"ACCEPT": 1, "DROP": 0})

# -----------------------------
# 3️⃣ Train binary model (Attack vs Normal)
# -----------------------------
X = df[["port", "protocol", "action", "packet_size", "duration", "login_attempts"]]
y_binary = df["label"]

X_train, X_test, y_train, y_test = train_test_split(X, y_binary, test_size=0.2, random_state=42)
binary_model = RandomForestClassifier(n_estimators=150, random_state=42)
binary_model.fit(X_train, y_train)

print("✅ Binary Model (Normal/Attack) Performance:")
print(classification_report(y_test, binary_model.predict(X_test)))

# -----------------------------
# 4️⃣ Train multi-class model (Attack Type)
# -----------------------------
attack_df = df[df["label"] == "Attack"]
y_multi = attack_df["attack_type"]
X_multi = attack_df[["port", "protocol", "action", "packet_size", "duration", "login_attempts"]]

X_train_m, X_test_m, y_train_m, y_test_m = train_test_split(X_multi, y_multi, test_size=0.2, random_state=42)
multi_model = RandomForestClassifier(n_estimators=120, random_state=42)
multi_model.fit(X_train_m, y_train_m)

print("✅ Multi-class Model (Attack Type) Performance:")
print(classification_report(y_test_m, multi_model.predict(X_test_m)))

# -----------------------------
# 5️⃣ Save both models
# -----------------------------
model_data = {
    "model": binary_model,
    "attack_type_model": multi_model
}

with open("model.pkl", "wb") as f:
    pickle.dump(model_data, f)

print("\n🎯 Models trained and saved successfully as model.pkl")

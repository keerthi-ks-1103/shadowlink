import pandas as pd
import json
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder

def extract_logs(path):
    with open(path) as f:
        data = json.load(f)

    logs = []
    for sim in data.get("simulations", []):
        for attack in sim.get("attacks_executed", []):
            logs.append({
                "user": attack.get("user"),
                "action": attack.get("attack"),
                "success": attack.get("success"),
                "timestamp": attack.get("timestamp")
            })

    return logs

def train(path="data/logs/simulation_log.json", save="data/models/anomaly_pipeline.pkl"):
    logs = extract_logs(path)
    if not logs:
        raise ValueError("No logs extracted from simulation_log.json")

    df = pd.DataFrame(logs)

    # Use only 'user' and 'action' for anomaly detection
    required_cols = ['user', 'action']
    if not set(required_cols).issubset(df.columns):
        raise ValueError("Missing required columns from logs")

    X = df[required_cols]
    
    # Pipeline for encoding and isolation forest
    pipeline = Pipeline([
        ('pre', ColumnTransformer([
            ('cat', OneHotEncoder(handle_unknown='ignore'), required_cols)
        ])),
        ('iso', IsolationForest(n_estimators=100, contamination=0.1, random_state=42))
    ])

    pipeline.fit(X)
    joblib.dump(pipeline, save)
    print(f"[✓] Anomaly detection model trained and saved to {save}")

if __name__ == "__main__":
    train()

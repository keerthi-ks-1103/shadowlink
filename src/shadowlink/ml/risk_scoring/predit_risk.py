import joblib
from pathlib import Path
import pandas as pd

# Load model + encoders
MODEL_DIR = Path("data/models/")
model = joblib.load(MODEL_DIR / "risk_predictor.joblib")
target_encoder = joblib.load(MODEL_DIR / "risk_label_encoder.joblib")

encoders = {
    name: joblib.load(MODEL_DIR / f"{name}_encoder.joblib")
    for name in ["role", "action", "resource", "success"]
}

def predict_risk(log: dict) -> str:
    try:
        encoded = [[
            encoders["role"].transform([str(log["role"])])[0],
            encoders["action"].transform([str(log["action"])])[0],
            encoders["resource"].transform([str(log["resource"])])[0],
            encoders["success"].transform([str(log["success"])])[0]
        ]]
        df = pd.DataFrame(encoded, columns=["role", "action", "resource", "success"])
        pred_class = model.predict(df)[0]
        return target_encoder.inverse_transform([pred_class])[0]
    except Exception as e:
        return f"error: {str(e)}"

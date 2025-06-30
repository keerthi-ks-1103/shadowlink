# src/shadowlink/ml/risk_scoring/train_risk_model.py

import pandas as pd
import joblib
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report

# Load labeled dataset
data_path = "data/simulation_results.csv"
df = pd.read_csv(data_path)

# Drop rows with missing labels
df = df.dropna(subset=["risk_label"])

# Define categorical features and target
feature_cols = ["role", "action", "resource", "success"]
target_col = "risk_label"

# Encode features
label_encoders = {}
for col in feature_cols:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col].astype(str))
    label_encoders[col] = le

# Encode target
target_encoder = LabelEncoder()
df["risk_label_encoded"] = target_encoder.fit_transform(df[target_col])

# Prepare training and testing sets
X = df[feature_cols]
y = df["risk_label_encoded"]
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train the classifier
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate the model
y_pred = model.predict(X_test)
print("\n📊 Classification Report:")
print(classification_report(y_test, y_pred, target_names=target_encoder.classes_))

# Save the model and encoders
Path("data/models").mkdir(parents=True, exist_ok=True)
joblib.dump(model, "data/models/risk_predictor.joblib")
joblib.dump(target_encoder, "data/models/risk_label_encoder.joblib")

for col, le in label_encoders.items():
    joblib.dump(le, f"data/models/{col}_encoder.joblib")

print("\n✅ Model and encoders saved in data/models/")

# Optional test on a new log
example = {
    "role": "developer",
    "action": "login",
    "resource": "/finance/data1",
    "success":"True"
}

encoded = [[
    label_encoders["role"].transform([example["role"]])[0],
    label_encoders["action"].transform([example["action"]])[0],
    label_encoders["resource"].transform([example["resource"]])[0],
    label_encoders["success"].transform([example["success"]])[0],
]]

pred_class = model.predict(encoded)[0]
pred_label = target_encoder.inverse_transform([pred_class])[0]
print(f"\n🔐 Example Prediction: {pred_label}")
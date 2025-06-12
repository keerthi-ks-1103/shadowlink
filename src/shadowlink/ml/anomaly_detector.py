import joblib
import pandas as pd

model = joblib.load("data/models/anomaly_pipeline.pkl")

def is_anomaly(user, action):
    df = pd.DataFrame([{
        "user": user,
        "action": action
    }])
    return model.predict(df)[0] == -1
print(is_anomaly("user_005", "Brute Force"))   # Output: True or False

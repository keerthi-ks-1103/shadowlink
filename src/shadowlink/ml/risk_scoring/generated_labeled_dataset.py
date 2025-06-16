# src/shadowlink/ml/risk_scoring/generate_labeled_dataset.py

import json
import csv
from pathlib import Path
from datetime import datetime

def label_risk_from_behavior(entry):
    """
    Assign risk level based on user behavior log
    """
    action = entry.get("action", "")
    resource = entry.get("resource", "")
    success = entry.get("success", False)
    role = entry.get("role", "")

    if not success:
        return "low"

    # Examples of high-risk patterns
    if role == "admin" and action in ["delete", "upload"]:
        return "critical"
    if "finance" in resource or "payroll" in resource:
        return "high"
    if action in ["download", "upload"]:
        return "medium"
    if action == "change_password":
        return "medium"

    return "low"

def process_behavior_logs(log_path: str, output_csv: str):
    with open(log_path, "r") as infile:
        logs = json.load(infile)

    Path(output_csv).parent.mkdir(parents=True, exist_ok=True)

    with open(output_csv, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "user_id", "role", "action", "resource",
            "timestamp", "success", "risk_label"
        ])

        for log in logs:
            risk = label_risk_from_behavior(log)

            writer.writerow([
                log.get("user_id", ""),
                log.get("role", ""),
                log.get("action", ""),
                log.get("resource", ""),
                log.get("timestamp", datetime.now().isoformat()),
                log.get("success", False),
                risk
            ])

    print(f"✅ Behavior-labeled dataset saved to {output_csv}")

if __name__ == "__main__":
    log_file = "data/logs/synthetic_logs.json"
    output_file = "data/simulation_results.csv"
    process_behavior_logs(log_file, output_file)

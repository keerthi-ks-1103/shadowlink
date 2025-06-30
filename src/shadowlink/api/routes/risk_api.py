from fastapi import UploadFile, File, APIRouter, HTTPException
import csv
import io
from shadowlink.ml.risk_scoring.predit_risk import predict_risk
from shadowlink.ml.risk_scoring.remediation_engine import generate_remediation
from shadowlink.ml.risk_scoring.nl_description import generate_description

router = APIRouter()

@router.post("/upload_logs", summary="Upload a CSV of behavior logs and get risk analysis")
def upload_logs(file: UploadFile = File(...)):
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="File must be a CSV")

    content = file.file.read().decode("utf-8")
    reader = csv.DictReader(io.StringIO(content))
    results = []

    for row in reader:
        try:
            log = {
                "role": row["role"],
                "action": row["action"],
                "resource": row["resource"],
                "success": row["success"].strip().lower() == "true"
            }
            risk = predict_risk(log)
            remediation = generate_remediation(log, risk)
            description = generate_description(log, risk)

            results.append({
                "log": log,
                "risk": risk,
                "description": description,
                "remediation": remediation
            })
        except Exception as e:
            results.append({"log": row, "error": str(e)})

    return {"results": results}

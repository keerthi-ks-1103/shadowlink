import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from fastapi import APIRouter
from pydantic import BaseModel
from shadowlink.ml.risk_scoring.predit_risk import predict_risk
from shadowlink.ml.risk_scoring.remediation_engine import generate_remediation

router = APIRouter()  # ✅ This is what defines the route group

class BehaviorLog(BaseModel):
    role: str
    action: str
    resource: str
    success: bool  # ✅ This must be bool (not str)

@router.post("/predict")
def predict_risk_route(log: BehaviorLog):
    log_dict = log.dict()
    risk = predict_risk(log_dict)

    if isinstance(risk, str) and risk.startswith("error"):
        return {"error": risk}

    remediation = generate_remediation(log_dict, risk)
    return {
        "risk": risk,
        "remediation": remediation
    }

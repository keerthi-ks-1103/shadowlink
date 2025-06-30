# scripts/run_all.py
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

import random
from shadowlink.simulation.attacks.brute_force import BruteForceAttack
from shadowlink.core.iam.environment import load_iam_env
from shadowlink.ml.risk_scoring.predit_risk import predict_risk
from shadowlink.ml.risk_scoring.remediation_engine import generate_remediation

# Load environment
env = load_iam_env()

# Choose a random user
user_id = random.choice(list(env.users.keys()))

# Simulate attack
attack = BruteForceAttack()
result = attack.execute(env, user_id)

# Predict risk from result details
input_features = {
    "role": env.get_user(user_id).get("primary_role", "unknown"),
    "action": result.details.get("attack_method"),
    "resource": "/simulated/resource",
    "success": result.success
}
risk = predict_risk(input_features)
remediation = generate_remediation(input_features, risk)

# Output
print(f"\n🔍 Risk Prediction: {risk}")
print(f"🛠️ Remediation Suggestions:\n{remediation}")

import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.shadowlink.ml.anomaly_detector import is_anomaly
from src.shadowlink.ml.rl_agent import suggest_action

# Example input from a simulation log
example_user = "user_001"
example_attack = "Privilege Escalation"

print(f"\nTesting AI Engine on user: {example_user}, attack: {example_attack}\n")

# 1. Check for anomaly
is_anom = is_anomaly(example_user, example_attack)
print("→ Anomaly Detected?", is_anom)

# 2. Get RL-suggested next move
next_move = suggest_action(example_user)
print("→ RL Suggested Next Action:", next_move)

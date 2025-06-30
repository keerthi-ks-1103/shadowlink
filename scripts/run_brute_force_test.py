import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from shadowlink.simulation.attacks.brute_force import BruteForceAttack
from shadowlink.core.iam.env_loader import load_iam_env

# Load IAM environment
env = load_iam_env("data/mock_iam/environments/default.json")

# Run brute force attack on a test user
attack = BruteForceAttack()
result = attack.execute(env, "user_001")  # Replace with a valid user_id from your JSON

print("✅ Attack Result:")
print(result.to_dict())

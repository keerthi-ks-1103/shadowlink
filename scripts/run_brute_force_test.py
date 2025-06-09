import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from shadowlink.simulation.attacks.brute_force import BruteForceAttack
from shadowlink.core.iam.environment import load_iam_env  # assuming you built this

# Load IAM env
env = load_iam_env("data/mock_iam/environments/default.json")

# Run attack
attack = BruteForceAttack()
result = attack.execute(env, "user_005")
print(result.to_dict())

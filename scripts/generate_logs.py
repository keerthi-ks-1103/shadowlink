import json, random
from datetime import datetime, timedelta
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from config.constants import roles, actions, resources

def generate_log(user_id, start_time, malicious=False):
    role = random.choice(roles)
    action = random.choices(
        actions if not malicious else ['escalate_privilege', 'delete_user'],
        weights=[8, 10] if malicious else [15, 10, 8, 3, 2], k=1
    )[0]
    return {
        "user_id": user_id,
        "role": role,
        "action": action,
        "resource": random.choice(resources),
        "timestamp": (start_time + timedelta(minutes=random.randint(0, 5))).isoformat(),
        "success": True if action != 'delete_user' else not malicious
    }

def save_logs(path="data/logs/synthetic_logs.json", normal=900, malicious=100):
    logs = []
    now = datetime.now()
    logs.extend(generate_log(f"U{i:03}", now) for i in range(normal))
    logs.extend(generate_log(f"M{i:03}", now, malicious=True) for i in range(malicious))
    random.shuffle(logs)
    with open(path, "w") as f:
        json.dump(logs, f, indent=2)

if __name__ == "__main__":
    save_logs()

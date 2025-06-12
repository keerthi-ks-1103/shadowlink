import json
import random
import pickle
from collections import defaultdict

def extract_logs(path):
    with open(path) as f:
        data = json.load(f)

    logs = []
    for sim in data.get("simulations", []):
        for attack in sim.get("attacks_executed", []):
            logs.append({
                "user": attack.get("user"),
                "action": attack.get("attack"),
                "success": attack.get("success"),
                "timestamp": attack.get("timestamp")
            })
    return logs

def reward(success, action):
    # Base reward on success and sensitivity
    base = {
        'Brute Force': 2,
        'Privilege Escalation': 10,
        'Lateral Movement': 6,
        'Data Exfiltration': 8
    }.get(action, 1)

    return base if success else -1  # Penalty for failed attacks

def train(path="data/logs/simulation_log.json", save="data/models/q_table.pkl", episodes=500):
    logs = extract_logs(path)
    if not logs:
        raise ValueError("No attack logs found.")

    # Extract unique users and actions
    users = list(set(log['user'] for log in logs))
    actions = list(set(log['action'] for log in logs))

    # Initialize Q-table
    q_table = defaultdict(lambda: {a: 0.0 for a in actions})

    alpha = 0.1  # learning rate
    gamma = 0.95  # discount factor
    epsilon = 0.1  # exploration

    for _ in range(episodes):
        log = random.choice(logs)
        state = log['user']
        action = log['action']
        success = log['success']

        current_q = q_table[state][action]
        reward_val = reward(success, action)

        next_state = log['user']
        future_q = max(q_table[next_state].values())  # Future value estimate
        q_table[state][action] = current_q + alpha * (reward_val + gamma * future_q - current_q)

    with open(save, "wb") as f:
        pickle.dump(dict(q_table), f)
    print(f"[✓] Trained Q-table saved to {save}")

if __name__ == "__main__":
    train()

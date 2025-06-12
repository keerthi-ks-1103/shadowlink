import pickle

# Load pre-trained Q-table
with open("data/models/q_table.pkl", "rb") as f:
    q_table = pickle.load(f)

def suggest_action(user):
    if user not in q_table:
        return "Brute Force"  # fallback default
    return max(q_table[user], key=q_table[user].get)

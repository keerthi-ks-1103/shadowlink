import json
from shadowlink.core.iam.environment import IAMEnvironmentManager

def load_iam_env(path="data/mock_iam/environments/default.json") -> IAMEnvironmentManager:
    manager = IAMEnvironmentManager()
    if not manager.load_environment(path):
        raise FileNotFoundError(f"❌ Could not load IAM environment from: {path}")
    return manager

"""
ShadowLink Configuration Settings
"""
import os
from pathlib import Path
from typing import Dict, Any

# Base paths
PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "data"
SRC_DIR = PROJECT_ROOT / "src"

# Environment
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
DEBUG = os.getenv("DEBUG", "false").lower() == "true"

# API Settings
API_CONFIG = {
    "host": os.getenv("API_HOST", "0.0.0.0"),
    "port": int(os.getenv("API_PORT", 8000)),
    "secret_key": os.getenv("SECRET_KEY", "dev-secret-key"),
}

# Database Settings
DATABASE_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", 5432)),
    "name": os.getenv("DB_NAME", "shadowlink"),
    "user": os.getenv("DB_USER", "shadowlink_user"),
    "password": os.getenv("DB_PASSWORD", ""),
}

# ML Model Paths
MODEL_PATHS = {
    "anomaly_detector": DATA_DIR / "models" / os.getenv("ANOMALY_MODEL", "anomaly_detector_v1.joblib"),
    "risk_predictor": DATA_DIR / "models" / os.getenv("RISK_MODEL", "risk_predictor_v1.joblib"),
}

# Simulation Settings
SIMULATION_CONFIG = {
    "max_time_seconds": int(os.getenv("MAX_SIMULATION_TIME", 300)),
    "default_iam_env": DATA_DIR / "mock_iam" / "environments" / "default.json",
    "log_all_actions": True,
}

# Logging Configuration
LOGGING_CONFIG = {
    "level": os.getenv("LOG_LEVEL", "INFO"),
    "file": DATA_DIR / "logs" / "shadowlink.log",
    "format": "{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{function}:{line} | {message}",
}

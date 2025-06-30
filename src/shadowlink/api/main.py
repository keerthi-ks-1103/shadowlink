import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))

from fastapi import FastAPI
from shadowlink.api.routes.risk_api import router as risk_router

app = FastAPI()

# Register the API route
app.include_router(risk_router)

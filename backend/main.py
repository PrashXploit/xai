"""
XAI-Sec FastAPI Backend — Main Entry Point
"""
import sys
import os

# Allow imports from project root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import joblib

from database.database_manager import create_tables

app = FastAPI(title="XAI-Sec API", version="2.0.0")

# ── CORS (allow the Next.js dev server) ──────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Database init ─────────────────────────────────────────────────────────────
create_tables()

# ── Shared model cache ────────────────────────────────────────────────────────
_models: dict = {}

def get_models() -> dict:
    """Load models once and cache them (replaces @st.cache_resource)."""
    global _models
    if _models:
        return _models

    model_dir = os.path.join(os.path.dirname(__file__), '..', 'models')
    ids_data     = joblib.load(os.path.join(model_dir, 'ids_model.pkl'))
    malware_data = joblib.load(os.path.join(model_dir, 'malware_model.pkl'))

    _models = {
        'ids_model':       ids_data['pipeline'],
        'ids_features':    ids_data['features'],
        'malware_model':   malware_data['pipeline'],
        'malware_features': malware_data['features'],
    }
    return _models

# Pre-load on startup
@app.on_event("startup")
async def startup_event():
    get_models()

# ── Routers ───────────────────────────────────────────────────────────────────
from backend.routes import auth, ids, malware, history, models as models_route  # noqa: E402

app.include_router(auth.router,          prefix="/auth",    tags=["Auth"])
app.include_router(ids.router,           prefix="/ids",     tags=["IDS"])
app.include_router(malware.router,       prefix="/malware", tags=["Malware"])
app.include_router(history.router,       prefix="/history", tags=["History"])
app.include_router(models_route.router,  prefix="/models",  tags=["Models"])

@app.get("/")
def root():
    return {"status": "XAI-Sec API running", "version": "2.0.0"}

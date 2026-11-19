"""Models route — serve metrics and confusion matrix images."""
import sys, os, json, base64
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from fastapi import APIRouter
from fastapi.responses import JSONResponse

router = APIRouter()
MODEL_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'models'))


def _load_metrics(name: str) -> dict:
    path = os.path.join(MODEL_DIR, f"{name}_metrics.json")
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {}


def _img_b64(name: str) -> str | None:
    path = os.path.join(MODEL_DIR, f"{name}_confusion_matrix.png")
    if os.path.exists(path):
        with open(path, "rb") as f:
            return base64.b64encode(f.read()).decode()
    return None


@router.get("/ids")
def ids_metrics():
    return {"metrics": _load_metrics("ids"), "confusion_matrix": _img_b64("ids")}


@router.get("/malware")
def malware_metrics():
    return {"metrics": _load_metrics("malware"), "confusion_matrix": _img_b64("malware")}

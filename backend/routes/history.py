"""History route — return user scan log."""
import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from fastapi import APIRouter, Header, HTTPException
from database.database_manager import get_user_history
from backend.auth_utils import decode_token

router = APIRouter()


def _get_user_id(authorization: str | None) -> int:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token(authorization.split(" ", 1)[1])
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return int(payload["sub"])


def _severity_for(result: str, confidence: float) -> str:
    text = (result or "").lower()
    if any(k in text for k in ["malware", "attack", "intrusion", "dos", "probe", "r2l", "u2r", "threat"]):
        if confidence >= 0.85:
            return "Critical"
        if confidence >= 0.7:
            return "High"
        if confidence >= 0.5:
            return "Medium"
        return "Low"
    return "Low"


@router.get("/")
def get_history(authorization: str | None = Header(default=None)):
    user_id = _get_user_id(authorization)
    rows = get_user_history(user_id)
    history = []
    for r in rows:
        scan_type, result, confidence, timestamp = r
        history.append({
            "scan_type": scan_type,
            "result": result,
            "confidence": float(confidence),
            "timestamp": timestamp,
            "severity": _severity_for(result, float(confidence)),
        })
    return history


@router.get("/summary")
def get_summary(authorization: str | None = Header(default=None)):
    user_id = _get_user_id(authorization)
    rows = get_user_history(user_id)

    normalized = []
    for r in rows:
        scan_type, result, confidence, timestamp = r
        normalized.append({
            "scan_type": scan_type,
            "result": result,
            "confidence": float(confidence),
            "timestamp": timestamp,
            "severity": _severity_for(result, float(confidence)),
        })

    total = len(normalized)
    threats = sum(1 for row in normalized if row["severity"] in ["Critical", "High", "Medium"])
    benign = total - threats
    avg_conf = round(sum(row["confidence"] for row in normalized) / total, 4) if total else 0.0

    severity_breakdown = {
        "Critical": sum(1 for row in normalized if row["severity"] == "Critical"),
        "High": sum(1 for row in normalized if row["severity"] == "High"),
        "Medium": sum(1 for row in normalized if row["severity"] == "Medium"),
        "Low": sum(1 for row in normalized if row["severity"] == "Low"),
    }

    by_scan_type = {
        "IDS": sum(1 for row in normalized if row["scan_type"] == "IDS"),
        "Malware": sum(1 for row in normalized if row["scan_type"] == "Malware"),
    }

    return {
        "total_scans": total,
        "threats_detected": threats,
        "benign_scans": benign,
        "average_confidence": avg_conf,
        "severity_breakdown": severity_breakdown,
        "by_scan_type": by_scan_type,
        "latest_scan": normalized[0] if normalized else None,
    }

"""IDS Scanner route."""
import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

import io
import numpy as np
import pandas as pd
from fastapi import APIRouter, Header, HTTPException, UploadFile, File
from pydantic import BaseModel
from typing import Optional

from backend.auth_utils import decode_token
from backend.main import get_models
from database.database_manager import save_scan
from utils.preprocessing import get_ids_data, _align_features
from sklearn.preprocessing import LabelEncoder

router = APIRouter()

ATTACK_TYPES = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']


def _get_user_id(authorization: str | None) -> int:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token(authorization.split(" ", 1)[1])
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return int(payload["sub"])


def _shap_for_instance(model_pipe, instance: pd.DataFrame, feature_names: list, prediction: int) -> list:
    try:
        from explainability.shap_explainer import get_shap_values
        scaled = (
            model_pipe.named_steps['scaler'].transform(instance)
            if 'scaler' in model_pipe.named_steps
            else instance.values
        )
        core = model_pipe.named_steps.get('model', model_pipe)
        vals = get_shap_values(core, scaled, prediction)
        return [{"feature": f, "value": float(v)} for f, v in zip(feature_names, vals)]
    except Exception:
        return []


@router.get("/sample")
def generate_sample(authorization: str | None = Header(default=None)):
    """Return a sample dataset for the IDS scanner."""
    _get_user_id(authorization)
    models = get_models()
    X, y = get_ids_data(is_training=False, expected_features=models['ids_features'])
    records = X.head(20).to_dict(orient='records')
    labels = y.head(20).tolist()
    return {"records": records, "labels": labels, "features": models['ids_features']}


@router.post("/scan")
async def scan_ids(
    authorization: str | None = Header(default=None),
    file: Optional[UploadFile] = File(default=None),
    instance_idx: int = 0,
):
    """
    Scan a single network traffic instance.
    If a CSV file is uploaded, use the row at instance_idx.
    Otherwise, use a generated sample at instance_idx.
    """
    user_id = _get_user_id(authorization)
    models = get_models()

    if file and file.filename:
        content = await file.read()
        df_raw = pd.read_csv(io.BytesIO(content))
        label_keys = ['label', 'class', 'target', 'attack']
        target_col = [c for c in df_raw.columns if any(k in c.lower() for k in label_keys)]
        df_feat = df_raw.drop(columns=target_col, errors='ignore')
        for col in df_feat.select_dtypes(include=['object']).columns:
            df_feat[col] = LabelEncoder().fit_transform(df_feat[col].astype(str))
        X_test = _align_features(df_feat, models['ids_features'])
    else:
        X_test, _ = get_ids_data(is_training=False, expected_features=models['ids_features'])

    if instance_idx >= len(X_test):
        instance_idx = 0

    instance = X_test.iloc[[instance_idx]]
    prediction = int(models['ids_model'].predict(instance)[0])
    confidence = float(models['ids_model'].predict_proba(instance).max())
    predicted_class = ATTACK_TYPES[prediction] if prediction < len(ATTACK_TYPES) else "Unknown"

    # Save to DB
    save_scan(user_id, "IDS", f"{predicted_class} Attack", confidence)

    # SHAP
    shap_values = _shap_for_instance(models['ids_model'], instance, models['ids_features'], prediction)

    return {
        "prediction": predicted_class,
        "prediction_index": prediction,
        "confidence": confidence,
        "is_threat": predicted_class != "Normal",
        "shap_values": shap_values,
        "instance": instance.iloc[0].to_dict(),
    }

"""
Retrain IDS and Malware models on properly balanced datasets.
Fixes: model always predicting same class.
Run: python training/retrain_all.py
"""
import os, sys
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, f1_score

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DATASET_DIR = os.path.join(ROOT, 'datasets')
MODEL_DIR   = os.path.join(ROOT, 'models')
os.makedirs(MODEL_DIR, exist_ok=True)

# ─────────────────────────────────────────────────────────────
# HELPER: encode any remaining string columns
# ─────────────────────────────────────────────────────────────
def encode_strings(df):
    for col in df.select_dtypes(include=['object']).columns:
        df[col] = LabelEncoder().fit_transform(df[col].astype(str))
    return df

# ─────────────────────────────────────────────────────────────
# 1. TRAIN IDS MODEL
# ─────────────────────────────────────────────────────────────
def train_ids():
    print("\n" + "="*55)
    print("  TRAINING IDS MODEL")
    print("="*55)

    csv_path = os.path.join(DATASET_DIR, 'ids_dataset.csv')
    if not os.path.exists(csv_path):
        print(f"  ids_dataset.csv not found → generating...")
        sys.path.insert(0, DATASET_DIR)
        from generate_datasets import generate_ids_dataset
        generate_ids_dataset(n=2000, filepath=csv_path)

    df = pd.read_csv(csv_path)
    label_col = next((c for c in df.columns if c.lower() in ['label','class','target','attack_type']), None)
    if label_col is None:
        raise ValueError("No label column found in ids_dataset.csv")

    y = df[label_col].astype(int)
    X = df.drop(columns=[label_col])
    X = encode_strings(X)
    X = X.apply(pd.to_numeric, errors='coerce').fillna(0)

    print(f"  Dataset: {len(df)} rows | Label dist: {y.value_counts().sort_index().to_dict()}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)

    pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('model', RandomForestClassifier(
            n_estimators=200,
            class_weight='balanced',   # ← KEY FIX
            random_state=42,
            n_jobs=-1
        ))
    ])
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1  = f1_score(y_test, y_pred, average='weighted')

    print(f"\n  Test Accuracy : {acc:.4f}")
    print(f"  Weighted F1   : {f1:.4f}")
    classes = sorted(y.unique())
    names   = ['Normal','DoS','Probe','R2L','U2R'][:len(classes)]
    print(classification_report(y_test, y_pred, target_names=names))

    model_data = {'pipeline': pipeline, 'features': X.columns.tolist()}
    out = os.path.join(MODEL_DIR, 'ids_model.pkl')
    joblib.dump(model_data, out)
    print(f"  ✅ IDS model saved → {out}")
    return model_data


# ─────────────────────────────────────────────────────────────
# 2. TRAIN MALWARE MODEL
# ─────────────────────────────────────────────────────────────
def train_malware():
    print("\n" + "="*55)
    print("  TRAINING MALWARE MODEL")
    print("="*55)

    csv_path = os.path.join(DATASET_DIR, 'malware_dataset.csv')
    if not os.path.exists(csv_path):
        print(f"  malware_dataset.csv not found → generating...")
        sys.path.insert(0, DATASET_DIR)
        from generate_datasets import generate_malware_dataset
        generate_malware_dataset(n=2000, filepath=csv_path)

    df = pd.read_csv(csv_path)
    label_col = next((c for c in df.columns if c.lower() in ['label','class','target','malware','legitimate']), None)
    if label_col is None:
        raise ValueError("No label column found in malware_dataset.csv")

    y = df[label_col].astype(int)
    X = df.drop(columns=[label_col])
    X = encode_strings(X)
    X = X.apply(pd.to_numeric, errors='coerce').fillna(0)

    print(f"  Dataset: {len(df)} rows | Label dist: {y.value_counts().sort_index().to_dict()}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)

    pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('model', RandomForestClassifier(
            n_estimators=200,
            class_weight='balanced',   # ← KEY FIX
            random_state=42,
            n_jobs=-1
        ))
    ])
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1  = f1_score(y_test, y_pred, average='weighted')

    print(f"\n  Test Accuracy : {acc:.4f}")
    print(f"  Weighted F1   : {f1:.4f}")
    names = ['Clean', 'Malware']
    print(classification_report(y_test, y_pred, target_names=names))

    model_data = {'pipeline': pipeline, 'features': X.columns.tolist()}
    out = os.path.join(MODEL_DIR, 'malware_model.pkl')
    joblib.dump(model_data, out)
    print(f"  ✅ Malware model saved → {out}")
    return model_data


# ─────────────────────────────────────────────────────────────
# 3. QUICK VARIABILITY TEST
# ─────────────────────────────────────────────────────────────
def test_variability(ids_data, mal_data):
    print("\n" + "="*55)
    print("  VARIABILITY TEST (should see mixed predictions)")
    print("="*55)

    ids_pipe = ids_data['pipeline']
    mal_pipe = mal_data['pipeline']

    # IDS: sample 5 rows from dataset
    ids_csv = os.path.join(DATASET_DIR, 'ids_dataset.csv')
    df_ids = pd.read_csv(ids_csv)
    X_ids = df_ids.drop(columns=[c for c in df_ids.columns if c.lower() in ['label','class','target','attack_type']])
    X_ids = encode_strings(X_ids)
    X_ids = X_ids.apply(pd.to_numeric, errors='coerce').fillna(0)
    sample = X_ids.sample(10, random_state=0)
    preds = ids_pipe.predict(sample)
    probs = ids_pipe.predict_proba(sample).max(axis=1)
    names = ['Normal','DoS','Probe','R2L','U2R']
    print("\n  IDS predictions (10 random samples):")
    for p, prob in zip(preds, probs):
        print(f"    {names[p]:8s}  confidence={prob:.2f}")

    # Malware: sample 5 rows
    mal_csv = os.path.join(DATASET_DIR, 'malware_dataset.csv')
    df_mal = pd.read_csv(mal_csv)
    X_mal = df_mal.drop(columns=[c for c in df_mal.columns if c.lower() in ['label','class','target','malware','legitimate']])
    X_mal = encode_strings(X_mal)
    X_mal = X_mal.apply(pd.to_numeric, errors='coerce').fillna(0)
    sample = X_mal.sample(10, random_state=0)
    preds = mal_pipe.predict(sample)
    probs = mal_pipe.predict_proba(sample).max(axis=1)
    print("\n  Malware predictions (10 random samples):")
    for p, prob in zip(preds, probs):
        print(f"    {'MALWARE' if p==1 else 'CLEAN':8s}  confidence={prob:.2f}")


if __name__ == '__main__':
    ids_data = train_ids()
    mal_data = train_malware()
    test_variability(ids_data, mal_data)
    print("\n🎉 All done! Restart Streamlit to load the new models.")

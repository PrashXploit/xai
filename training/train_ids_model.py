import os
import sys
import argparse
import joblib
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import matplotlib.pyplot as plt
import seaborn as sns

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.preprocessing import get_ids_data, split_data
from utils.visualization import save_metrics_to_file, create_performance_metrics_chart

def build_model_summary(y_true, y_pred, y_proba=None, is_binary=False):
    metrics = {
        'accuracy': accuracy_score(y_true, y_pred),
        'precision': precision_score(y_true, y_pred, average='binary' if is_binary else 'weighted', zero_division=0),
        'recall': recall_score(y_true, y_pred, average='binary' if is_binary else 'weighted', zero_division=0),
        'f1': f1_score(y_true, y_pred, average='binary' if is_binary else 'weighted', zero_division=0),
        'confusion_matrix': confusion_matrix(y_true, y_pred),
        'false_positive_rate': 0.0,
        'roc_auc': None,
    }
    if is_binary:
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        metrics['false_positive_rate'] = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        if y_proba is not None:
            metrics['roc_auc'] = roc_auc_score(y_true, y_proba)
    else:
        cm = confusion_matrix(y_true, y_pred)
        class_fprs = []
        for idx in range(cm.shape[0]):
            tp = cm[idx, idx]
            fp = cm[:, idx].sum() - tp
            tn = cm.sum() - cm[idx, :].sum() - cm[:, idx].sum() + tp
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            class_fprs.append(fpr)
        metrics['false_positive_rate'] = sum(class_fprs) / len(class_fprs) if class_fprs else 0.0
        if y_proba is not None:
            metrics['roc_auc'] = roc_auc_score(y_true, y_proba, multi_class='ovr', average='weighted')
    return metrics

def train_ids(data_path=None):
    print("Loading and preprocessing data...")
    X, y = get_ids_data(data_path, is_training=True)
    X_train, X_test, y_train, y_test = split_data(X, y)
    
    # Random Forest Pipeline
    print("Training Random Forest Classifier on IDS dataset...")
    rf_pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('model', RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1))
    ])
    rf_pipeline.fit(X_train, y_train)
    rf_pred = rf_pipeline.predict(X_test)
    rf_proba = rf_pipeline.predict_proba(X_test) if hasattr(rf_pipeline, 'predict_proba') else None
    rf_metrics = build_model_summary(y_test, rf_pred, rf_proba[:, 1] if rf_proba is not None and rf_proba.shape[1] > 1 else rf_proba, is_binary=False)
    rf_f1 = f1_score(y_test, rf_pred, average='weighted')
    
    # XGBoost Pipeline
    print("Training XGBoost Classifier on IDS dataset...")
    xgb_pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('model', XGBClassifier(n_estimators=100, random_state=42, n_jobs=-1, eval_metric='mlogloss'))
    ])
    xgb_pipeline.fit(X_train, y_train)
    xgb_pred = xgb_pipeline.predict(X_test)
    xgb_proba = xgb_pipeline.predict_proba(X_test) if hasattr(xgb_pipeline, 'predict_proba') else None
    xgb_metrics = build_model_summary(y_test, xgb_pred, xgb_proba[:, 1] if xgb_proba is not None and xgb_proba.shape[1] > 1 else xgb_proba, is_binary=False)
    xgb_f1 = f1_score(y_test, xgb_pred, average='weighted')
    
    print(f"Results -> RF F1: {rf_f1:.4f} | XGBoost F1: {xgb_f1:.4f}")
    
    if xgb_f1 > rf_f1:
        print("Selecting XGBoost as the best model.")
        best_pipeline = xgb_pipeline
        y_pred = xgb_pred
        winner = 'XGBoost'
        winner_metrics = xgb_metrics
        comparison = {
            'rf': {**rf_metrics, 'model_name': 'Random Forest', 'selected': False},
            'xgb': {**xgb_metrics, 'model_name': 'XGBoost', 'selected': True},
            'selected': 'XGBoost',
            'winner': 'XGBoost',
        }
    else:
        print("Selecting Random Forest as the best model.")
        best_pipeline = rf_pipeline
        y_pred = rf_pred
        winner = 'Random Forest'
        winner_metrics = rf_metrics
        comparison = {
            'rf': {**rf_metrics, 'model_name': 'Random Forest', 'selected': True},
            'xgb': {**xgb_metrics, 'model_name': 'XGBoost', 'selected': False},
            'selected': 'Random Forest',
            'winner': 'Random Forest',
        }

    acc = accuracy_score(y_test, y_pred)
    
    # Define model_dir early
    model_dir = os.path.join(os.path.dirname(__file__), '..', 'models')
    os.makedirs(model_dir, exist_ok=True)
    
    print("Best Model Evaluation Metrics:")
    print(f"Accuracy: {acc:.4f}")
    target_names = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']
    print(classification_report(y_test, y_pred, target_names=target_names[:len(set(y_test))]))
    
    # Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    
    # Plot confusion matrix
    fig, ax = plt.subplots(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax,
                xticklabels=target_names[:len(set(y_test))],
                yticklabels=target_names[:len(set(y_test))])
    ax.set_title('Confusion Matrix - Best IDS Model')
    ax.set_xlabel('Predicted Label')
    ax.set_ylabel('True Label')
    plt.tight_layout()
    cm_path = os.path.join(model_dir, 'ids_confusion_matrix.png')
    plt.savefig(cm_path)
    plt.close()
    
    # Save metrics to JSON file
    save_metrics_to_file('ids', y_test, y_pred, model_dir)
    
    # Generate and save performance metrics chart
    try:
        fig_metrics, _ = create_performance_metrics_chart(y_test, y_pred, 'IDS', target_names[:len(set(y_test))])
        metrics_chart_path = os.path.join(model_dir, 'ids_performance_metrics.html')
        fig_metrics.write_html(metrics_chart_path)
    except Exception:
        pass
    
    model_data = {
        'pipeline': best_pipeline,
        'features': X.columns.tolist(),
        'comparison': comparison,
        'winner': winner,
        'selected_metrics': winner_metrics,
    }
    
    model_path = os.path.join(model_dir, 'ids_model.pkl')
    print(f"Saving best model pipeline and configuration to {model_path}...")
    joblib.dump(model_data, model_path)
    print("Training finished.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Train IDS Model")
    parser.add_argument("--data", type=str, default=None, help="Path to NSL-KDD CSV dataset.")
    args = parser.parse_args()
    train_ids(args.data)

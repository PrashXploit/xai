"""
Visualization utilities for model performance metrics and comparisons
"""

import pandas as pd
import numpy as np
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score, confusion_matrix, roc_auc_score
import plotly.graph_objects as go
import plotly.express as px
import os
import json


# ==================== PERFORMANCE METRICS VISUALIZATION ====================

def create_performance_metrics_chart(y_true, y_pred, model_name, target_names=None):
    """
    Create a performance metrics chart (Precision, Recall, F1) for a model
    
    Args:
        y_true: True labels
        y_pred: Predicted labels
        model_name: Name of the model (e.g., "IDS", "Malware")
        target_names: List of class names
        
    Returns:
        plotly figure object and metrics dataframe
    """
    
    # Calculate metrics for each class
    precision_scores = precision_score(y_true, y_pred, average=None, zero_division=0)
    recall_scores = recall_score(y_true, y_pred, average=None, zero_division=0)
    f1_scores = f1_score(y_true, y_pred, average=None, zero_division=0)
    
    # Create class names if not provided
    if target_names is None:
        target_names = [f"Class {i}" for i in range(len(precision_scores))]
    else:
        target_names = target_names[:len(precision_scores)]
    
    # Create DataFrame for plotting
    metrics_df = pd.DataFrame({
        'Class': target_names,
        'Precision': precision_scores,
        'Recall': recall_scores,
        'F1-Score': f1_scores
    })
    
    # Create grouped bar chart
    fig = go.Figure()
    
    fig.add_trace(go.Bar(
        x=metrics_df['Class'],
        y=metrics_df['Precision'],
        name='Precision',
        marker_color='#ff2e4d',
        text=np.round(metrics_df['Precision'], 3),
        textposition='auto'
    ))
    
    fig.add_trace(go.Bar(
        x=metrics_df['Class'],
        y=metrics_df['Recall'],
        name='Recall',
        marker_color='#3b82f6',
        text=np.round(metrics_df['Recall'], 3),
        textposition='auto'
    ))
    
    fig.add_trace(go.Bar(
        x=metrics_df['Class'],
        y=metrics_df['F1-Score'],
        name='F1-Score',
        marker_color='#10b981',
        text=np.round(metrics_df['F1-Score'], 3),
        textposition='auto'
    ))
    
    fig.update_layout(
        title=f'{model_name} Model - Performance Metrics',
        xaxis_title='Class',
        yaxis_title='Score',
        barmode='group',
        plot_bgcolor='rgba(22, 26, 38, 0.5)',
        paper_bgcolor='rgba(11, 15, 31, 0)',
        font=dict(color='rgba(255, 255, 255, 0.9)', size=11),
        hovermode='x unified',
        margin=dict(l=50, r=50, t=70, b=50),
        height=400,
        legend=dict(x=0.02, y=0.98, bgcolor='rgba(0, 0, 0, 0.3)', bordercolor='rgba(255, 255, 255, 0.1)', borderwidth=1)
    )
    
    return fig, metrics_df


def create_average_metrics_chart(metrics_data):
    """
    Create a chart comparing average metrics (Precision, Recall, F1) across models
    
    Args:
        metrics_data: Dictionary containing {model_name: {'precision': float, 'recall': float, 'f1': float}}
        
    Returns:
        plotly figure object
    """
    
    models = list(metrics_data.keys())
    precisions = [metrics_data[m].get('precision', 0) for m in models]
    recalls = [metrics_data[m].get('recall', 0) for m in models]
    f1_scores = [metrics_data[m].get('f1', 0) for m in models]
    
    fig = go.Figure()
    
    fig.add_trace(go.Bar(
        x=models,
        y=precisions,
        name='Avg Precision',
        marker_color='#ff2e4d',
        text=np.round(precisions, 3),
        textposition='auto'
    ))
    
    fig.add_trace(go.Bar(
        x=models,
        y=recalls,
        name='Avg Recall',
        marker_color='#3b82f6',
        text=np.round(recalls, 3),
        textposition='auto'
    ))
    
    fig.add_trace(go.Bar(
        x=models,
        y=f1_scores,
        name='Avg F1-Score',
        marker_color='#10b981',
        text=np.round(f1_scores, 3),
        textposition='auto'
    ))
    
    fig.update_layout(
        title='Average Performance Metrics Comparison',
        xaxis_title='Model',
        yaxis_title='Score',
        barmode='group',
        plot_bgcolor='rgba(22, 26, 38, 0.5)',
        paper_bgcolor='rgba(11, 15, 31, 0)',
        font=dict(color='rgba(255, 255, 255, 0.9)', size=11),
        hovermode='x unified',
        margin=dict(l=50, r=50, t=70, b=50),
        height=400,
        legend=dict(x=0.02, y=0.98, bgcolor='rgba(0, 0, 0, 0.3)', bordercolor='rgba(255, 255, 255, 0.1)', borderwidth=1)
    )
    
    return fig




# ==================== COMPARISON VISUALIZATIONS ====================

def create_model_comparison_radar(ids_metrics_df, malware_metrics_df):
    """
    Create a radar chart comparing IDS and Malware models across metrics
    
    Args:
        ids_metrics_df: DataFrame with columns ['Class', 'Precision', 'Recall', 'F1-Score']
        malware_metrics_df: DataFrame with columns ['Class', 'Precision', 'Recall', 'F1-Score']
        
    Returns:
        plotly figure object
    """
    
    # Calculate average metrics
    ids_avg_precision = ids_metrics_df['Precision'].mean()
    ids_avg_recall = ids_metrics_df['Recall'].mean()
    ids_avg_f1 = ids_metrics_df['F1-Score'].mean()
    
    malware_avg_precision = malware_metrics_df['Precision'].mean()
    malware_avg_recall = malware_metrics_df['Recall'].mean()
    malware_avg_f1 = malware_metrics_df['F1-Score'].mean()
    
    categories = ['Precision', 'Recall', 'F1-Score']
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatterpolar(
        r=[ids_avg_precision, ids_avg_recall, ids_avg_f1],
        theta=categories,
        fill='toself',
        name='IDS Model',
        line=dict(color='#ff2e4d'),
        fillcolor='rgba(255, 46, 77, 0.3)'
    ))
    
    fig.add_trace(go.Scatterpolar(
        r=[malware_avg_precision, malware_avg_recall, malware_avg_f1],
        theta=categories,
        fill='toself',
        name='Malware Model',
        line=dict(color='#3b82f6'),
        fillcolor='rgba(59, 130, 246, 0.3)'
    ))
    
    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 1],
                tickfont=dict(color='rgba(255, 255, 255, 0.7)', size=10),
                gridcolor='rgba(255, 255, 255, 0.1)'
            ),
            angularaxis=dict(
                tickfont=dict(color='rgba(255, 255, 255, 0.85)', size=11),
                linecolor='rgba(255, 255, 255, 0.2)',
                gridcolor='rgba(255, 255, 255, 0.1)'
            ),
            bgcolor='rgba(22, 26, 38, 0.3)'
        ),
        title='IDS vs Malware - Performance Radar',
        showlegend=True,
        paper_bgcolor='rgba(11, 15, 31, 0)',
        font=dict(color='rgba(255, 255, 255, 0.9)', size=11),
        margin=dict(l=60, r=60, t=70, b=60),
        height=450,
        legend=dict(x=0.85, y=0.95, bgcolor='rgba(0, 0, 0, 0.3)', bordercolor='rgba(255, 255, 255, 0.1)', borderwidth=1)
    )
    
    return fig


def create_model_comparison_heatmap(ids_metrics_df, malware_metrics_df):
    """
    Create a heatmap comparing metrics across both models
    
    Args:
        ids_metrics_df: DataFrame with columns ['Class', 'Precision', 'Recall', 'F1-Score']
        malware_metrics_df: DataFrame with columns ['Class', 'Precision', 'Recall', 'F1-Score']
        
    Returns:
        plotly figure object
    """
    
    # Calculate average performance
    comparison_data = {
        'IDS': [
            ids_metrics_df['Precision'].mean(),
            ids_metrics_df['Recall'].mean(),
            ids_metrics_df['F1-Score'].mean()
        ],
        'Malware': [
            malware_metrics_df['Precision'].mean(),
            malware_metrics_df['Recall'].mean(),
            malware_metrics_df['F1-Score'].mean()
        ]
    }
    
    z = [comparison_data['IDS'], comparison_data['Malware']]
    x = ['Precision', 'Recall', 'F1-Score']
    y = ['IDS Model', 'Malware Model']
    
    fig = go.Figure(data=go.Heatmap(
        z=z,
        x=x,
        y=y,
        colorscale='RdYlGn',
        text=np.array(z).round(3),
        texttemplate='%{text:.3f}',
        textfont={"size": 12},
        colorbar=dict(
            title="Score",
            tickcolor='rgba(255, 255, 255, 0.8)',
            tickfont=dict(color='rgba(255, 255, 255, 0.8)', size=10)
        ),
        hovertemplate='<b>%{y}</b><br>%{x}: %{text:.3f}<extra></extra>'
    ))
    
    fig.update_layout(
        title='Model Performance Comparison - Heatmap',
        plot_bgcolor='rgba(22, 26, 38, 0.5)',
        paper_bgcolor='rgba(11, 15, 31, 0)',
        font=dict(color='rgba(255, 255, 255, 0.9)', size=11),
        margin=dict(l=100, r=50, t=70, b=50),
        height=300,
        xaxis=dict(tickfont=dict(color='rgba(255, 255, 255, 0.85)', size=11)),
        yaxis=dict(tickfont=dict(color='rgba(255, 255, 255, 0.85)', size=11))
    )
    
    return fig


def save_metrics_to_file(model_name, y_true, y_pred, model_dir='models'):
    """
    Save metrics to a JSON file for later retrieval
    
    Args:
        model_name: Name of the model ('ids' or 'malware')
        y_true: True labels
        y_pred: Predicted labels
        model_dir: Directory to save metrics
    """
    
    os.makedirs(model_dir, exist_ok=True)
    
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    unique_labels = np.unique(np.concatenate([y_true, y_pred]))

    # Calculate overall metrics
    precision = precision_score(y_true, y_pred, average='weighted' if len(unique_labels) > 2 else 'binary', zero_division=0)
    recall = recall_score(y_true, y_pred, average='weighted' if len(unique_labels) > 2 else 'binary', zero_division=0)
    f1 = f1_score(y_true, y_pred, average='weighted' if len(unique_labels) > 2 else 'binary', zero_division=0)
    accuracy = accuracy_score(y_true, y_pred)
    cm = confusion_matrix(y_true, y_pred, labels=unique_labels)

    if len(unique_labels) == 2:
        tn, fp, fn, tp = cm.ravel()
        false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    else:
        class_fprs = []
        for idx in range(cm.shape[0]):
            tp = cm[idx, idx]
            fp = cm[:, idx].sum() - tp
            tn = cm.sum() - cm[idx, :].sum() - cm[:, idx].sum() + tp
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            class_fprs.append(fpr)
        false_positive_rate = float(np.mean(class_fprs)) if class_fprs else 0.0

    metrics = {
        'model_name': model_name,
        'accuracy': float(accuracy),
        'precision': float(precision),
        'recall': float(recall),
        'f1': float(f1),
        'false_positive_rate': float(false_positive_rate),
        'confusion_matrix': cm.tolist(),
        'roc_auc': None,
    }

    filepath = os.path.join(model_dir, f'{model_name}_metrics.json')
    with open(filepath, 'w') as f:
        json.dump(metrics, f, indent=4)
    
    return metrics


def load_metrics_from_file(model_name, model_dir='models'):
    """
    Load metrics from saved JSON file
    
    Args:
        model_name: Name of the model ('ids' or 'malware')
        model_dir: Directory containing metrics
        
    Returns:
        Dictionary with metrics or None if file not found
    """
    
    filepath = os.path.join(model_dir, f'{model_name}_metrics.json')
    
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            return json.load(f)
    return None

import shap
import matplotlib.pyplot as plt

def generate_shap_summary(model, X, is_classification=True):
    """
    Generate and plot SHAP summary plot.
    """
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X)
    
    if is_classification:
        if isinstance(shap_values, list):
            shap_vals_to_plot = shap_values[1]
        elif len(shap_values.shape) == 3:
            shap_vals_to_plot = shap_values[:, :, 1]
        else:
            shap_vals_to_plot = shap_values
    else:
        shap_vals_to_plot = shap_values
        
    plt.figure(figsize=(10, 6))
    shap.summary_plot(shap_vals_to_plot, X, show=False)
    
    fig = plt.gcf()
    return fig

def generate_shap_feature_importance(model, X):
    """
    Generate global feature importance bar plot using SHAP.
    """
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X)
    
    if isinstance(shap_values, list):
        shap_vals_to_plot = shap_values[1]
    elif len(shap_values.shape) == 3:
        shap_vals_to_plot = shap_values[:, :, 1]
    else:
        shap_vals_to_plot = shap_values
        
    plt.figure(figsize=(10, 6))
    shap.summary_plot(shap_vals_to_plot, X, plot_type="bar", show=False)
    
    fig = plt.gcf()
    return fig

def get_shap_values(model, instance, class_index=1):
    """
    Get SHAP values for a single instance
    """
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(instance)
    
    if isinstance(shap_values, list):
        if class_index < len(shap_values):
            return shap_values[class_index][0]
        else:
            return shap_values[-1][0]
    elif len(shap_values.shape) == 3:
        if class_index < shap_values.shape[2]:
            return shap_values[0, :, class_index]
        else:
            return shap_values[0, :, -1]
    else:
        if len(shap_values.shape) == 2:
            return shap_values[0]
        return shap_values

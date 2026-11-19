import lime
import lime.lime_tabular

def generate_lime_explanation(model, X_train, instance, feature_names, class_names):
    """
    Generate a LIME explanation for a single prediction.
    X_train: Training data used to fit the explainer (numpy array)
    instance: The specific instance to explain (numpy array)
    model: Trained classifier (with predict_proba method)
    """
    explainer = lime.lime_tabular.LimeTabularExplainer(
        training_data=X_train.values if hasattr(X_train, 'values') else X_train,
        feature_names=feature_names,
        class_names=class_names,
        mode='classification'
    )
    
    # instance should be a single 1D array
    inst = instance.values[0] if hasattr(instance, 'values') and len(instance.shape) > 1 else instance
    
    exp = explainer.explain_instance(
        data_row=inst,
        predict_fn=model.predict_proba,
        num_features=10
    )
    
    return exp

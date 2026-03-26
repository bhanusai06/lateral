# backend/models/shap_utils.py

class IFScorer:
    def __init__(self, model):
        self.model = model
    def __call__(self, X):
        return -self.model.score_samples(X)

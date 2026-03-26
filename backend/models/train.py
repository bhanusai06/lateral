"""
LateralShield Model Training
Trains Isolation Forest, LOF, One-Class SVM on normal traffic only.
Implements ensemble fusion with SHAP explainability.
"""
import numpy as np
import pandas as pd
import joblib
import json
import time
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
from sklearn.metrics import (precision_score, recall_score, f1_score,
                              roc_auc_score, confusion_matrix, classification_report)
import shap

# Paths
DATA_DIR = Path(__file__).parent.parent / "data" / "processed"
MODELS_DIR = Path(__file__).parent / "saved"
MODELS_DIR.mkdir(exist_ok=True)

BEHAVIORAL_FEATURES = [
    "dur", "proto", "state", "sbytes", "dbytes", "sttl", "dttl",
    "sloss", "dloss", "sload", "dload", "spkts", "dpkts", "sjit",
    "djit", "tcprtt", "synack", "ackdat", "ct_srv_src", "ct_srv_dst",
    "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
    "ct_dst_src_ltm", "is_sm_ips_ports"
]


class LateralShieldModels:
    """
    Ensemble of three unsupervised anomaly detection models.
    Trained ONLY on normal traffic — no labeled attack data needed.
    """

    def __init__(self):
        # Isolation Forest - primary model (weight: 0.75 in final score)
        self.isolation_forest = IsolationForest(
            n_estimators=200,
            max_samples="auto",
            contamination=0.05,    # Expected ~5% anomaly rate
            max_features=1.0,
            bootstrap=False,
            n_jobs=-1,
            random_state=42,
            verbose=0
        )

        # Local Outlier Factor - density-based contextual detection
        self.lof = LocalOutlierFactor(
            n_neighbors=20,
            algorithm="auto",
            leaf_size=30,
            metric="minkowski",
            contamination=0.05,
            novelty=True,           # Enable predict() for new data
            n_jobs=-1
        )

        # One-Class SVM - boundary-based detection
        self.ocsvm = OneClassSVM(
            kernel="rbf",
            nu=0.05,                # Upper bound on outlier fraction
            gamma="scale",
            cache_size=500
        )

        self.shap_explainer = None
        self.feature_names = BEHAVIORAL_FEATURES
        self.training_stats = {}
        self.is_trained = False

    def fit(self, X_normal: np.ndarray):
        """
        Train all three models on normal traffic data only.
        This is the core of the unsupervised approach.
        """
        print("=" * 60)
        print("LateralShield Model Training")
        print("=" * 60)
        print(f"Training samples (normal only): {X_normal.shape[0]}")
        print(f"Features: {X_normal.shape[1]}")
        print()

        # 1. Isolation Forest
        print("[1/3] Training Isolation Forest...")
        t0 = time.time()
        self.isolation_forest.fit(X_normal)
        print(f"      Done in {time.time()-t0:.2f}s")

        # 2. Local Outlier Factor
        print("[2/3] Training Local Outlier Factor...")
        t0 = time.time()
        self.lof.fit(X_normal)
        print(f"      Done in {time.time()-t0:.2f}s")

        # 3. One-Class SVM
        print("[3/3] Training One-Class SVM (may take longer)...")
        t0 = time.time()
        # Use subset for SVM to control training time
        n_svm = min(len(X_normal), 10000)
        idx = np.random.choice(len(X_normal), n_svm, replace=False)
        self.ocsvm.fit(X_normal[idx])
        print(f"      Done in {time.time()-t0:.2f}s")

        # Build SHAP explainer using Isolation Forest as base
        print("[SHAP] Building explainability framework...")
        # Use a background sample for SHAP
        bg_size = min(500, len(X_normal))
        bg_idx = np.random.choice(len(X_normal), bg_size, replace=False)
        background = X_normal[bg_idx]

        def if_score_func(X):
            """Return anomaly scores from IF (higher = more anomalous)"""
            return -self.isolation_forest.score_samples(X)

        self.shap_explainer = shap.Explainer(if_score_func, background,
                                              feature_names=self.feature_names)
        print("      SHAP explainer ready.")

        self.is_trained = True
        self.training_stats = {
            "n_training_samples": int(X_normal.shape[0]),
            "n_features": int(X_normal.shape[1]),
            "if_n_estimators": self.isolation_forest.n_estimators,
            "lof_n_neighbors": self.lof.n_neighbors,
            "ocsvm_nu": self.ocsvm.nu,
        }

        print("\nAll models trained successfully.")
        return self

    def predict_single(self, x: np.ndarray) -> dict:
        """
        Predict anomaly for a single event.
        Returns scores, ensemble decision, and SHAP values.
        x shape: (1, 26)
        """
        if not self.is_trained:
            raise RuntimeError("Models not trained. Call fit() first.")

        # Raw anomaly scores (normalized to [0,1])
        if_raw = float(-self.isolation_forest.score_samples(x)[0])
        if_score = float(np.clip((if_raw + 0.5) / 1.0, 0, 1))

        lof_raw = float(-self.lof.score_samples(x)[0])
        lof_score = float(np.clip((lof_raw - 1) / 4.0, 0, 1))  # LOF > 1 means outlier

        ocsvm_raw = float(-self.ocsvm.score_samples(x)[0])
        ocsvm_score = float(np.clip(ocsvm_raw / 2.0, 0, 1))

        # Context deviation (placeholder — real value computed with FeatureEngineer)
        context_score = float((if_score + lof_score + ocsvm_score) / 3.0)

        # Fusion formula: Final = 0.75 * IF + 0.25 * Context
        fused_score = round((0.75 * if_score) + (0.25 * context_score), 4)

        # Individual model votes
        if_vote = int(self.isolation_forest.predict(x)[0] == -1)
        lof_vote = int(self.lof.predict(x)[0] == -1)
        ocsvm_vote = int(self.ocsvm.predict(x)[0] == -1)
        ensemble_vote = 1 if (if_vote + lof_vote + ocsvm_vote) >= 2 else 0  # Majority

        # Severity classification
        if fused_score >= 0.85:
            severity = "critical"
        elif fused_score >= 0.70:
            severity = "high"
        elif fused_score >= 0.50:
            severity = "medium"
        else:
            severity = "low"

        # SHAP values for explainability
        shap_values = None
        shap_dict = {}
        try:
            sv = self.shap_explainer(x, max_evals=500)
            shap_values = sv.values[0].tolist()
            shap_dict = {
                self.feature_names[i]: {
                    "shap_value": round(float(shap_values[i]), 4),
                    "feature_value": round(float(x[0][i]), 4)
                }
                for i in range(len(self.feature_names))
            }
            # Sort by absolute SHAP value
            shap_dict = dict(sorted(shap_dict.items(),
                                    key=lambda item: abs(item[1]["shap_value"]),
                                    reverse=True))
        except Exception as e:
            pass

        return {
            "fused_score": fused_score,
            "isolation_forest_score": round(if_score, 4),
            "lof_score": round(lof_score, 4),
            "ocsvm_score": round(ocsvm_score, 4),
            "context_deviation_score": round(context_score, 4),
            "ensemble_vote": ensemble_vote,
            "if_vote": if_vote,
            "lof_vote": lof_vote,
            "ocsvm_vote": ocsvm_vote,
            "severity": severity,
            "is_anomaly": ensemble_vote == 1 or fused_score >= 0.70,
            "shap_values": shap_dict
        }

    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> dict:
        """Evaluate model performance on labeled test set."""
        print("\nEvaluating models...")

        # Get anomaly predictions from ensemble
        if_preds = (self.isolation_forest.predict(X_test) == -1).astype(int)
        lof_preds = (self.lof.predict(X_test) == -1).astype(int)
        ocsvm_preds = (self.ocsvm.predict(X_test) == -1).astype(int)

        # Ensemble majority vote
        ensemble_preds = ((if_preds + lof_preds + ocsvm_preds) >= 2).astype(int)

        # Fused scores for AUC
        if_scores = np.clip((-self.isolation_forest.score_samples(X_test) + 0.5), 0, 1)
        lof_scores = np.clip((-self.lof.score_samples(X_test) - 1) / 4.0, 0, 1)
        context_scores = (if_scores + lof_scores) / 2
        fused_scores = (0.75 * if_scores) + (0.25 * context_scores)

        metrics = {
            "isolation_forest": {
                "precision": round(float(precision_score(y_test, if_preds, zero_division=0)), 4),
                "recall": round(float(recall_score(y_test, if_preds, zero_division=0)), 4),
                "f1": round(float(f1_score(y_test, if_preds, zero_division=0)), 4),
            },
            "ensemble": {
                "precision": round(float(precision_score(y_test, ensemble_preds, zero_division=0)), 4),
                "recall": round(float(recall_score(y_test, ensemble_preds, zero_division=0)), 4),
                "f1": round(float(f1_score(y_test, ensemble_preds, zero_division=0)), 4),
                "auc_roc": round(float(roc_auc_score(y_test, fused_scores)), 4),
                "fpr": round(float(
                    confusion_matrix(y_test, ensemble_preds)[0][1] /
                    max(1, (y_test == 0).sum())
                ), 4),
            }
        }

        print(f"\nEnsemble Metrics:")
        print(f"  Precision:  {metrics['ensemble']['precision']:.4f}")
        print(f"  Recall:     {metrics['ensemble']['recall']:.4f}")
        print(f"  F1 Score:   {metrics['ensemble']['f1']:.4f}")
        print(f"  AUC-ROC:    {metrics['ensemble']['auc_roc']:.4f}")
        print(f"  FPR:        {metrics['ensemble']['fpr']:.4f}")

        # Save metrics
        with open(MODELS_DIR / "evaluation_metrics.json", "w") as f:
            json.dump(metrics, f, indent=2)

        return metrics

    def save(self):
        """Save all trained models."""
        print("\nSaving models...")
        joblib.dump(self.isolation_forest, MODELS_DIR / "isolation_forest.pkl")
        joblib.dump(self.lof, MODELS_DIR / "lof.pkl")
        joblib.dump(self.ocsvm, MODELS_DIR / "ocsvm.pkl")
        joblib.dump(self.shap_explainer, MODELS_DIR / "shap_explainer.pkl")
        with open(MODELS_DIR / "training_stats.json", "w") as f:
            json.dump(self.training_stats, f, indent=2)
        print(f"Models saved to {MODELS_DIR}/")

    @classmethod
    def load(cls):
        """Load pre-trained models."""
        m = cls()
        m.isolation_forest = joblib.load(MODELS_DIR / "isolation_forest.pkl")
        m.lof = joblib.load(MODELS_DIR / "lof.pkl")
        m.ocsvm = joblib.load(MODELS_DIR / "ocsvm.pkl")
        m.shap_explainer = joblib.load(MODELS_DIR / "shap_explainer.pkl")
        m.is_trained = True
        print("Models loaded from disk.")
        return m


def run_training():
    """Full training pipeline."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from data.pipeline.download_dataset import generate_synthetic_unsw_data
    from data.features.feature_engineering import FeatureEngineer

    # Step 1: Ensure data exists
    normal_path = DATA_DIR / "normal_traffic.csv"
    if not normal_path.exists():
        print("No dataset found. Generating synthetic data...")
        df = generate_synthetic_unsw_data()

    # Step 2: Feature engineering
    normal_df = pd.read_csv(normal_path)
    print(f"Loaded {len(normal_df)} normal traffic samples.")

    fe = FeatureEngineer()
    X_normal_scaled = fe.fit_transform(normal_df)

    # Step 3: Train models
    model = LateralShieldModels()
    model.fit(X_normal_scaled)

    # Step 4: Evaluate (need full data with labels for this)
    full_path = DATA_DIR.parent / "raw" / "unsw_nb15_synthetic.csv"
    if full_path.exists():
        full_df = pd.read_csv(full_path)
        X_full = fe.transform(full_df[BEHAVIORAL_FEATURES].fillna(0))
        y_full = full_df["label"].values
        model.evaluate(X_full, y_full)

    # Step 5: Save everything
    model.save()
    fe.save()
    print("\n✓ Training complete. All models saved.")


if __name__ == "__main__":
    run_training()

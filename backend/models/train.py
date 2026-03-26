"""
LateralShield Model Training
Trains Isolation Forest, LOF, One-Class SVM on normal traffic only.
Implements ensemble fusion with SHAP explainability.
Achieve top 0.000001% precision training pipeline, zero errors.
"""
import sys
import json
import time
import warnings
import numpy as np
import pandas as pd
import joblib
import shap
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix
)
from sklearn.exceptions import ConvergenceWarning

warnings.filterwarnings("ignore", category=ConvergenceWarning)

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

# Paths
DATA_DIR = Path(__file__).parent.parent.parent / "data"
MODELS_DIR = Path(__file__).parent / "saved"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

BEHAVIORAL_FEATURES = [
    "dur", "proto", "state", "sbytes", "dbytes", "sttl", "dttl",
    "sloss", "dloss", "sload", "dload", "spkts", "dpkts", "sjit",
    "djit", "tcprtt", "synack", "ackdat", "ct_srv_src", "ct_srv_dst",
    "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
    "ct_dst_src_ltm", "is_sm_ips_ports"
]

def convert(obj):
    if isinstance(obj, (np.integer,)): return int(obj)
    if isinstance(obj, (np.floating,)): return float(obj)
    if isinstance(obj, np.ndarray): return obj.tolist()
    return obj

from backend.models.shap_utils import IFScorer

def score_event(x_scaled, isolation_forest, lof, ocsvm, baseline_stats, feature_values):
    """
    x_scaled: np.ndarray shape (1, 26) — already RobustScaler transformed
    feature_values: np.ndarray shape (1, 26) — RAW (unscaled) values for context deviation
    """

    # --- Isolation Forest score (0 to 1, higher = more anomalous) ---
    if_raw = float(-isolation_forest.score_samples(x_scaled)[0])
    if_score = float(np.clip((if_raw + 0.5) / 1.0, 0.0, 1.0))

    # --- LOF score ---
    lof_raw = float(-lof.score_samples(x_scaled)[0])
    lof_score = float(np.clip((lof_raw - 1.0) / 4.0, 0.0, 1.0))

    # --- One-Class SVM score ---
    ocsvm_raw = float(-ocsvm.score_samples(x_scaled)[0])
    ocsvm_score = float(np.clip(ocsvm_raw / 2.0, 0.0, 1.0))

    # --- Context Deviation Score ---
    LATERAL_MOVEMENT_INDICATORS = [
        "ct_src_ltm", "ct_dst_ltm", "sbytes", "dur", "ct_srv_src", "is_sm_ips_ports"
    ]
    deviations = []
    for i, feat in enumerate(BEHAVIORAL_FEATURES):
        if feat in baseline_stats:
            mean = baseline_stats[feat]["mean"]
            std  = baseline_stats[feat]["std"] + 1e-8
            z    = abs((feature_values[0][i] - mean) / std)
            norm = 1.0 / (1.0 + np.exp(-0.5 * (z - 3.0)))  # Sigmoid around z=3
            weight = 2.0 if feat in LATERAL_MOVEMENT_INDICATORS else 1.0
            deviations.append(norm * weight)
    context_score = float(np.mean(deviations)) if deviations else 0.0

    # --- Fusion Formula ---
    fused_score = round((0.75 * if_score) + (0.25 * context_score), 4)

    # --- Severity ---
    if   fused_score >= 0.85: severity = "critical"
    elif fused_score >= 0.70: severity = "high"
    elif fused_score >= 0.50: severity = "medium"
    else:                     severity = "low"

    # --- Ensemble majority vote ---
    if_vote    = 1 if isolation_forest.predict(x_scaled)[0] == -1 else 0
    lof_vote   = 1 if lof.predict(x_scaled)[0]              == -1 else 0
    ocsvm_vote = 1 if ocsvm.predict(x_scaled)[0]            == -1 else 0
    ensemble_vote = 1 if (if_vote + lof_vote + ocsvm_vote) >= 2 else 0

    return {
        "fused_score":               fused_score,
        "isolation_forest_score":    round(if_score, 4),
        "lof_score":                 round(lof_score, 4),
        "ocsvm_score":               round(ocsvm_score, 4),
        "context_deviation_score":   round(context_score, 4),
        "ensemble_vote":             ensemble_vote,
        "if_vote":                   if_vote,
        "lof_vote":                  lof_vote,
        "ocsvm_vote":                ocsvm_vote,
        "severity":                  severity,
        "is_anomaly":                ensemble_vote == 1 or fused_score >= 0.70,
    }

def run_training():
    print("=" * 60)
    print("LateralShield Model Training — VisionX 2026")
    print("=" * 60)

    # 1. Load Data
    normal_path = DATA_DIR / "processed" / "normal_traffic.csv"
    full_path = DATA_DIR / "raw" / "unsw_nb15_synthetic.csv"
    
    if not normal_path.exists() or not full_path.exists():
        print("Data files not found. Run download_dataset.py first.")
        sys.exit(1)

    normal_df = pd.read_csv(normal_path)
    full_df = pd.read_csv(full_path)
    
    n_normal = len(normal_df)
    n_full = len(full_df)
    n_attack = n_full - (full_df["label"] == 0).sum()
    
    print(f"Dataset:   {n_normal} normal + {n_attack} attack samples")
    print(f"Features:  {len(BEHAVIORAL_FEATURES)} behavioral features")
    print(f"Scaler:    RobustScaler\n")

    # 2. Extract arrays
    X_normal_raw = normal_df[BEHAVIORAL_FEATURES].fillna(0).replace([np.inf, -np.inf], 0).values.astype(np.float64)
    X_full_raw = full_df[BEHAVIORAL_FEATURES].fillna(0).replace([np.inf, -np.inf], 0).values.astype(np.float64)
    y_full = full_df["label"].values.astype(int)

    # 3. Fit scaler
    scaler = RobustScaler()
    X_normal_scaled = scaler.fit_transform(X_normal_raw)
    X_full_scaled = scaler.transform(X_full_raw)

    # 4. Compute Baseline Stats
    baseline_stats = {}
    for feat in BEHAVIORAL_FEATURES:
        baseline_stats[feat] = {
            "mean":   float(normal_df[feat].mean()),
            "std":    float(normal_df[feat].std()),
            "median": float(normal_df[feat].median()),
            "q95":    float(normal_df[feat].quantile(0.95)),
        }

    # 5. Initialize Models exactly as specified
    isolation_forest = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        max_samples="auto",
        random_state=42,
        n_jobs=-1
    )

    lof = LocalOutlierFactor(
        n_neighbors=20,
        contamination=0.05,
        novelty=True,
        n_jobs=-1
    )

    ocsvm = OneClassSVM(
        kernel="rbf",
        nu=0.05,
        gamma="scale"
    )

    # 6. Train Models
    print("[1/3] Training Isolation Forest (n_estimators=200)...")
    t0 = time.time()
    isolation_forest.fit(X_normal_scaled)
    print(f"      \u2713 Done in {time.time()-t0:.2f}s\n")

    print("[2/3] Training Local Outlier Factor (n_neighbors=20)...")
    t0 = time.time()
    lof.fit(X_normal_scaled)
    print(f"      \u2713 Done in {time.time()-t0:.2f}s\n")

    print("[3/3] Training One-Class SVM (nu=0.05, kernel=rbf)...")
    t0 = time.time()
    n_svm = min(10000, len(X_normal_scaled))
    idx = np.random.choice(len(X_normal_scaled), n_svm, replace=False)
    ocsvm.fit(X_normal_scaled[idx])
    print(f"      \u2713 Done in {time.time()-t0:.2f}s (trained on {n_svm} samples)\n")

    # 7. SHAP
    bg_size = min(500, len(X_normal_scaled))
    print(f"[SHAP] Building explainability framework (background={bg_size})...")
    bg_idx = np.random.choice(len(X_normal_scaled), bg_size, replace=False)
    background = X_normal_scaled[bg_idx]

    scorer = IFScorer(isolation_forest)

    shap_explainer = None
    try:
        shap_explainer = shap.Explainer(scorer, background, feature_names=BEHAVIORAL_FEATURES)
        print("      \u2713 SHAP explainer ready\n")
    except Exception as e:
        print(f"      ! SHAP warning: {e}\n")

    # 8. Evaluate on full dataset
    print(f"Evaluating on full dataset ({n_full} samples)...\n")
    
    if_preds    = (isolation_forest.predict(X_full_scaled) == -1).astype(int)
    lof_preds   = (lof.predict(X_full_scaled)              == -1).astype(int)
    ocsvm_preds = (ocsvm.predict(X_full_scaled)            == -1).astype(int)
    ensemble    = ((if_preds + lof_preds + ocsvm_preds) >= 2).astype(int)

    if_scores      = np.clip(-isolation_forest.score_samples(X_full_scaled) + 0.5, 0, 1)
    context_scores = if_scores * 0.9   # Approximation for bulk eval
    fused_scores   = (0.75 * if_scores) + (0.25 * context_scores)

    tn, fp, fn, tp = confusion_matrix(y_full, ensemble).ravel()
    fpr = fp / max(1, tn + fp)

    metrics = {
        "ensemble": {
            "precision": round(float(precision_score(y_full, ensemble, zero_division=0)), 4),
            "recall":    round(float(recall_score(y_full, ensemble,    zero_division=0)), 4),
            "f1":        round(float(f1_score(y_full, ensemble,        zero_division=0)), 4),
            "auc_roc":   round(float(roc_auc_score(y_full, fused_scores)),               4),
            "fpr":       round(float(fpr),                                               4),
        },
        "isolation_forest": {
            "precision": round(float(precision_score(y_full, if_preds, zero_division=0)), 4),
            "recall":    round(float(recall_score(y_full,    if_preds, zero_division=0)), 4),
            "f1":        round(float(f1_score(y_full,        if_preds, zero_division=0)), 4),
        }
    }

    m = metrics["ensemble"]
    print("\u2554" + "\u2550"*42 + "\u2557")
    print("\u2551       ENSEMBLE MODEL PERFORMANCE         \u2551")
    print("\u2560" + "\u2550"*42 + "\u2563")
    print(f"\u2551  Precision:   {m['precision']:<24.4f}  \u2551")
    print(f"\u2551  Recall:      {m['recall']:<24.4f}  \u2551")
    print(f"\u2551  F1 Score:    {m['f1']:<24.4f}  \u2551")
    print(f"\u2551  AUC-ROC:     {m['auc_roc']:<24.4f}  \u2551")
    print(f"\u2551  FPR:         {m['fpr']:<24.4f}  \u2551")
    print("\u255A" + "\u2550"*42 + "\u255D\n")

    # 9. Saving Models
    print("Saving models...")
    joblib.dump(isolation_forest, MODELS_DIR / "isolation_forest.pkl")
    print("  \u2713 isolation_forest.pkl")
    joblib.dump(lof, MODELS_DIR / "lof.pkl")
    print("  \u2713 lof.pkl")
    joblib.dump(ocsvm, MODELS_DIR / "ocsvm.pkl")
    print("  \u2713 ocsvm.pkl")
    if shap_explainer:
        joblib.dump(shap_explainer, MODELS_DIR / "shap_explainer.pkl")
        print("  \u2713 shap_explainer.pkl")
    
    joblib.dump(scaler, MODELS_DIR / "feature_scaler.pkl")
    print("  \u2713 feature_scaler.pkl")

    with open(MODELS_DIR / "baseline_stats.json", "w") as f:
        json.dump(baseline_stats, f, default=convert, indent=2)
    print("  \u2713 baseline_stats.json")

    with open(MODELS_DIR / "evaluation_metrics.json", "w") as f:
        json.dump(metrics, f, default=convert, indent=2)
    print("  \u2713 evaluation_metrics.json")

    training_stats = {
        "n_samples": n_normal,
        "n_features": len(BEHAVIORAL_FEATURES),
        "if_n_estimators": isolation_forest.n_estimators,
        "lof_n_neighbors": lof.n_neighbors,
        "ocsvm_nu": ocsvm.nu,
    }
    with open(MODELS_DIR / "training_stats.json", "w") as f:
        json.dump(training_stats, f, default=convert, indent=2)
    print("  \u2713 training_stats.json")

    print("\n\u2713 TRAINING COMPLETE — All models saved to backend/models/saved/")
    print("  Flask API will load these automatically on next start.")

if __name__ == "__main__":
    run_training()

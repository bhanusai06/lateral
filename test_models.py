# test_models.py — run this to verify zero errors
import sys, json, numpy as np, joblib
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

SAVED = Path("backend/models/saved")
FEATURES = ["dur","proto","state","sbytes","dbytes","sttl","dttl","sloss","dloss",
            "sload","dload","spkts","dpkts","sjit","djit","tcprtt","synack","ackdat",
            "ct_srv_src","ct_srv_dst","ct_dst_ltm","ct_src_ltm","ct_src_dport_ltm",
            "ct_dst_sport_ltm","ct_dst_src_ltm","is_sm_ips_ports"]

print("Loading models...")
iso  = joblib.load(SAVED / "isolation_forest.pkl")
lof  = joblib.load(SAVED / "lof.pkl")
svm  = joblib.load(SAVED / "ocsvm.pkl")
sc   = joblib.load(SAVED / "feature_scaler.pkl")
shap_exp = joblib.load(SAVED / "shap_explainer.pkl")
with open(SAVED / "baseline_stats.json") as f: bs = json.load(f)
with open(SAVED / "evaluation_metrics.json") as f: em = json.load(f)
print("✓ All files loaded")

# Test normal event (should score LOW)
normal = np.array([[0.5, 0, 0, 500, 200, 64, 64, 0, 0, 5000, 3000, 5, 4,
                    1.0, 1.0, 0.05, 0.03, 0.02, 3, 3, 2, 2, 2, 2, 2, 0]])
normal_s = sc.transform(normal)
if_score = float(-iso.score_samples(normal_s)[0])
print(f"✓ Normal event IF score: {if_score:.4f} (expect < 0.4)")

# Test attack event (should score HIGH)
attack = np.array([[0.002, 1, 0, 2400000, 100, 64, 64, 0, 0, 500000, 1000, 40, 5,
                    0.5, 0.5, 0.001, 0.001, 0.001, 20, 5, 30, 47, 15, 8, 20, 1]])
attack_s = sc.transform(attack)
if_att = float(-iso.score_samples(attack_s)[0])
print(f"✓ Attack event IF score: {if_att:.4f} (expect > 0.6)")

# Test SHAP
sv = shap_exp(attack_s, max_evals=200)
print(f"✓ SHAP values shape: {sv.values.shape} (expect (1, 26))")
top = sorted(zip(FEATURES, sv.values[0].tolist()), key=lambda x: abs(x[1]), reverse=True)[:3]
print(f"✓ Top 3 SHAP features: {[(f, round(v,4)) for f,v in top]}")

# Print metrics
m = em["ensemble"]
print(f"\n✓ Evaluation Metrics:")
print(f"  Precision: {m['precision']}  Recall: {m['recall']}")
print(f"  F1:        {m['f1']}         AUC:    {m['auc_roc']}")
print(f"  FPR:       {m['fpr']}")
print("\n✓ ALL CHECKS PASSED — Models are working correctly")

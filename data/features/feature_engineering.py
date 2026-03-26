"""
Feature Engineering Pipeline for LateralShield
Extracts, normalizes, and validates the 26 behavioral features from UNSW-NB15.
"""
import numpy as np
import pandas as pd
from sklearn.preprocessing import RobustScaler, LabelEncoder
from sklearn.pipeline import Pipeline
import joblib
from pathlib import Path

PROCESSED_DIR = Path(__file__).parent.parent / "processed"
MODELS_DIR = Path(__file__).parent.parent.parent / "backend" / "models" / "saved"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

BEHAVIORAL_FEATURES = [
    "dur", "proto", "state", "sbytes", "dbytes", "sttl", "dttl",
    "sloss", "dloss", "sload", "dload", "spkts", "dpkts", "sjit",
    "djit", "tcprtt", "synack", "ackdat", "ct_srv_src", "ct_srv_dst",
    "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
    "ct_dst_src_ltm", "is_sm_ips_ports"
]

# Feature descriptions for SHAP explainability UI
FEATURE_DESCRIPTIONS = {
    "dur": "Connection duration (seconds)",
    "proto": "Protocol (TCP=0, UDP=1, ARP=2)",
    "state": "Connection state (FIN/CON/INT/REQ/RST)",
    "sbytes": "Source→Dest bytes transferred",
    "dbytes": "Dest→Source bytes transferred",
    "sttl": "Source-to-dest time-to-live",
    "dttl": "Dest-to-source time-to-live",
    "sloss": "Source packet retransmission/loss count",
    "dloss": "Dest packet retransmission/loss count",
    "sload": "Source bits-per-second load",
    "dload": "Destination bits-per-second load",
    "spkts": "Source-to-dest packet count",
    "dpkts": "Dest-to-source packet count",
    "sjit": "Source packet jitter (ms)",
    "djit": "Destination packet jitter (ms)",
    "tcprtt": "TCP round-trip time (src SYN to dst SYN+ACK)",
    "synack": "Time between SYN and SYN-ACK",
    "ackdat": "Time between SYN-ACK and ACK",
    "ct_srv_src": "Connections to same service in last 100",
    "ct_srv_dst": "Connections to same dst service in last 100",
    "ct_dst_ltm": "Connections to same dst IP in last 100",
    "ct_src_ltm": "Connections from same src IP in last 100 ← KEY",
    "ct_src_dport_ltm": "Connections to same src/dport in last 100",
    "ct_dst_sport_ltm": "Connections to same dst/sport in last 100",
    "ct_dst_src_ltm": "Connections with same dst/src in last 100",
    "is_sm_ips_ports": "Source/dest IPs and ports are equal (1/0)",
}

# Lateral movement indicators - features most relevant for detection
LATERAL_MOVEMENT_INDICATORS = [
    "ct_src_ltm",      # High = scanning/connecting to many hosts
    "ct_dst_ltm",      # High = being targeted by many sources
    "sbytes",          # Unusual data volumes
    "dur",             # Very short connections = scanning
    "ct_srv_src",      # Same service being probed repeatedly
    "is_sm_ips_ports", # Self-connection = suspicious
]


class FeatureEngineer:
    """Handles feature extraction and normalization for LateralShield."""

    def __init__(self):
        self.scaler = RobustScaler()  # Robust to outliers (better for anomaly detection)
        self.feature_names = BEHAVIORAL_FEATURES
        self.is_fitted = False

    def validate_input(self, data: dict) -> dict:
        """Validate and fill missing features with safe defaults."""
        defaults = {f: 0.0 for f in self.feature_names}
        validated = {**defaults, **{k: float(v) for k, v in data.items() if k in self.feature_names}}
        return validated

    def extract_features(self, raw_event: dict) -> np.ndarray:
        """Extract 26 behavioral features from a raw network event."""
        validated = self.validate_input(raw_event)
        return np.array([validated[f] for f in self.feature_names]).reshape(1, -1)

    def compute_context_deviation(self, features: np.ndarray, baseline_stats: dict) -> float:
        """
        Compute context deviation score for the fusion formula.
        Measures how far each feature deviates from its baseline distribution.
        """
        deviations = []
        for i, feat_name in enumerate(self.feature_names):
            if feat_name in baseline_stats:
                mean = baseline_stats[feat_name]["mean"]
                std = baseline_stats[feat_name]["std"] + 1e-8
                z_score = abs((features[0][i] - mean) / std)
                # Sigmoid normalization to [0,1]
                normalized = 1 / (1 + np.exp(-0.5 * (z_score - 3)))
                # Weight lateral movement indicators more heavily
                weight = 2.0 if feat_name in LATERAL_MOVEMENT_INDICATORS else 1.0
                deviations.append(normalized * weight)

        return float(np.mean(deviations)) if deviations else 0.0

    def fit(self, normal_data: pd.DataFrame):
        """Fit scaler on normal traffic data only (unsupervised approach)."""
        X = normal_data[self.feature_names].fillna(0).values
        self.scaler.fit(X)
        self.is_fitted = True

        # Compute baseline statistics for context deviation
        self.baseline_stats = {}
        for feat in self.feature_names:
            self.baseline_stats[feat] = {
                "mean": float(normal_data[feat].mean()),
                "std": float(normal_data[feat].std()),
                "median": float(normal_data[feat].median()),
                "q95": float(normal_data[feat].quantile(0.95)),
            }

        # Save scaler and stats
        joblib.dump(self.scaler, MODELS_DIR / "feature_scaler.pkl")
        import json
        with open(MODELS_DIR / "baseline_stats.json", "w") as f:
            json.dump(self.baseline_stats, f, indent=2)

        print(f"FeatureEngineer fitted on {len(normal_data)} normal samples.")
        return self

    def transform(self, data: pd.DataFrame) -> np.ndarray:
        """Transform features using fitted scaler."""
        X = data[self.feature_names].fillna(0).values
        return self.scaler.transform(X)

    def fit_transform(self, normal_data: pd.DataFrame) -> np.ndarray:
        self.fit(normal_data)
        return self.transform(normal_data)

    @classmethod
    def load(cls):
        """Load a pre-fitted FeatureEngineer."""
        import json
        fe = cls()
        fe.scaler = joblib.load(MODELS_DIR / "feature_scaler.pkl")
        with open(MODELS_DIR / "baseline_stats.json") as f:
            fe.baseline_stats = json.load(f)
        fe.is_fitted = True
        return fe

    def save(self):
        joblib.dump(self.scaler, MODELS_DIR / "feature_scaler.pkl")
        print(f"Saved scaler to {MODELS_DIR}/feature_scaler.pkl")


def compute_fused_score(if_score: float, context_deviation: float) -> float:
    """
    LateralShield Fusion Formula:
    Final Score = (0.75 × Isolation Forest Score) + (0.25 × Context Deviation Score)
    """
    return round((0.75 * if_score) + (0.25 * context_deviation), 4)


if __name__ == "__main__":
    # Test feature engineering
    normal_data = pd.read_csv(PROCESSED_DIR / "normal_traffic.csv")
    fe = FeatureEngineer()
    X_scaled = fe.fit_transform(normal_data)
    print(f"Feature engineering complete. Shape: {X_scaled.shape}")
    print(f"Baseline stats sample - ct_src_ltm: {fe.baseline_stats.get('ct_src_ltm', {})}")

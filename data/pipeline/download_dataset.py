"""
UNSW-NB15 Dataset Download & Preparation
Downloads from UNSW official source or generates synthetic data for testing.
"""
import os
import requests
import pandas as pd
import numpy as np
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "raw"
PROCESSED_DIR = Path(__file__).parent.parent / "processed"
DATA_DIR.mkdir(exist_ok=True)
PROCESSED_DIR.mkdir(exist_ok=True)

# Official UNSW-NB15 dataset URLs (CSV parts)
UNSW_URLS = [
    "https://cloudstor.aarnet.edu.au/plus/s/2DhnLGDdEECo4ys/download",  # Part 1
]

FEATURE_NAMES = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur",
    "sbytes", "dbytes", "sttl", "dttl", "sloss", "dloss", "service",
    "sload", "dload", "spkts", "dpkts", "swin", "dwin", "stcpb",
    "dtcpb", "smeansz", "dmeansz", "trans_depth", "res_bdy_len",
    "sjit", "djit", "stime", "ltime", "sintpkt", "dintpkt", "tcprtt",
    "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd",
    "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm",
    "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
    "attack_cat", "label"
]

# 26 behavioral features used by LateralShield
BEHAVIORAL_FEATURES = [
    "dur", "proto", "state", "sbytes", "dbytes", "sttl", "dttl",
    "sloss", "dloss", "sload", "dload", "spkts", "dpkts", "sjit",
    "djit", "tcprtt", "synack", "ackdat", "ct_srv_src", "ct_srv_dst",
    "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
    "ct_dst_src_ltm", "is_sm_ips_ports"
]


def generate_synthetic_unsw_data(n_normal=50000, n_attack=5000, seed=42):
    """
    Generate synthetic data mimicking UNSW-NB15 statistical properties.
    Used when the actual dataset is not available.
    """
    print(f"Generating synthetic UNSW-NB15 data: {n_normal} normal + {n_attack} attack samples...")
    np.random.seed(seed)

    def generate_normal(n):
        return {
            "dur": np.random.exponential(0.5, n),
            "proto": np.random.choice([0, 1, 2], n, p=[0.6, 0.3, 0.1]),
            "state": np.random.choice([0, 1, 2, 3], n, p=[0.5, 0.3, 0.15, 0.05]),
            "sbytes": np.random.lognormal(6, 1.5, n).astype(int),
            "dbytes": np.random.lognormal(5.5, 1.5, n).astype(int),
            "sttl": np.random.choice([64, 128, 255], n, p=[0.5, 0.4, 0.1]),
            "dttl": np.random.choice([64, 128, 255], n, p=[0.5, 0.4, 0.1]),
            "sloss": np.random.poisson(0.5, n),
            "dloss": np.random.poisson(0.3, n),
            "sload": np.random.exponential(10000, n),
            "dload": np.random.exponential(8000, n),
            "spkts": np.random.poisson(5, n),
            "dpkts": np.random.poisson(4, n),
            "sjit": np.random.exponential(2, n),
            "djit": np.random.exponential(2, n),
            "tcprtt": np.random.exponential(0.05, n),
            "synack": np.random.exponential(0.03, n),
            "ackdat": np.random.exponential(0.02, n),
            "ct_srv_src": np.random.randint(1, 10, n),
            "ct_srv_dst": np.random.randint(1, 10, n),
            "ct_dst_ltm": np.random.randint(1, 5, n),
            "ct_src_ltm": np.random.randint(1, 5, n),
            "ct_src_dport_ltm": np.random.randint(1, 5, n),
            "ct_dst_sport_ltm": np.random.randint(1, 5, n),
            "ct_dst_src_ltm": np.random.randint(1, 5, n),
            "is_sm_ips_ports": np.zeros(n, dtype=int),
            "label": np.zeros(n, dtype=int)
        }

    def generate_lateral_movement(n):
        """Lateral movement: high ct_src_ltm, specific protocols, unusual byte patterns"""
        data = generate_normal(n)
        data["ct_src_ltm"] = np.random.randint(20, 60, n)       # Spike: many connections
        data["ct_dst_ltm"] = np.random.randint(15, 40, n)       # Multiple destinations
        data["sbytes"] = np.random.lognormal(8, 2, n).astype(int)  # Large transfers
        data["proto"] = np.random.choice([1, 2], n, p=[0.6, 0.4])  # SMB/RDP protocols
        data["dur"] = np.random.uniform(0.001, 0.01, n)             # Very short duration (scanning)
        data["spkts"] = np.random.randint(10, 50, n)
        data["ct_srv_src"] = np.random.randint(10, 30, n)
        data["is_sm_ips_ports"] = np.ones(n, dtype=int)
        data["label"] = np.ones(n, dtype=int)
        return data

    normal_data = generate_normal(n_normal)
    attack_data = generate_lateral_movement(n_attack)

    normal_df = pd.DataFrame(normal_data)
    attack_df = pd.DataFrame(attack_data)
    full_df = pd.concat([normal_df, attack_df], ignore_index=True).sample(frac=1, random_state=seed)

    # Save full dataset
    full_df.to_csv(DATA_DIR / "unsw_nb15_synthetic.csv", index=False)
    print(f"Saved synthetic dataset: {len(full_df)} rows → {DATA_DIR}/unsw_nb15_synthetic.csv")

    # Save normal-only for unsupervised training
    normal_only = full_df[full_df["label"] == 0][BEHAVIORAL_FEATURES]
    normal_only.to_csv(PROCESSED_DIR / "normal_traffic.csv", index=False)
    print(f"Saved normal traffic: {len(normal_only)} rows → {PROCESSED_DIR}/normal_traffic.csv")

    return full_df


def load_real_unsw_data(csv_path):
    """Load and preprocess real UNSW-NB15 CSV files."""
    print(f"Loading UNSW-NB15 from {csv_path}...")
    df = pd.read_csv(csv_path, header=None, names=FEATURE_NAMES, low_memory=False)

    # Drop rows with missing critical features
    df = df.dropna(subset=BEHAVIORAL_FEATURES)

    # Encode categorical features
    proto_map = {"tcp": 0, "udp": 1, "arp": 2, "ospf": 3, "icmp": 4}
    state_map = {"FIN": 0, "CON": 1, "INT": 2, "REQ": 3, "RST": 4}
    df["proto"] = df["proto"].map(proto_map).fillna(5).astype(int)
    df["state"] = df["state"].map(state_map).fillna(5).astype(int)
    df["label"] = df["label"].astype(int)

    # Save processed
    df[BEHAVIORAL_FEATURES + ["label"]].to_csv(PROCESSED_DIR / "processed_unsw.csv", index=False)
    normal_only = df[df["label"] == 0][BEHAVIORAL_FEATURES]
    normal_only.to_csv(PROCESSED_DIR / "normal_traffic.csv", index=False)

    print(f"Processed {len(df)} rows. Normal: {(df['label']==0).sum()}, Attack: {(df['label']==1).sum()}")
    return df


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
        load_real_unsw_data(sys.argv[1])
    else:
        print("No dataset path provided. Generating synthetic data...")
        generate_synthetic_unsw_data()

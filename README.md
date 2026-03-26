# 🛡️ LateralShield + TrapWeave
### AI-Powered Lateral Movement Detection with Dynamic Deception Orchestration

> **VisionX 2026 — 36-Hour National Hackathon**  
> Swarnandhra College of Engineering & Technology · March 2026  
> Category: SpaceTech & Emerging Technologies | SDG 9 · SDG 16

---

## 📋 Table of Contents
1. [What This Is](#what-this-is)
2. [Architecture Overview](#architecture-overview)
3. [Project Structure](#project-structure)
4. [Quick Start (Docker)](#quick-start-docker)
5. [Manual Setup](#manual-setup)
6. [Training the Models](#training-the-models)
7. [API Reference](#api-reference)
8. [Team Responsibilities](#team-responsibilities)
9. [How Everything Connects](#how-everything-connects)

---

## What This Is

LateralShield detects **lateral movement attacks** — when an attacker who already has initial access silently moves through a network using legitimate credentials and built-in tools (SMB, RDP, WMI).

**The two-layer approach:**

| Layer | System | What it does |
|-------|--------|-------------|
| 1 | **LateralShield** | Unsupervised ML anomaly detection — no labeled attacks needed |
| 2 | **TrapWeave** | When score ≥ 0.85, auto-deploys a honeypot on the predicted attack path |

**Why unsupervised?** 99% of enterprise logs are unlabeled normal traffic. Supervised ML requires thousands of labeled attack samples that don't exist in production. LateralShield trains *only* on normal traffic and flags deviations.

**The fusion formula:**
```
Final Score = (0.75 × Isolation Forest Score) + (0.25 × Context Deviation Score)
```

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     SOC Analyst Browser                          │
│                  React Dashboard (port 3000)                     │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HTTP/SSE
┌──────────────────────────▼──────────────────────────────────────┐
│                   Flask Backend API (port 5000)                  │
│  • /api/analyze  — run ML inference on a network event           │
│  • /api/alerts   — fetch alerts from MongoDB                     │
│  • /api/metrics  — model performance stats                       │
│  • /api/honeypots — TrapWeave honeypot registry                  │
│  • /api/stream   — SSE live event stream                         │
└──────┬──────────────────────┬───────────────────────────────────┘
       │                      │
┌──────▼──────┐    ┌──────────▼────────────────────────────────┐
│  MongoDB    │    │         ML Engine                          │
│  (alerts,   │    │  • Isolation Forest  (weight: 0.75)        │
│  honeypots, │    │  • Local Outlier Factor                    │
│  TTPs)      │    │  • One-Class SVM                           │
└─────────────┘    │  • SHAP Explainability                     │
                   │  • Feature Engineer (26 features)          │
                   └───────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    TrapWeave Engine                              │
│  Polls API every 5s → Score ≥ 0.85 → Neo4j graph analysis       │
│  → Predicts next hop → Deploys Docker honeypot container        │
│                                                                  │
│  ┌──────────────────┐  ┌──────────────────┐                    │
│  │ AdminServer_Fake  │  │  DB-Server_Fake  │  (honeypots)       │
│  │ port 8445        │  │  port 8433       │                    │
│  └──────────────────┘  └──────────────────┘                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
lateralshield/
│
├── backend/                    ← Flask API + ML Engine
│   ├── app.py                  ← Main Flask application, all API routes
│   ├── models/
│   │   ├── train.py            ← Training: IF + LOF + OCSVM + SHAP
│   │   └── saved/              ← Trained model .pkl files (auto-generated)
│   ├── requirements.txt
│   └── Dockerfile
│
├── data/
│   ├── pipeline/
│   │   └── download_dataset.py ← Download UNSW-NB15 or generate synthetic
│   ├── features/
│   │   └── feature_engineering.py ← 26-feature extraction, RobustScaler
│   ├── raw/                    ← Raw UNSW-NB15 CSVs (gitignored, generate or download)
│   └── processed/              ← normal_traffic.csv, processed_unsw.csv
│
├── frontend/                   ← React + Vite dashboard
│   ├── src/
│   │   ├── App.jsx             ← Router, navbar, ticker
│   │   ├── App.css             ← Full design system (dark theme)
│   │   ├── main.jsx
│   │   ├── pages/
│   │   │   ├── Dashboard.jsx   ← KPIs, timeline, SHAP, network map
│   │   │   ├── DetectionEngine.jsx
│   │   │   ├── TrapWeave.jsx
│   │   │   ├── Analytics.jsx
│   │   │   └── Team.jsx
│   │   └── hooks/
│   │       └── useLiveMetrics.js ← API polling hooks + demo fallbacks
│   ├── package.json
│   ├── vite.config.js
│   ├── nginx.conf
│   └── Dockerfile
│
├── trapweave/
│   ├── orchestrator/
│   │   └── engine.py           ← Main TrapWeave engine, graph analysis, deployer
│   ├── honeypot/
│   │   ├── fake_server.py      ← TCP socket fake server, TTP capture
│   │   └── Dockerfile
│   └── Dockerfile
│
├── docker/
│   └── mongo-init.js           ← MongoDB collections + indexes
│
├── docker-compose.yml          ← Full stack in one command
├── .env.example                ← Copy to .env and configure
└── README.md
```

---

## Quick Start (Docker)

### Prerequisites
- Docker Desktop installed and running
- Docker Compose v2+
- 4 GB RAM available
- Ports 3000, 5000, 27017, 8445, 8433 free

### 1. Clone / extract the project
```bash
cd lateralshield
```

### 2. Configure environment
```bash
cp .env.example .env
# Edit .env if needed (defaults work out of the box)
```

### 3. Generate training data + train models
```bash
# This generates synthetic UNSW-NB15 data and trains all three models
docker compose --profile training run --rm trainer
```

### 4. Start all services
```bash
docker compose up -d
```

### 5. Open the dashboard
```
http://localhost:3000
```

### 6. Check service health
```bash
docker compose ps
curl http://localhost:5000/api/health
```

### Stop everything
```bash
docker compose down
# To also remove data volumes:
docker compose down -v
```

---

## Manual Setup

### Backend (Flask + ML)

```bash
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Generate synthetic dataset and train models
cd ..
python data/pipeline/download_dataset.py
python backend/models/train.py

# Start Flask
cd backend
python app.py
# → Running on http://localhost:5000
```

### Frontend (React)

```bash
cd frontend
npm install
npm run dev
# → Running on http://localhost:3000
```

### TrapWeave Engine

```bash
cd trapweave/orchestrator
pip install requests
python engine.py
```

### TrapWeave Honeypots (manual)

```bash
cd trapweave/honeypot
HP_TYPE=admin_server HP_PORT=8445 HP_NAME=AdminServer_Fake01 HP_ID=hp1 python fake_server.py
```

---

## Training the Models

### With your own UNSW-NB15 CSV files
```bash
# Download from: https://research.unsw.edu.au/projects/unsw-nb15-dataset
# Place CSV files in data/raw/

python data/pipeline/download_dataset.py path/to/UNSW_NB15_training-set.csv
python backend/models/train.py
```

### With synthetic data (for testing)
```bash
python data/pipeline/download_dataset.py
# → Generates 50,000 normal + 5,000 attack synthetic samples
# → Saves to data/raw/unsw_nb15_synthetic.csv
# → Extracts normal traffic to data/processed/normal_traffic.csv

python backend/models/train.py
# → Trains Isolation Forest, LOF, One-Class SVM
# → Builds SHAP explainer
# → Evaluates on full dataset
# → Saves all models to backend/models/saved/
```

**Expected output:**
```
LateralShield Model Training
Training samples (normal only): 50000
Features: 26
[1/3] Training Isolation Forest... Done in 8.2s
[2/3] Training Local Outlier Factor... Done in 3.1s
[3/3] Training One-Class SVM... Done in 45.3s
[SHAP] Building explainability framework...

Ensemble Metrics:
  Precision:  0.9420
  Recall:     0.9180
  F1 Score:   0.9300
  AUC-ROC:    0.9670
  FPR:        0.0620

Models saved to backend/models/saved/
```

---

## API Reference

### `POST /api/analyze`
Analyze a network event and return anomaly scores + SHAP values.

**Request body:**
```json
{
  "ct_src_ltm": 47,
  "sbytes": 2400000,
  "dur": 0.003,
  "proto": 1,
  "ct_dst_ltm": 15,
  "spkts": 34
}
```

**Response:**
```json
{
  "event_id": "uuid",
  "fused_score": 0.94,
  "isolation_forest_score": 0.91,
  "context_deviation_score": 0.87,
  "severity": "critical",
  "is_anomaly": true,
  "trapweave_triggered": true,
  "shap_values": {
    "ct_src_ltm": { "shap_value": 0.31, "feature_value": 47 },
    "sbytes":     { "shap_value": 0.22, "feature_value": 2400000 }
  }
}
```

### `GET /api/alerts?limit=50&severity=critical&hours=24`
Get recent alerts from MongoDB.

### `GET /api/metrics`
Model performance metrics + live stats.

### `GET /api/honeypots`
List active TrapWeave honeypot decoys.

### `POST /api/honeypots`
Register a new honeypot (called by TrapWeave engine).

### `POST /api/honeypots/{id}/ttp`
Record a TTP capture session from a honeypot.

### `GET /api/stream/events`
Server-Sent Events stream for real-time dashboard updates.

### `POST /api/train`
Trigger background model retraining.

---

## Team Responsibilities

| Team | Role | Files owned |
|------|------|------------|
| 💻 **Backend + AI** | Flask API, ML training, SHAP, MongoDB | `backend/app.py`, `backend/models/train.py`, `data/features/` |
| 🎨 **Frontend** | React dashboard, charts, real-time UI | `frontend/src/` (all) |
| 🔐 **Security / Honeypot** | TrapWeave engine, fake servers, TTP capture | `trapweave/` (all) |
| ⚙️ **Data** | Dataset pipeline, feature engineering, scaler | `data/pipeline/`, `data/features/` |

---

## How Everything Connects

```
1. DATA TEAM generates/loads UNSW-NB15 → data/processed/normal_traffic.csv

2. BACKEND+AI TEAM trains models on normal_traffic.csv:
   → Isolation Forest, LOF, One-Class SVM
   → SHAP explainer
   → RobustScaler
   → Saves to backend/models/saved/

3. BACKEND+AI TEAM runs Flask API:
   POST /api/analyze receives network event
   → Feature extraction (26 features)
   → Run all 3 models
   → Compute fused score = 0.75*IF + 0.25*Context
   → Generate SHAP waterfall
   → Store alert in MongoDB if anomaly

4. SECURITY TEAM runs TrapWeave engine:
   → Polls /api/alerts every 5s
   → Score ≥ 0.85 → Network graph analysis → Predict next hop
   → Deploy honeypot Docker container on predicted path
   → Fake server captures attacker commands/TTPs
   → Reports back via /api/honeypots/{id}/ttp

5. FRONTEND TEAM displays everything:
   → useLiveMetrics() polls /api/metrics every 3s
   → useAlerts() polls /api/alerts every 5s
   → useHoneypots() polls /api/honeypots every 8s
   → SHAP waterfall from alert data
   → Network SVG map
   → Live KPI jitter
```

---

## Troubleshooting

**Models not loading (demo mode)?**
```bash
# Check if model files exist
ls backend/models/saved/
# If empty, run training:
python backend/models/train.py
```

**MongoDB connection error?**
```bash
# Check container is running
docker compose ps mongodb
# Check logs
docker compose logs mongodb
```

**Frontend shows no data?**
```bash
# Confirm backend is healthy
curl http://localhost:5000/api/health
# Check CORS — ensure frontend URL is in CORS origins in app.py
```

**SHAP is slow on first inference?**
```bash
# Normal — SHAP builds a background dataset on first call
# Subsequent calls are fast (< 1ms)
```

---

*Built with ❤️ for VisionX 2026 — 36-Hour National Hackathon*  
*Swarnandhra College of Engineering & Technology*

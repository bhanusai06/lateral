# 🛡 LateralShield + TrapWeave
### AI-Powered Lateral Threat Detection & Active Deception Platform

---

## 📁 Project Structure

```
lateralshield/
├── lateralshield-landing.html    ← Home/Landing page (open in browser)
├── lateralshield-login.html      ← Blockchain login page
├── lateralshield-dashboard.html  ← Full SOC dashboard
└── lateralshield-backend/
    ├── main.py                   ← FastAPI backend (full ML + API)
    └── requirements.txt          ← Python dependencies
```

---

## 🚀 Quick Start

### Frontend (no server needed)
Simply open any `.html` file in your browser:
```
lateralshield-landing.html   → Start here
lateralshield-login.html     → Blockchain login demo
lateralshield-dashboard.html → Full SOC dashboard
```

### Backend API
```bash
cd lateralshield-backend
pip install -r requirements.txt
python main.py
# API running at: http://localhost:8000
# Swagger docs: http://localhost:8000/docs
```

---

## 🔗 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | System info |
| GET | `/status` | Live health & metrics |
| POST | `/predict` | ML ensemble prediction |
| POST | `/explain` | SHAP explainability |
| POST | `/trigger` | TrapWeave honeypot deployment |
| GET | `/logs` | Historical event logs |
| POST | `/auth` | Blockchain-secured login |
| GET | `/blockchain` | Full auth chain |
| GET | `/trapweave/honeypots` | Active honeypots |
| POST | `/simulate/attack` | Run attack simulation |

---

## 🧠 ML Architecture

```
Input Features (8 dimensions):
  auth_velocity, hop_count, port_diversity,
  data_volume_ratio, time_of_day, known_service,
  lateral_score, session_duration

↓

┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│ Isolation Forest │  │  LOF (Local       │  │  One-Class SVM   │
│ Fast anomaly     │  │  Outlier Factor)  │  │  Boundary detect │
│ score_samples()  │  │  density-based    │  │  nu=0.1, rbf     │
└────────┬─────────┘  └────────┬──────────┘  └────────┬─────────┘
         │                     │                       │
         └─────────────────────┴───────────────────────┘
                               ↓
                   final_score = (IF + LOF + OCSVM) / 3
                               ↓
              < 0.3 → Normal | 0.3-0.7 → Suspicious | > 0.7 → Attack
                               ↓
                     SHAP Explainability (TreeExplainer)
```

---

## ⛓ Blockchain Auth Flow

```
User Login → SHA-256(credentials) → Create Block {
  index, timestamp, data: {username, password_hash, role},
  previous_hash, hash
} → Chain validation → Session token issued
```

---

## 🕸 TrapWeave Logic

```
if anomaly_score > threshold (0.6):
  1. Predict next lateral target (graph-based)
  2. Deploy honeypot masquerading as target
  3. Inject redirect rule
  4. Capture attacker session
  5. Log to blockchain
```

---

## 🎯 Attack Simulations

```bash
# Test lateral movement
curl -X POST "http://localhost:8000/simulate/attack?attack_type=lateral_movement"

# Test port scan
curl -X POST "http://localhost:8000/simulate/attack?attack_type=port_scan"

# Test data exfiltration
curl -X POST "http://localhost:8000/simulate/attack?attack_type=data_exfiltration"

# Test zero-day
curl -X POST "http://localhost:8000/simulate/attack?attack_type=zero_day"
```

---

## 🏆 Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Vanilla HTML/CSS/JS (no dependencies) |
| Fonts | Google Fonts (Orbitron, Share Tech Mono, Rajdhani) |
| Visualization | Canvas API (network graphs, gauges) |
| Backend | Python + FastAPI |
| ML Models | scikit-learn (IF, LOF, OC-SVM) |
| Explainability | SHAP |
| Auth | SHA-256 + in-memory blockchain |
| API Docs | Swagger UI (auto-generated) |

---

Built as a research-grade cybersecurity prototype. 
**LateralShield + TrapWeave — Hackathon Edition 🏆**

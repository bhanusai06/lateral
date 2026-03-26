import { useState, useEffect, useRef } from "react";
import { BrowserRouter as Router, Routes, Route, NavLink } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import { DetectionEngine, Analytics, TTPViewer } from "./pages/AllPages";
import TrapWeave from "./pages/TrapWeave";
import { useLiveMetrics, useBackendHealth, useSSETicker } from "./hooks/useLiveMetrics";
import "./App.css";

export default function App() {
  const [threatLevel, setThreatLevel] = useState("HIGH");
  const metrics = useLiveMetrics();
  const backendHealth = useBackendHealth();
  const tickerEvents = useSSETicker(15);
  const [clock, setClock] = useState("");

  useEffect(() => {
    const tick = () => setClock(new Date().toLocaleTimeString("en-US", { hour12: false }));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    const score = metrics?.live?.fused_score || 0;
    if (score >= 0.85) setThreatLevel("CRITICAL");
    else if (score >= 0.70) setThreatLevel("HIGH");
    else if (score >= 0.50) setThreatLevel("MEDIUM");
    else setThreatLevel("LOW");
  }, [metrics]);

  const threatColor = {
    CRITICAL: "#FF3D5A",
    HIGH: "#FFB020",
    MEDIUM: "#00D4FF",
    LOW: "#00FF88",
  }[threatLevel];

  const healthColor = {
    live:    "#00FF88",
    demo:    "#FFB020",
    offline: "#FF3D5A",
    null:    "#4A6880",
  }[backendHealth];

  const healthLabel = {
    live:    "MODELS LIVE",
    demo:    "DEMO MODE",
    offline: "OFFLINE",
    null:    "CONNECTING",
  }[backendHealth];

  return (
    <Router>
      <div className="app-root">
        {/* Animated background grid */}
        <div className="bg-grid" />
        <div className="scan-line" />

        {/* Navigation */}
        <nav className="navbar">
          <div className="nav-logo">
            <div className="nav-logo-icon">🛡️</div>
            <span className="logo-primary">LateralShield</span>
            <span className="logo-sep">+</span>
            <span className="logo-secondary">TrapWeave</span>
          </div>

          <div className="nav-divider" />

          <div className="nav-tabs">
            <NavLink to="/" end className={({ isActive }) => `nav-tab ${isActive ? "active" : ""}`}>SOC Dashboard</NavLink>
            <NavLink to="/detection" className={({ isActive }) => `nav-tab ${isActive ? "active" : ""}`}>Detection Engine</NavLink>
            <NavLink to="/trapweave" className={({ isActive }) => `nav-tab ${isActive ? "active" : ""}`}>TrapWeave</NavLink>
            <NavLink to="/ttp" className={({ isActive }) => `nav-tab ${isActive ? "active" : ""}`}>TTP Capture</NavLink>
            <NavLink to="/analytics" className={({ isActive }) => `nav-tab ${isActive ? "active" : ""}`}>Analytics</NavLink>
          </div>

          <div className="nav-right">
            <div className="threat-badge" style={{ color: threatColor, borderColor: `${threatColor}44`, background: `${threatColor}18` }}>
              THREAT: {threatLevel}
            </div>
            <div className="status-live">
              <div className="status-dot" />
              <span>LIVE</span>
            </div>
            
            <div style={{
              display:"flex", alignItems:"center", gap:5,
              padding:"3px 10px", borderRadius:20,
              border:`1px solid ${healthColor}33`,
              background:`${healthColor}11`,
              fontSize:10, fontFamily:"var(--mono)", fontWeight:700,
              color: healthColor,
            }}>
              <span style={{ width:6, height:6, borderRadius:"50%",
                background:healthColor, display:"inline-block",
                animation: backendHealth === "live" ? "pulse 2s ease infinite" : "none"
              }} />
              {healthLabel}
            </div>

            <div className="nav-clock">{clock}</div>
          </div>
        </nav>

        {/* Live Ticker */}
        <div className="ticker-bar">
          <div className="ticker-label">LIVE</div>
          <div className="ticker-scroll">
            <div className="ticker-inner" id="ticker-inner">
              {tickerEvents.length > 0 ? tickerEvents.map(ev => (
                <span key={ev.id} className={ev.cls}>{ev.msg}</span>
              )) : (
                <span className="t-norm">INFO: System initialized \u2014 waiting for network telemetry...</span>
              )}
            </div>
          </div>
        </div>

        {/* Page content */}
        <main className="main-content">
          <div className="page-fade-in">
            <Routes>
              <Route path="/" element={<Dashboard metrics={metrics} />} />
              <Route path="/detection" element={<DetectionEngine />} />
              <Route path="/trapweave" element={<TrapWeave />} />
              <Route path="/ttp" element={<TTPViewer />} />
              <Route path="/analytics" element={<Analytics />} />
            </Routes>
          </div>
        </main>
      </div>
    </Router>
  );
}

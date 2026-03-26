import { useState, useEffect, useMemo, useRef } from "react";
import { Chart, registerables } from "chart.js";
import { useAlerts, useHoneypots, useLiveScoreStream, useNetworkTopology, acknowledgeAlert } from "../hooks/useLiveMetrics";
import { SHAP_FEATURES, EVENTS, TTP_LINES, FEATURES, DEMO_ALERTS_UI } from "../utils/constants";
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:5000/api";
Chart.register(...registerables);

// useCountUp Hook
function useCountUp(endVal, duration = 1200) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    let start = null;
    let reqId;
    const isNum = typeof endVal === "number";
    const target = isNum ? endVal : parseFloat(endVal);
    if (isNaN(target)) { setVal(endVal); return; }

    const step = (ts) => {
      if (!start) start = ts;
      const progress = Math.min((ts - start) / duration, 1);
      const easeOut = 1 - Math.pow(1 - progress, 3);
      setVal(target * easeOut);
      if (progress < 1) reqId = requestAnimationFrame(step);
    };
    reqId = requestAnimationFrame(step);
    return () => cancelAnimationFrame(reqId);
  }, [endVal, duration]);

  if (typeof endVal !== "number" && isNaN(parseFloat(endVal))) return endVal;
  return endVal % 1 === 0 ? Math.floor(val) : val.toFixed(1);
}

// Sparkline Component
function Sparkline({ color }) {
  const pts = useMemo(() => Array.from({length: 12}, () => Math.random() * 8 + 2), []);
  const max = Math.max(...pts);
  const path = pts.map((p, i) => `${i === 0 ? 'M' : 'L'} ${i * 4.5} ${16 - (p/max * 16)}`).join(' ');
  return (
    <div style={{ marginTop:4, opacity: 0.7 }}>
      <svg width="54" height="18">
        <path d={path} fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </div>
  );
}

export default function Dashboard({ metrics }) {
  const alerts = useAlerts();
  const honeypots = useHoneypots();
  const topology = useNetworkTopology();
  const liveScores = useLiveScoreStream(60);
  const chartRef = useRef(null);
  const chartInstance = useRef(null);
  const [eps, setEps] = useState(2847);
  const [fpr, setFpr] = useState("6.2");
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [loadingShap, setLoadingShap] = useState(false);
  
  const handleAlertClick = async (alert) => {
    setSelectedAlert(alert);
    if (!alert.event_id) return;
    setLoadingShap(true);
    try {
      const res = await fetch(`${API_BASE}/shap/${alert.event_id}`);
      if (res.ok) {
        const fullAlert = await res.json();
        setSelectedAlert(fullAlert);
      }
    } catch (e) { console.error("SHAP fetch failed", e); }
    setLoadingShap(false);
  };
  
  const handleAction = async (actionStr) => {
    if (!selectedAlert || !selectedAlert.event_id) return;
    await acknowledgeAlert(selectedAlert.event_id, actionStr);
    // Optimistic UI update
    setSelectedAlert({...selectedAlert, status: actionStr});
  };

  // Live KPI jitter
  useEffect(() => {
    const id = setInterval(() => {
      setEps(2700 + Math.floor(Math.random() * 400));
      setFpr((5.8 + Math.random() * 1).toFixed(1));
    }, 3000);
    return () => clearInterval(id);
  }, []);

  // Anomaly chart
  useEffect(() => {
    if (!chartRef.current) return;
    const labels = Array.from({ length: 60 }, (_, i) => i % 10 === 0 ? `-${60 - i}m` : "");
    // Use liveScores for the fused dataset:
    const fused = liveScores;
    if (chartInstance.current) chartInstance.current.destroy();
    chartInstance.current = new Chart(chartRef.current, {
      type: "line",
      data: {
        labels,
        datasets: [
          { label:"Fused Score", data:fused, borderColor:"#FF3D5A", backgroundColor:"rgba(255,61,90,0.05)", borderWidth:1.5, pointRadius:0, tension:0.4, fill:true },
          { label:"IF Score",    data:fused.map(v => v * 0.92),  borderColor:"#00D4FF", backgroundColor:"rgba(0,212,255,0.04)",  borderWidth:1,   pointRadius:0, tension:0.4, fill:true },
          { label:"Threshold",   data:Array(60).fill(0.7), borderColor:"rgba(255,176,32,0.5)", borderDash:[4,4], borderWidth:1, pointRadius:0, fill:false },
        ]
      },
      options: {
        responsive:true, maintainAspectRatio:false,
        plugins:{ legend:{ display:false } },
        scales:{
          x:{ grid:{ color:"rgba(0,212,255,0.05)" }, ticks:{ color:"#4A6880", font:{ family:"JetBrains Mono", size:10 } } },
          y:{ min:0, max:1, grid:{ color:"rgba(0,212,255,0.06)" }, ticks:{ color:"#4A6880", font:{ family:"JetBrains Mono", size:10 }, stepSize:0.25 } }
        }
      }
    });
    return () => chartInstance.current?.destroy();
  }, [liveScores]);

  const m = metrics?.model_metrics?.ensemble || {};
  const ls = metrics?.live_stats || {};

  return (
    <div>
      {/* KPI Row */}
      <div style={{ marginBottom:18 }}>
        <div className="section-hd" style={{ display:"flex", alignItems:"center", gap: 16 }}>
          <h2>Live System Status</h2>
          {metrics?.live_stats && !metrics.live_stats.models_loaded && (
            <div style={{ background:"rgba(255,176,32,0.1)", border:"1px solid rgba(255,176,32,0.3)", color:"var(--amber)", padding:"4px 12px", borderRadius:4, fontSize:11, fontWeight:700, fontFamily:"var(--mono)", letterSpacing:0.5 }}>
              ⚠ DEMO MODE — MODELS NOT LOADED
            </div>
          )}
          <div className="line" />
          <span className="section-meta"><span className="live-dot" /> UPDATING EVERY 3s</span>
        </div>
        <div className="kpi-grid">
          <Kpi label="Active Threats"
            value={metrics?.live_stats?.critical_alerts ?? 7}
            color="#FF3D5A" meta="↑ from last hour" 
            barPct={Math.min(100, (metrics?.live_stats?.critical_alerts ?? 7) * 10)} />
          <Kpi label="Anomalies Today"
            value={metrics?.live_stats?.today_alerts ?? 143}
            color="#FFB020" meta="↑ 12% vs yesterday"  barPct={60} />
          <Kpi label="Events / Second"
            value={(metrics?.live_stats?.events_per_second ?? eps).toLocaleString()}
            color="#00D4FF" meta="→ Stable throughput"  barPct={85} />
          <Kpi label="Honeypots Active"
            value={metrics?.live_stats?.active_honeypots ?? honeypots.filter(h => h.status === "active").length}
            color="#8B5CF6" meta="Auto-deployed"   barPct={40} />
          <Kpi label="Models Loaded"
            value={metrics?.live_stats?.models_loaded ? "LIVE" : "DEMO"}
            color={metrics?.live_stats?.models_loaded ? "#00FF88" : "#FFB020"}
            meta={metrics?.live_stats?.models_loaded ? "All .pkl files active" : "Demo mode"}
            barPct={100} />
          <Kpi label="FPR"
            value={((metrics?.model_metrics?.ensemble?.fpr ?? 0.062) * 100).toFixed(1) + "%"}
            color="#00FF88" meta="↓ Below 10% target"  
            barPct={Math.round((metrics?.model_metrics?.ensemble?.fpr ?? 0.062) * 100)} />
        </div>
      </div>

      {/* Main Grid */}
      <div className="main-grid">
        <div className="left-col">

          {/* Event Timeline */}
          <div className="card" style={{ padding:0 }}>
            <div style={{ padding:"14px 20px 10px", borderBottom:"1px solid var(--border)", display:"flex", alignItems:"center", gap:10 }}>
              <span className="live-dot" />
              <span style={{ fontSize:13, fontWeight:600 }}>Triage Workflow</span>
              <div style={{ marginLeft:"auto", display:"flex", gap:6 }}>
                {selectedAlert && <span style={{ fontSize:10, color:"var(--text3)", fontFamily:"var(--mono)", padding:"4px 8px" }}>Selected: {selectedAlert.event_id?.slice(0,8)}</span>}
              </div>
            </div>
            
            <div style={{ padding:"20px", display:"flex", flexDirection:"column", gap:16, flex:1, justifyContent:"center" }}>
              <button 
                className="btn-primary" 
                disabled={!selectedAlert}
                onClick={() => handleAction("trap")}
                style={{ width:"100%", padding:"12px", fontSize:14, opacity:selectedAlert?1:0.5 }}>
                🪤 Deploy TrapWeave Decoy
              </button>
              <button 
                className="btn-secondary" 
                disabled={!selectedAlert}
                onClick={() => handleAction("investigate")}
                style={{ width:"100%", padding:"12px", fontSize:14, opacity:selectedAlert?1:0.5 }}>
                🔍 Mark as Investigated
              </button>
              <button 
                className="btn-secondary" 
                disabled={!selectedAlert}
                onClick={() => handleAction("dismiss")}
                style={{ width:"100%", padding:"12px", fontSize:14, borderColor:"rgba(255,61,90,0.3)", color:"var(--text)", opacity:selectedAlert?1:0.5 }}>
                ✕ Dismiss False Positive
              </button>
              
              {selectedAlert?.status && (
                <div style={{ textAlign:"center", fontSize:11, color:"var(--green)", fontFamily:"var(--mono)", marginTop:8 }}>
                  Status: {selectedAlert.status.toUpperCase()} ✓
                </div>
              )}
            </div>
          </div>

          {/* Anomaly Chart */}
          <div className="card">
            <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:12 }}>
              <span style={{ fontSize:13, fontWeight:600 }}>Anomaly Score — Last 60 Minutes</span>
              <div style={{ marginLeft:"auto", display:"flex", gap:14, fontSize:11, fontFamily:"var(--mono)" }}>
                <span style={{ color:"var(--red)" }}>── Fused</span>
                <span style={{ color:"var(--cyan)" }}>── IF Score</span>
                <span style={{ color:"var(--text3)" }}>- - Threshold</span>
              </div>
            </div>
            <div className="chart-wrap"><canvas ref={chartRef} /></div>
          </div>

          {/* SHAP Explainability */}
          <div className="card">
            <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:12 }}>
              <span style={{ fontSize:13, fontWeight:600 }}>SHAP Explainability — Alert {selectedAlert?.event_id ? `#${selectedAlert.event_id.slice(0,6)}` : "#2847"}</span>
              <span style={{ marginLeft:"auto", fontSize:11, fontFamily:"var(--mono)", color:"var(--text3)" }}>{selectedAlert ? "" : "ct_src_ltm · SMB · DESKTOP-04"}</span>
            </div>
            <div style={{ background:"rgba(255,61,90,0.06)", border:"1px solid rgba(255,61,90,0.2)", borderRadius:"var(--r)", padding:"10px 14px", marginBottom:12, display:"flex", alignItems:"center", gap:10 }}>
              <span style={{ fontSize:16 }}>⚠️</span>
              <div style={{ flex:1 }}>
                <div style={{ fontSize:12, fontWeight:700, color:"var(--red)", marginBottom:2 }}>
                  {(selectedAlert?.severity?.toUpperCase() ?? "CRITICAL")} DETECTED
                </div>
                <div style={{ fontSize:11, fontFamily:"var(--mono)", color:"var(--text2)" }}>
                  {selectedAlert 
                    ? `${selectedAlert.source_ip} → ${selectedAlert.dest_ip}`
                    : "DESKTOP-04 → DB-Server-02 via SMB | 445/tcp | SVCACCOUNT-02"}
                </div>
              </div>
              <div style={{ textAlign:"right" }}>
                <div style={{ fontSize:22, fontWeight:700, fontFamily:"var(--mono)", color:"var(--red)" }}>
                  {(selectedAlert?.scores?.fused ?? 0.94).toFixed(3)}
                </div>
                <div style={{ fontSize:10, color:"var(--text3)", fontFamily:"var(--mono)" }}>FUSED SCORE</div>
              </div>
            </div>
            <div style={{ fontSize:11, color:"var(--text3)", fontFamily:"var(--mono)", marginBottom:10, paddingBottom:8, borderBottom:"1px solid var(--border)", display:"flex", justifyContent:"space-between" }}>
              <span>Feature contribution · Red = increases risk · Green = decreases risk</span>
              {loadingShap && <span style={{ color:"var(--cyan)" }}>Loading SHAP explainer...</span>}
            </div>
            {!selectedAlert && (
              <div style={{ fontSize:11, color:"var(--text3)", fontFamily:"var(--mono)", marginBottom:8, fontStyle:"italic" }}>
                Click an alert in the feed to see its real SHAP explanation ↑
              </div>
            )}
            {(selectedAlert?.shap_values
              ? Object.entries(selectedAlert.shap_values)
                  .slice(0, 7)
                  .map(([name, data]) => ({
                    name,
                    impact: data.shap_value,
                    actual: data.feature_value?.toFixed ? data.feature_value.toFixed(2) : String(data.feature_value),
                    type: data.shap_value >= 0 ? "pos" : "neg",
                  }))
              : SHAP_FEATURES).map((f, i) => (
              <div key={i} className="shap-feature" style={{ animationDelay:`${i*0.07}s` }}>
                <span className="shap-name">{f.name}</span>
                <div className="shap-track">
                  <div className={`shap-bar ${f.type==="pos"?"shap-pos":"shap-neg"}`} style={{ width:`${Math.min(95, Math.abs(f.impact)*150)}%`, transition: "width 0.8s ease" }}>
                    {f.impact > 0 ? "+" : ""}{typeof f.impact === 'number' ? f.impact.toFixed(3) : f.impact}
                  </div>
                </div>
                <span className="shap-actual">{f.actual}</span>
              </div>
            ))}
            <div style={{ marginTop:12, padding:10, background:"var(--bg2)", borderRadius:"var(--r)", border:"1px solid var(--border)", fontSize:12, color:"var(--text2)" }}>
              Formula: <span style={{ color:"var(--text3)", fontFamily:"var(--mono)", fontSize:11 }}>Final = (0.75 × IF) + (0.25 × Context)</span>
              &nbsp;= (0.75×0.91) + (0.25×0.87) = <strong style={{ color:"var(--red)" }}>0.94</strong>
            </div>
          </div>
        </div>

        {/* Right column */}
        <div className="right-col">
          {/* Network Map */}
          <div className="card">
            <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:12 }}>
              <span style={{ fontSize:13, fontWeight:600 }}>TrapWeave Network Map</span>
              <span className="live-dot" style={{ background:"var(--purple)" }} />
              <span className="tag" style={{ color:"var(--purple)", borderColor:"rgba(139,92,246,0.3)" }}>LIVE</span>
            </div>
            <NetworkMapSVG topology={topology} />
            <div style={{ display:"flex", gap:12, marginTop:8, paddingTop:8, borderTop:"1px solid var(--border)" }}>
              {[["#00D4FF","Normal"],["#FF3D5A","Attacker"],["#8B5CF6","Honeypot"],["#FFB020","At Risk"]].map(([c,l]) => (
                <div key={l} style={{ display:"flex", alignItems:"center", gap:4, fontSize:11, color:"var(--text3)" }}>
                  <div style={{ width:7, height:7, borderRadius:"50%", background:c }} />{l}
                </div>
              ))}
            </div>
          </div>

          {/* Alert Feed */}
          <div className="card">
            <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:12 }}>
              <span className="live-dot" />
              <span style={{ fontSize:13, fontWeight:600 }}>Alert Feed</span>
              <span style={{ marginLeft:"auto", fontSize:11, fontFamily:"var(--mono)", color:"var(--text3)" }}>{alerts.length} alerts</span>
            </div>
            <div style={{ maxHeight:360, overflowY:"auto" }}>
              {alerts.length === 0 && (
                <div style={{ padding:"20px", textAlign:"center", fontSize:12, color:"var(--text3)", fontFamily:"var(--mono)" }}>
                  No alerts yet — system is monitoring...
                </div>
              )}
              {(alerts.length ? alerts : DEMO_ALERTS_UI).map((a, i) => (
                <div key={i} 
                  className={`alert-item ${a.severity}`} 
                  onClick={() => handleAlertClick(a)}
                  style={{ cursor: "pointer", background: selectedAlert?.event_id === a.event_id ? "rgba(255,255,255,0.05)" : a.severity==="critical" ? "rgba(255,61,90,0.06)" : a.severity==="high" ? "rgba(255,176,32,0.06)" : "var(--bg2)", borderLeft: selectedAlert?.event_id === a.event_id ? `3px solid var(--cyan)` : undefined }}>
                  <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:6 }}>
                    <span style={{ fontSize:15 }}>
                      {a.severity==="critical" ? "🔴" : a.severity==="high" ? "🟠" : "🔵"}
                    </span>
                    <span style={{ fontSize:11, fontWeight:700, fontFamily:"var(--mono)", color:a.severity==="critical"?"var(--red)":a.severity==="high"?"var(--amber)":"var(--cyan)" }}>
                      {a.severity?.toUpperCase() ?? "—"}
                    </span>
                    <span style={{ marginLeft:"auto", fontSize:10, color:"var(--text3)", fontFamily:"var(--mono)" }}>
                      {a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString()}
                    </span>
                  </div>
                  <div style={{ fontSize:12, color:"var(--text2)" }}>
                    <code style={{ background:"var(--bg0)", padding:"1px 4px", borderRadius:3, fontFamily:"var(--mono)", fontSize:10, color:"var(--cyan)" }}>{a.source_ip ?? "unknown"}</code>
                    {" → "}
                    <code style={{ background:"var(--bg0)", padding:"1px 4px", borderRadius:3, fontFamily:"var(--mono)", fontSize:10, color:"var(--cyan)" }}>{a.dest_ip ?? "unknown"}</code>
                  </div>
                  <div style={{ marginTop:6, display:"flex", gap:4 }}>
                    <span className="tag">Score: {a.scores?.fused?.toFixed(3) ?? "—"}</span>
                    {a.is_anomaly && <span className="tag" style={{ color:"var(--red)" }}>ANOMALY</span>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Metrics Row */}
      <div style={{ marginBottom:16 }}>
        <div className="section-hd"><h2>Model Performance Metrics</h2><div className="line" /></div>
        <div className="metrics-grid">
          {[
            { label:"Precision", val:((m.precision||0.942)*100).toFixed(1)+"%",   color:"#00FF88" },
            { label:"Recall",    val:((m.recall   ||0.918)*100).toFixed(1)+"%",   color:"#00D4FF" },
            { label:"F1 Score",  val:((m.f1       ||0.930)*100).toFixed(1)+"%",   color:"#00D4FF" },
            { label:"AUC-ROC",   val:(m.auc_roc   ||0.967).toFixed(3),            color:"#FFB020" },
            { label:"FPR",       val:((m.fpr      ||0.062)*100).toFixed(1)+"%",   color:"#00FF88" },
          ].map(({label, val, color}) => (
            <div key={label} className="metric-card">
              <div className="metric-label">{label}</div>
              <div className="metric-value" style={{ color }}>{val}</div>
              <div className="metric-sub">Ensemble model</div>
            </div>
          ))}
        </div>
      </div>

      {/* Bottom Row */}
      <div className="section-hd"><h2>Intelligence & Capture</h2><div className="line" /></div>
      <div className="bottom-grid">
        {/* Feature importance */}
        <div className="card">
          <div style={{ fontSize:13, fontWeight:600, marginBottom:12 }}>Feature Importance (26 Features)</div>
          {FEATURES.map((f, i) => (
            <div key={i} className="feat-item">
              <span className="feat-name">{f.name}</span>
              <div className="feat-track"><div className="feat-fill" style={{ width:`${f.pct * 5}%` }} /></div>
              <span className="feat-pct">{f.pct}%</span>
            </div>
          ))}
        </div>

        {/* TTP Terminal */}
        <div className="card">
          <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:10 }}>
            <span style={{ fontSize:13, fontWeight:600 }}>TTP Capture</span>
            <span className="tag" style={{ color:"var(--purple)", borderColor:"rgba(139,92,246,0.3)" }}>AdminServer_Fake01</span>
          </div>
          <div className="terminal">
            {TTP_LINES.map((l, i) => (
              <div key={i} style={{ marginBottom:3, lineHeight:1.5 }}>
                <span className={l.cls}>{l.text}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Honeypots */}
        <div className="card">
          <div style={{ fontSize:13, fontWeight:600, marginBottom:12 }}>Active Honeypot Decoys</div>
          <div style={{ background:"rgba(139,92,246,0.08)", border:"1px solid rgba(139,92,246,0.2)", borderRadius:"var(--r)", padding:"10px 12px", marginBottom:12, display:"flex", alignItems:"center", gap:10 }}>
            <div style={{ width:34, height:34, borderRadius:8, background:"rgba(139,92,246,0.2)", display:"flex", alignItems:"center", justifyContent:"center", fontSize:18 }}>🪤</div>
            <div>
              <div style={{ fontSize:13, fontWeight:600 }}>TrapWeave Engine</div>
              <div style={{ fontSize:11, fontFamily:"var(--mono)", color:"var(--text2)" }}>4 decoys · AI-triggered · Graph-mapped</div>
            </div>
            <div style={{ marginLeft:"auto", padding:"3px 10px", borderRadius:20, fontSize:11, fontWeight:700, fontFamily:"var(--mono)", background:"rgba(0,255,136,0.1)", color:"var(--green)", border:"1px solid rgba(0,255,136,0.2)" }}>ACTIVE</div>
          </div>
          {(honeypots.length ? honeypots : DEMO_HPS).map((h, i) => {
            const icons = { admin_server:"🖥️", database:"🗄️", fileshare:"📁", domain_controller:"🔑" };
            const hitsColor = h.hit_count > 5 ? "var(--red)" : h.hit_count > 0 ? "var(--amber)" : "var(--text3)";
            return (
              <div key={h.id ?? i} className="hp-item">
                <div className="hp-icon" style={{ background:"rgba(139,92,246,0.12)" }}>{icons[h.type] ?? "🔒"}</div>
                <div style={{ flex:1 }}>
                  <div className="hp-name">{h.name}</div>
                  <div className="hp-addr">{h.ip}</div>
                </div>
                <div>
                  <div className="hp-hits" style={{ color:hitsColor }}>{h.hit_count}</div>
                  <div className="hp-hits-lbl">HITS</div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function Kpi({ label, value, color, meta, barPct }) {
  const animatedVal = useCountUp(value);
  return (
    <div className="kpi">
      <div className="kpi-label">{label}</div>
      <div className="kpi-value" style={{ color }}>{animatedVal}</div>
      <div className="kpi-meta" style={{ color:"var(--text3)", display:"flex", justifyContent:"space-between", alignItems:"flex-end" }}>
        <span>{meta}</span>
        <Sparkline color={color} />
      </div>
      <div className="kpi-bar" style={{ width:`${barPct}%`, background:color, opacity:0.55 }} />
    </div>
  );
}

function NetworkMapSVG({ topology }) {
  // Use dynamic topology from API if available, else fallback
  const nodes = topology?.nodes || [
    { x:160, y:125, r:20, color:"#FF3D5A", label:"ATTACKER",         sub:"192.168.1.147", pulse:true, type:"attacker"  },
    { x:60,  y:60,  r:15, color:"#FFB020", label:"DESKTOP-04",       sub:"Compromised", type:"compromised"               },
    { x:75,  y:200, r:13, color:"#00D4FF", label:"LAPTOP-07",        sub:"", type:"normal"                           },
    { x:255, y:50,  r:15, color:"#FFB020", label:"DB-Server",        sub:"At Risk", type:"at_risk"                    },
    { x:265, y:155, r:15, color:"#8B5CF6", label:"AdminFake01",      sub:"HONEYPOT",      glow:true, type:"honeypot"   },
    { x:255, y:220, r:13, color:"#00D4FF", label:"FileServer",       sub:"", type:"normal"                           },
    { x:160, y:240, r:11, color:"#4A6880", label:"GATEWAY",          sub:"", type:"normal"                           },
  ];
  const edges = topology?.edges || [
    { ax:160,ay:125, bx:60,by:60,   color:"rgba(255,61,90,0.6)",  dash:"" },
    { ax:160,ay:125, bx:75,by:200,  color:"rgba(255,61,90,0.3)",  dash:"4,3" },
    { ax:60, ay:60,  bx:255,by:50,  color:"rgba(255,176,32,0.5)", dash:"4,3" },
    { ax:60, ay:60,  bx:265,by:155, color:"rgba(139,92,246,0.7)", dash:"" },
    { ax:160,ay:240, bx:60,by:200,  color:"rgba(0,212,255,0.2)",  dash:"4,3" },
  ];
  
  // Helper to map dynamic node coordinates if they don't exist
  const mappedNodes = nodes.map((n, i) => {
    if (n.x !== undefined) return n;
    // Simple circular layout for dynamic nodes if positions omitted
    const angle = (i / nodes.length) * Math.PI * 2;
    return {
      ...n,
      x: 160 + Math.cos(angle) * 100,
      y: 135 + Math.sin(angle) * 80,
      r: n.type === "attacker" ? 20 : n.type === "honeypot" ? 15 : 13,
      pulse: n.type === "attacker",
      glow: n.type === "honeypot",
      color: n.type === "attacker" ? "#FF3D5A" : n.type === "honeypot" ? "#8B5CF6" : n.type === "at_risk" || n.type === "compromised" ? "#FFB020" : "#00D4FF",
    }
  });
  
  const mappedEdges = edges.map(e => {
    if (e.ax !== undefined) return e;
    const ax_node = mappedNodes.find(n => n.id === e.from) || mappedNodes[0];
    const bx_node = mappedNodes.find(n => n.id === e.to) || mappedNodes[1];
    return {
      ax: ax_node.x, ay: ax_node.y, bx: bx_node.x, by: bx_node.y,
      color: e.honeypot_trap ? "rgba(139,92,246,0.7)" : e.blocked ? "rgba(255,176,32,0.5)" : "rgba(255,61,90,0.4)",
      dash: e.honeypot_trap ? "" : "4,3"
    };
  });

  return (
    <svg viewBox="0 0 320 270" style={{ width:"100%", height:240, background:"radial-gradient(ellipse at center, rgba(0,212,255,0.04), transparent 70%)", borderRadius:"var(--r)" }}>
      {mappedEdges.map((e, i) => (
        <line key={i} x1={e.ax} y1={e.ay} x2={e.bx} y2={e.by}
          stroke={e.color} strokeWidth={1.5} strokeDasharray={e.dash} />
      ))}
      {mappedNodes.map((n, i) => (
        <g key={i}>
          {n.pulse && (
            <circle cx={n.x} cy={n.y} r={n.r+6} fill="none" stroke={n.color} strokeWidth={1} opacity={0.3}>
              <animate attributeName="r" values={`${n.r+4};${n.r+14};${n.r+4}`} dur="2s" repeatCount="indefinite" />
              <animate attributeName="opacity" values="0.4;0;0.4" dur="2s" repeatCount="indefinite" />
            </circle>
          )}
          {n.glow && (
            <circle cx={n.x} cy={n.y} r={n.r+5} fill="none" stroke={n.color} strokeWidth={1} opacity={0.35}>
              <animate attributeName="r" values={`${n.r+3};${n.r+10};${n.r+3}`} dur="3s" repeatCount="indefinite" />
              <animate attributeName="opacity" values="0.5;0;0.5" dur="3s" repeatCount="indefinite" />
            </circle>
          )}
          <circle cx={n.x} cy={n.y} r={n.r} fill={n.color} fillOpacity={0.14} stroke={n.color} strokeWidth={1.5} />
          <text x={n.x} y={n.y-2} textAnchor="middle" fill={n.color} fontSize={6.5} fontWeight={600} fontFamily="JetBrains Mono,monospace">{n.label}</text>
          {n.sub && <text x={n.x} y={n.y+8} textAnchor="middle" fill={n.color} fillOpacity={0.6} fontSize={5.5} fontFamily="JetBrains Mono,monospace">{n.sub}</text>}
        </g>
      ))}
    </svg>
  );
}


const DEMO_HPS = [
  { name:"AdminServer_Fake01", ip:"192.168.100.45", type:"admin_server",       hit_count:12 },
  { name:"DB-Server_Fake02",   ip:"192.168.100.46", type:"database",           hit_count:4  },
  { name:"FileShare_Fake03",   ip:"192.168.100.47", type:"fileshare",          hit_count:1  },
  { name:"DomainCtrl_Fake04",  ip:"192.168.100.48", type:"domain_controller", hit_count:0  },
];

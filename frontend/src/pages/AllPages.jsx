// AllPages.jsx
import { useState, useRef, useEffect } from "react";
import { analyzeEvent } from "../hooks/useLiveMetrics";
import { CHART_COLORS } from "../utils/constants";

const FEATURES_26 = [
  "dur","proto","state","sbytes","dbytes","sttl","dttl","sloss","dloss",
  "sload","dload","spkts","dpkts","sjit","djit","tcprtt","synack","ackdat",
  "ct_srv_src","ct_srv_dst","ct_dst_ltm","ct_src_ltm","ct_src_dport_ltm",
  "ct_dst_sport_ltm","ct_dst_src_ltm","is_sm_ips_ports"
];

export function DetectionEngine() {
  const [form, setForm] = useState({ ct_src_ltm:47, sbytes:2400000, dur:0.003, proto:1, ct_dst_ltm:15 });
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const submit = async () => {
    setLoading(true);
    const res = await analyzeEvent(form);
    setResult(res);
    setLoading(false);
  };

  return (
    <div>
      <div className="section-hd"><h2>LateralShield Detection Engine</h2><div className="line" /></div>
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:16, marginBottom:16 }}>
        {[
          { icon:(<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 2L3 10V22H21V10L12 2Z"/><path d="M12 12V22"/><path d="M12 12L7 17"/><path d="M12 12L17 17"/></svg>), label:"Isolation Forest", color:"var(--cyan)", weight:"0.75 in fusion", desc:"Trained only on normal traffic. Isolates anomalous points by recursive random partitioning. No labeled attacks needed." },
          { icon:(<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="3"/><circle cx="19" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><circle cx="5" cy="5" r="2"/></svg>), label:"Local Outlier Factor", color:"var(--amber)", weight:"Density-based", desc:"Compares local density of each point to its neighbors. Detects outliers in high-density normal regions." },
          { icon:(<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 12H21"/><path d="M12 3C8 3 5 8 5 12c0 4 3 9 7 9s7-5 7-9"/></svg>), label:"One-Class SVM", color:"var(--purple)", weight:"Boundary model", desc:"Learns the decision boundary of normal behavior in feature space. Flags anything outside the boundary." },
        ].map(m => (
          <div key={m.label} className="card">
            <div style={{ color:m.color, marginBottom:10 }}>{m.icon}</div>
            <div style={{ fontWeight:700, color:m.color, marginBottom:4 }}>{m.label}</div>
            <div style={{ fontSize:11, fontFamily:"var(--mono)", color:"var(--text3)", marginBottom:8 }}>{m.weight}</div>
            <div style={{ fontSize:12, color:"var(--text2)", lineHeight:1.7 }}>{m.desc}</div>
          </div>
        ))}
      </div>

      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16 }}>
        {/* Live test */}
        <div className="card">
          <div style={{ fontSize:13, fontWeight:600, marginBottom:14 }}>Live Event Analysis</div>
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:10, marginBottom:14 }}>
            {Object.entries(form).map(([k, v]) => (
              <div key={k}>
                <div style={{ fontSize:10, fontFamily:"var(--mono)", color:"var(--text3)", marginBottom:3 }}>{k}</div>
                <input value={v} onChange={e => setForm(p => ({ ...p, [k]: parseFloat(e.target.value)||0 }))}
                  style={{ width:"100%", background:"var(--bg2)", border:"1px solid var(--border)", borderRadius:"var(--r)", padding:"6px 10px", color:"var(--text)", fontFamily:"var(--mono)", fontSize:12 }} />
              </div>
            ))}
          </div>
          <button className="btn-primary" onClick={submit} disabled={loading} style={{ width:"100%" }}>
            {loading ? "Analyzing…" : "⚡ Analyze Event"}
          </button>
          {result && !result.error && (
            <div style={{ marginTop:14, padding:14, background:"var(--bg2)",
              borderRadius:"var(--r)",
              border:`1px solid ${result.fused_score >= 0.7
                ? "rgba(255,61,90,0.3)" : "var(--border)"}` }}>

              {/* Score gauge row */}
              <div style={{ display:"flex", justifyContent:"center", marginBottom:12 }}>
                <ScoreGauge score={result.fused_score ?? 0} />
              </div>

              {/* All score values */}
              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr",
                gap:8, fontSize:12, fontFamily:"var(--mono)" }}>
                <div><span style={{ color:"var(--text3)" }}>Fused Score: </span>
                  <strong style={{ color: result.fused_score >= 0.85 ? "var(--red)"
                    : result.fused_score >= 0.70 ? "var(--amber)" : "var(--green)" }}>
                    {result.fused_score?.toFixed(4)}
                  </strong>
                </div>
                <div><span style={{ color:"var(--text3)" }}>Severity: </span>
                  <strong style={{ color:"var(--text)" }}>
                    {result.severity?.toUpperCase()}
                  </strong>
                </div>
                <div><span style={{ color:"var(--text3)" }}>IF Score: </span>
                  <span style={{ color:"var(--cyan)" }}>
                    {result.isolation_forest_score?.toFixed(4)}
                  </span>
                </div>
                <div><span style={{ color:"var(--text3)" }}>LOF Score: </span>
                  <span style={{ color:"var(--cyan)" }}>
                    {result.lof_score?.toFixed(4)}
                  </span>
                </div>
                <div><span style={{ color:"var(--text3)" }}>OCSVM Score: </span>
                  <span style={{ color:"var(--cyan)" }}>
                    {result.ocsvm_score?.toFixed(4)}
                  </span>
                </div>
                <div><span style={{ color:"var(--text3)" }}>Context Dev: </span>
                  <span style={{ color:"var(--cyan)" }}>
                    {result.context_deviation_score?.toFixed(4)}
                  </span>
                </div>
                <div><span style={{ color:"var(--text3)" }}>Is Anomaly: </span>
                  <strong style={{ color: result.is_anomaly ? "var(--red)" : "var(--green)" }}>
                    {result.is_anomaly ? "YES ⚠" : "NO ✓"}
                  </strong>
                </div>
                <div><span style={{ color:"var(--text3)" }}>TrapWeave: </span>
                  <strong style={{ color: result.trapweave_triggered
                    ? "var(--purple)" : "var(--text3)" }}>
                    {result.trapweave_triggered ? "TRIGGERED 🪤" : "STANDBY"}
                  </strong>
                </div>
              </div>

              {/* SHAP top features from real API */}
              {result.shap_values && Object.keys(result.shap_values).length > 0 && (
                <div style={{ marginTop:12, paddingTop:12,
                  borderTop:"1px solid var(--border)" }}>
                  <div style={{ fontSize:10, color:"var(--text3)",
                    fontFamily:"var(--mono)", marginBottom:8 }}>
                    TOP SHAP FEATURES (from real model):
                  </div>
                  {Object.entries(result.shap_values).slice(0, 5).map(([feat, data]) => (
                    <div key={feat} className="shap-feature">
                      <span className="shap-name">{feat}</span>
                      <div className="shap-track">
                        <div
                          className={`shap-bar ${data.shap_value >= 0 ? "shap-pos" : "shap-neg"}`}
                          style={{ width:`${Math.min(95, Math.abs(data.shap_value) * 200)}%` }}>
                          {data.shap_value >= 0 ? "+" : ""}{data.shap_value?.toFixed(3)}
                        </div>
                      </div>
                      <span className="shap-actual">
                        {data.feature_value?.toFixed ? data.feature_value.toFixed(1) : data.feature_value}
                      </span>
                    </div>
                  ))}
                </div>
              )}

              {/* Formula proof */}
              <div style={{ marginTop:10, padding:8, background:"var(--bg0)",
                borderRadius:"var(--r)", fontSize:11, fontFamily:"var(--mono)",
                color:"var(--text2)" }}>
                (0.75 × {result.isolation_forest_score?.toFixed(3)}) +
                (0.25 × {result.context_deviation_score?.toFixed(3)}) =&nbsp;
                <strong style={{ color:"var(--red)" }}>
                  {result.fused_score?.toFixed(4)}
                </strong>
              </div>
            </div>
          )}

          {result?.error && (
            <div style={{ marginTop:12, padding:10, background:"rgba(255,61,90,0.08)",
              borderRadius:"var(--r)", border:"1px solid rgba(255,61,90,0.2)",
              fontSize:12, fontFamily:"var(--mono)", color:"var(--red)" }}>
              Error: {result.error} — check backend is running at localhost:5000
            </div>
          )}
        </div>

        {/* 26 features */}
        <div className="card">
          <div style={{ fontSize:13, fontWeight:600, marginBottom:12 }}>26 Behavioral Features — UNSW-NB15</div>
          <div style={{ display:"flex", flexWrap:"wrap", gap:6 }}>
            {FEATURES_26.map(f => (
              <span key={f} className="tag" style={{ fontSize:11, color:"var(--cyan)" }}>{f}</span>
            ))}
          </div>
          <div style={{ marginTop:14, padding:10, background:"var(--bg2)", borderRadius:"var(--r)", border:"1px solid var(--border)", fontSize:12, color:"var(--text2)" }}>
            <span style={{ color:"var(--cyan)", fontWeight:600 }}>Fusion Formula: </span>
            Final Score = (0.75 × Isolation Forest) + (0.25 × Context Deviation)
          </div>
        </div>
      </div>
    </div>
  );
}

function ScoreGauge({ score }) {
  const color = score >= 0.85 ? "var(--red)" : score >= 0.70 ? "var(--amber)" : "var(--green)";
  return (
    <div style={{ position:"relative", width:100, height:100, margin:"0 auto" }}>
      <svg viewBox="0 0 100 100" style={{ width:"100%", height:"100%" }}>
        <path d="M 20 80 A 45 45 0 1 1 80 80" fill="none" stroke="var(--bg0)" strokeWidth="8" strokeLinecap="round" />
        <path d="M 20 80 A 45 45 0 1 1 80 80" fill="none" stroke={color} strokeWidth="8" strokeLinecap="round" strokeDasharray="200" strokeDashoffset={Math.max(0, 200 - (score * 200) * 1.5)} style={{ transition:"stroke-dashoffset 1s ease-out" }} />
      </svg>
      <div style={{ position:"absolute", top:0, left:0, width:"100%", height:"100%", display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center" }}>
        <div style={{ fontSize:24, fontWeight:700, fontFamily:"var(--mono)", color }}>{score.toFixed(3)}</div>
        <div style={{ fontSize:10, color:"var(--text3)", fontFamily:"var(--mono)" }}>SCORE</div>
      </div>
    </div>
  );
}


// ── Analytics Page ────────────────────────────────────────────────

import { Chart as ChartJS, registerables as regs } from "chart.js";
ChartJS.register(...regs);

export function Analytics() {
  const barRef = useRef(null);
  const doughRef = useRef(null);
  const bar2Ref = useRef(null);
  const c1 = useRef(null); const c2 = useRef(null); const c3 = useRef(null);
  const [training, setTraining] = useState({ running: false, progress: 0, stage: "idle", logs: [] });

  useEffect(() => {
    let es;
    const connectStream = () => {
      try {
        es = new EventSource(`${import.meta.env.VITE_API_URL || "http://localhost:5000/api"}/train/stream`);
        es.onmessage = (e) => {
          try {
            const data = JSON.parse(e.data);
            setTraining(data);
            // Auto close if finished
            if (!data.running && data.stage === "Complete ✓") es.close();
          } catch {}
        };
      } catch {}
    };
    connectStream();
    // Reconnect every 5s if disconnected during training
    const id = setInterval(() => { if (!es || es.readyState === 2) connectStream(); }, 5000);
    return () => { clearInterval(id); if (es) es.close(); };
  }, []);

  const startTraining = async () => {
    try {
      await fetch(`${import.meta.env.VITE_API_URL || "http://localhost:5000/api"}/train`, {
        method: "POST", headers: { "Content-Type": "application/json" }
      });
    } catch {}
  };

  useEffect(() => {
    if (barRef.current) {
      c1.current?.destroy();
      c1.current = new ChartJS(barRef.current, {
        type:"bar",
        data:{
          labels:["00","02","04","06","08","10","12","14","16","18","20","22"],
          datasets:[
            { label:"Critical", data:[1,0,2,0,1,3,2,7,5,3,2,1], backgroundColor:CHART_COLORS[1], borderRadius:3 },
            { label:"High",     data:[3,2,4,1,5,8,6,12,9,7,5,3], backgroundColor:CHART_COLORS[3], borderRadius:3 },
            { label:"Medium",   data:[8,5,7,3,9,15,12,20,16,11,8,5], backgroundColor:CHART_COLORS[0], borderRadius:3 },
          ]
        },
        options:{ responsive:true, maintainAspectRatio:false, plugins:{ legend:{ display:false } },
          scales:{ x:{ stacked:true, grid:{ display:false }, ticks:{ color:"#4A6880", font:{ size:10 } } },
                   y:{ stacked:true, grid:{ color:"rgba(0,212,255,0.06)" }, ticks:{ color:"#4A6880", font:{ size:10 } } } } }
      });
    }
    if (doughRef.current) {
      c2.current?.destroy();
      c2.current = new ChartJS(doughRef.current, {
        type:"doughnut",
        data:{
          labels:["SMB (445)","RDP (3389)","WMI","SSH","LDAP","Other"],
          datasets:[{ data:[38,25,18,10,6,3], backgroundColor:[...CHART_COLORS, "rgba(74,104,128,0.8)"], borderWidth:0 }]
        },
        options:{ responsive:true, maintainAspectRatio:false, cutout:"62%",
          plugins:{ legend:{ position:"right", labels:{ color:"#8FB8CC", font:{ size:11 }, boxWidth:12, padding:12 } } } }
      });
    }
    if (bar2Ref.current) {
      c3.current?.destroy();
      c3.current = new ChartJS(bar2Ref.current, {
        type:"bar",
        data:{
          labels:["Precision","Recall","F1","AUC-ROC","1-FPR"],
          datasets:[
            { label:"IF Only",  data:[0.86,0.82,0.84,0.91,0.88], backgroundColor:CHART_COLORS[0], borderRadius:3 },
            { label:"Ensemble", data:[0.942,0.918,0.930,0.967,0.938], backgroundColor:CHART_COLORS[2], borderRadius:3 },
          ]
        },
        options:{ responsive:true, maintainAspectRatio:false, indexAxis:"y",
          plugins:{ legend:{ position:"top", labels:{ color:"#8FB8CC", font:{ size:11 }, boxWidth:10 } } },
          scales:{ x:{ min:0.8, max:1.0, grid:{ color:"rgba(0,212,255,0.06)" }, ticks:{ color:"#4A6880", font:{ size:10 } } },
                   y:{ grid:{ display:false }, ticks:{ color:"#8FB8CC", font:{ family:"JetBrains Mono", size:11 } } } } }
      });
    }
    return () => { c1.current?.destroy(); c2.current?.destroy(); c3.current?.destroy(); };
  }, []);

  return (
    <div>
      <div className="section-hd"><h2>Analytics & Model Performance</h2><div className="line" /></div>
      <div className="metrics-grid" style={{ marginBottom: 16 }}>
        {[
          { label:"Total Processed", val:"1.4M", unit:"Events", color:"var(--cyan)" },
          { label:"Avg Detection Time", val:"14", unit:"ms", color:"var(--green)" },
          { label:"False Positives", val:"< 0.1", unit:"%", color:"var(--red)" },
          { label:"Active Models", val:"3", unit:"/3", color:"var(--purple)" }
        ].map(m => (
          <div key={m.label} className="card" style={{ padding: "12px 16px" }}>
            <div style={{ fontSize:10, fontFamily:"var(--mono)", color:"var(--text3)", marginBottom:8 }}>{m.label.toUpperCase()}</div>
            <div style={{ fontSize:22, fontWeight:700, fontFamily:"var(--mono)", color:m.color }}>
              {m.val} <span style={{ fontSize:12, color:"var(--text3)", fontWeight:500 }}>{m.unit}</span>
            </div>
          </div>
        ))}
      </div>
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16, marginBottom:16 }}>
        <div className="card">
          <div style={{ fontSize:13, fontWeight:600, marginBottom:12 }}>Threat Distribution (24h)</div>
          <div style={{ position:"relative", height:240 }}><canvas ref={barRef} /></div>
        </div>
        <div className="card">
          <div style={{ fontSize:13, fontWeight:600, marginBottom:12 }}>Protocol Anomaly Breakdown</div>
          <div style={{ position:"relative", height:240 }}><canvas ref={doughRef} /></div>
        </div>
      </div>
      <div style={{ display:"grid", gridTemplateColumns:"2fr 1fr", gap:16, marginBottom:16 }}>
        <div className="card">
          <div style={{ display:"flex", alignItems:"center", gap:12, marginBottom:16 }}>
            <span style={{ fontSize:14, fontWeight:600 }}>Model Retraining Pipeline</span>
            {training.running ? (
              <span className="badge badge-high" style={{ padding:"4px 10px" }}>
                <span className="live-dot" style={{ background:"var(--amber)", display:"inline-block", marginRight:6 }} />
                TRAINING IN PROGRESS
              </span>
            ) : (
              <button className="btn-primary" onClick={startTraining} style={{ padding:"6px 16px", fontSize:11 }}>
                Start Retraining
              </button>
            )}
            <span style={{ marginLeft:"auto", fontSize:11, fontFamily:"var(--mono)", color:"var(--text3)" }}>{training.stage}</span>
          </div>
          
          <div className="score-wrap" style={{ marginBottom:16, background:"var(--bg0)", height:12, borderRadius:6 }}>
             <div className="score-fill" style={{ width:`${training.progress}%`, background:"var(--cyan)", height:"100%", transition:"width 1s cubic-bezier(0.4, 0, 0.2, 1)" }} />
          </div>
          
          <div className="terminal" style={{ height:140, fontSize:11, borderRadius:"var(--r2)", display:"flex", flexDirection:"column", justifyContent:"flex-end" }}>
            {training.logs.length === 0 ? (
               <div style={{ color:"var(--text3)", fontStyle:"italic" }}>Click 'Start Retraining' to begin epoch loop...</div>
            ) : (
               training.logs.map((L, i) => <div key={i} style={{ color:L.includes("✓") ? "var(--green)" : "var(--text2)", marginBottom:4, fontFamily:"var(--mono)" }}>{L}</div>)
            )}
          </div>
        </div>
        <div className="card">
          <div style={{ fontSize:13, fontWeight:600, marginBottom:12 }}>Ensemble vs. Single Model — Performance Comparison</div>
          <div style={{ position:"relative", height:190 }}><canvas ref={bar2Ref} /></div>
        </div>
      </div>
    </div>
  );
}

// ── TTP Viewer Page ────────────────────────────────────────────────

import { useTTP } from "../hooks/useLiveMetrics";

export function TTPViewer() {
  const { data: sessions, loading } = useTTP();

  return (
    <div>
      <div className="section-hd"><h2>TTP Capture & MITRE ATT&CK Mapping</h2><div className="line" /></div>
      <div style={{ marginBottom:16, fontSize:13, color:"var(--text2)", lineHeight:1.6 }}>
        When TrapWeave deploys a honeypot, the attacker's interactive sessions are recorded. 
        The engine automatically classifies executed commands against the MITRE ATT&CK framework directly from the decoy containers.
      </div>
      
      <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill, minmax(400px, 1fr))", gap:16 }}>
        {sessions.map((sess, idx) => (
          <div key={idx} className="card" style={{ borderTop:"3px solid var(--purple)" }}>
            <div style={{ display:"flex", justifyContent:"space-between", marginBottom:12 }}>
              <div>
                <div style={{ fontSize:14, fontWeight:700, marginBottom:4 }}>{sess.honeypot_name}</div>
                <div style={{ fontSize:11, fontFamily:"var(--mono)", color:"var(--cyan)" }}>
                  DECOY IP: {sess.honeypot_ip} · TYPE: {sess.honeypot_type?.toUpperCase()}
                </div>
              </div>
              <div style={{ textAlign:"right" }}>
                <div style={{ fontSize:10, color:"var(--text3)", fontFamily:"var(--mono)", marginBottom:2 }}>ATTACKER IP</div>
                <div style={{ fontSize:12, fontWeight:700, fontFamily:"var(--mono)", color:"var(--red)" }}>{sess.attacker_ip}</div>
              </div>
            </div>
            
            <div className="terminal" style={{ maxHeight:200, overflowY:"auto", fontSize:11, background:"#0A1118", border:"1px solid rgba(139,92,246,0.3)" }}>
              {sess.commands?.map((cmd, i) => {
                // Heuristic MITRE Mapping
                let mitre = "";
                let mitreColor = "";
                const c = cmd.command.toLowerCase();
                if (c.includes("whoami") || c.includes("ipconfig") || c.includes("net user") || c.includes("net view")) { mitre = "T1087: Account/System Discovery"; mitreColor = "var(--cyan)"; }
                else if (c.includes("psexec") || c.includes("wmi") || c.includes("ssh")) { mitre = "T1021: Remote Services"; mitreColor = "var(--amber)"; }
                else if (c.includes("mimikatz") || c.includes("sekurlsa")) { mitre = "T1003: OS Credential Dumping"; mitreColor = "var(--red)"; }
                else if (c.includes("powershell -enc") || c.includes("xp_cmdshell")) { mitre = "T1059: Command and Scripting"; mitreColor = "var(--purple)"; }
                else { mitre = "T1059: Execution"; mitreColor = "var(--text3)"; }
                
                return (
                  <div key={i} style={{ marginBottom:10 }}>
                    <div style={{ fontSize:9, color:"var(--text3)", marginBottom:2 }}>
                      {cmd.timestamp ? new Date(cmd.timestamp).toLocaleTimeString() : ""}
                    </div>
                    <div style={{ display:"flex", alignItems:"flex-start", gap:8 }}>
                      <span style={{ color:"var(--green)" }}>root@target:~#</span>
                      <span style={{ color:"var(--text)", flex:1, wordBreak:"break-all" }}>{cmd.command}</span>
                    </div>
                    {(mitre && cmd.command.trim() !== "") && (
                      <div style={{ marginTop:4, padding:"2px 6px", background:"rgba(255,255,255,0.05)", borderRadius:3, display:"inline-block", fontSize:9, color:mitreColor, border:`1px solid ${mitreColor}44` }}>
                        {mitre}
                      </div>
                    )}
                  </div>
                );
              })}
              {(!sess.commands || sess.commands.length === 0) && (
                <div style={{ color:"var(--text3)" }}>Session established... waiting for commands.</div>
              )}
            </div>
          </div>
        ))}
      </div>
      {sessions.length === 0 && !loading && (
        <div className="card" style={{ textAlign:"center", padding:40, color:"var(--text3)", fontStyle:"italic" }}>
          No honeypot interactions captured yet. Deploy a TrapWeave decoy to begin collecting TTPs.
        </div>
      )}
    </div>
  );
}


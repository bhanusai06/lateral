import { useState, useEffect } from "react";
import { useHoneypots, useAlerts } from "../hooks/useLiveMetrics";

export default function TrapWeave() {
  const honeypots = useHoneypots();
  // Provide defensive fallback if fetch hasn't completed
  const alerts = (useAlerts() || []).slice(0, 10);
  const [uptime, setUptime] = useState("4d 12h 33m 12s");

  useEffect(() => {
    const start = Date.now() - 390792000;
    const interval = setInterval(() => {
      const diff = Date.now() - start;
      const d = Math.floor(diff / 86400000);
      const h = Math.floor((diff % 86400000) / 3600000);
      const m = Math.floor((diff % 3600000) / 60000);
      const s = Math.floor((diff % 60000) / 1000);
      setUptime(`${d}d ${h}h ${m}m ${s}s`);
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="page-fade-in">
      <div className="section-hd"><h2>TrapWeave Orchestrator</h2><div className="line" /></div>
      
      {/* Top Bar Stats */}
      <div style={{ display:"grid", gridTemplateColumns:"repeat(3, 1fr)", gap:16, marginBottom:16 }}>
        <div className="card">
          <div style={{ fontSize:10, fontFamily:"var(--mono)", color:"var(--text3)", letterSpacing:1, marginBottom:8 }}>ENGINE STATUS</div>
          <div style={{ display:"flex", alignItems:"center", gap:8 }}>
            <span className="live-dot" style={{ background:"var(--purple)", width:10, height:10 }}></span>
            <span style={{ fontSize:24, fontWeight:700, fontFamily:"var(--mono)", color:"var(--purple)" }}>ACTIVE</span>
          </div>
        </div>
        <div className="card">
          <div style={{ fontSize:10, fontFamily:"var(--mono)", color:"var(--text3)", letterSpacing:1, marginBottom:8 }}>SYSTEM UPTIME</div>
          <div style={{ fontSize:22, fontWeight:700, fontFamily:"var(--mono)", color:"var(--text)" }}>{uptime}</div>
        </div>
        <div className="card">
          <div style={{ fontSize:10, fontFamily:"var(--mono)", color:"var(--text3)", letterSpacing:1, marginBottom:8 }}>ACTIVE DECOYS</div>
          <div style={{ fontSize:24, fontWeight:700, fontFamily:"var(--mono)", color:"var(--cyan)" }}>{honeypots?.length || 4}</div>
        </div>
      </div>

      <div style={{ display:"grid", gridTemplateColumns:"2fr 1fr", gap:16 }}>
        {/* Network Graph Visualization */}
        <div className="card" style={{ padding:0 }}>
           <div style={{ padding:"16px 20px 0" }}>
             <div style={{ fontSize:13, fontWeight:600, marginBottom:12 }}>Live Decoy Topology</div>
           </div>
           <TrapWeaveGraph />
        </div>

        {/* Live Attack Feed */}
        <div className="card">
           <div style={{ fontSize:13, fontWeight:600, marginBottom:12, display:"flex", alignItems:"center", gap:8 }}>
             <span className="live-dot" style={{ background:"var(--amber)" }} /> Honeypot Events
           </div>
           <div style={{ maxHeight:400, overflowY:"auto", paddingRight:4 }}>
             {alerts.length === 0 ? (
                <div style={{ color:"var(--text3)", fontSize:12, fontStyle:"italic" }}>No active honeypot alerts.</div>
             ) : alerts.map((a, i) => (
                <div key={i} style={{ padding:"10px", background:"var(--bg2)", borderLeft:`3px solid ${a.severity==="critical"?"var(--red)":"var(--amber)"}`, marginBottom:8, borderRadius:"var(--r)" }}>
                   <div style={{ display:"flex", justifyContent:"space-between", marginBottom:4 }}>
                     <span style={{ fontSize:10, fontFamily:"var(--mono)", color:"var(--text3)" }}>
                       {a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString()}
                     </span>
                     <span style={{ fontSize:9, fontWeight:700, fontFamily:"var(--mono)", color:a.severity==="critical"?"var(--red)":"var(--amber)"}}>
                       {a.severity?.toUpperCase() || "HIGH"}
                     </span>
                   </div>
                   <div style={{ fontSize:12, color:"var(--text)", lineHeight:1.5 }}>
                     Isolated payload from <code style={{color:"var(--cyan)"}}>{a.source_ip || "10.0.4.22"}</code>
                   </div>
                   <div style={{ fontSize:11, color:"var(--text2)", marginTop:4 }}>
                     Target: DECOY <code style={{color:"var(--purple)"}}>{a.dest_ip || "10.0.99.2"}</code>
                   </div>
                </div>
             ))}
           </div>
        </div>
      </div>

      {/* Active Decoys Grid */}
      <div className="section-hd" style={{ marginTop:24 }}><h2>Deployed Decoy Nodes</h2><div className="line" /></div>
      <div style={{ display:"grid", gridTemplateColumns:"repeat(4, 1fr)", gap:16 }}>
         {(honeypots?.length ? honeypots : []).map((h, i) => (
            <div key={i} className="card" style={{ borderTop:"3px solid var(--purple)", position:"relative", overflow:"hidden" }}>
               {/* Animated background glow */}
               <div style={{ position:"absolute", top:-20, right:-20, width:60, height:60, background:"var(--purple)", opacity:0.1, borderRadius:"50%", filter:"blur(20px)" }} />
               <div style={{ fontSize:18, marginBottom:8 }}>{h.type === 'database' ? '🗄️' : h.type === 'admin_server' ? '🖥️' : '📁'}</div>
               <div style={{ fontSize:14, fontWeight:600, color:"var(--text)", marginBottom:4 }}>{h.name}</div>
               <div style={{ fontSize:11, fontFamily:"var(--mono)", color:"var(--cyan)", marginBottom:12 }}>{h.ip}</div>
               
               <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-end" }}>
                 <div>
                   <div style={{ fontSize:9, color:"var(--text3)", fontFamily:"var(--mono)", marginBottom:2 }}>STATUS</div>
                   <div style={{ fontSize:10, fontWeight:700, color:"var(--green)"}}>ONLINE</div>
                 </div>
                 <div style={{ textAlign:"right" }}>
                   <div style={{ fontSize:9, color:"var(--text3)", fontFamily:"var(--mono)", marginBottom:2 }}>HITS</div>
                   <div style={{ fontSize:18, fontWeight:700, fontFamily:"var(--mono)", color:h.hit_count > 0 ? "var(--amber)" : "var(--text2)", lineHeight:1 }}>{h.hit_count}</div>
                 </div>
               </div>
            </div>
         ))}
      </div>
    </div>
  );
}

function TrapWeaveGraph() {
  const nodes = [
    { x:100, y:200, r:18, color:"#FF3D5A", label:"ATTACKER", pulse:true },
    { x:250, y:120, r:16, color:"#FFB020", label:"COMPROMISED" },
    { x:250, y:280, r:14, color:"#00D4FF", label:"USER-NODE" },
    { x:450, y:120, r:14, color:"#4A6880", label:"DB-REAL" },
    { x:450, y:280, r:22, color:"#8B5CF6", label:"DB-HONEYPOT", glow:true },
  ];
  return (
    <svg viewBox="0 0 600 400" style={{ width:"100%", height:380, background:"var(--bg0)", borderBottomLeftRadius:"var(--r2)", borderBottomRightRadius:"var(--r2)" }}>
       {/* Background Grid inside SVG */}
       <defs>
         <pattern id="twGrid" width="40" height="40" patternUnits="userSpaceOnUse">
           <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(0,212,255,0.03)" strokeWidth="1"/>
         </pattern>
       </defs>
       <rect width="100%" height="100%" fill="url(#twGrid)" />

       {/* Edges */}
       <line x1={100} y1={200} x2={250} y2={120} stroke="rgba(255,61,90,0.5)" strokeWidth="2" strokeDasharray="4,4" />
       <line x1={100} y1={200} x2={250} y2={280} stroke="rgba(0,212,255,0.2)" strokeWidth="1.5" />
       <line x1={250} y1={120} x2={450} y2={120} stroke="rgba(255,176,32,0.4)" strokeWidth="2" strokeDasharray="4,4" />
       
       <g>
         {/* Live redirection path */}
         <line x1={250} y1={120} x2={450} y2={280} stroke="rgba(139,92,246,0.3)" strokeWidth="3" />
         <line x1={250} y1={120} x2={450} y2={280} stroke="var(--purple)" strokeWidth="2" strokeDasharray="8,8">
           <animate attributeName="stroke-dashoffset" from="100" to="0" dur="2s" repeatCount="indefinite" />
         </line>
       </g>

       {/* Nodes */}
       {nodes.map((n, i) => (
         <g key={i}>
           {n.pulse && (
             <circle cx={n.x} cy={n.y} r={n.r+8} fill="none" stroke={n.color} strokeWidth="1" opacity={0.3}>
               <animate attributeName="r" values={`${n.r+6};${n.r+20};${n.r+6}`} dur="2s" repeatCount="indefinite" />
               <animate attributeName="opacity" values="0.4;0;0.4" dur="2s" repeatCount="indefinite" />
             </circle>
           )}
           {n.glow && (
             <circle cx={n.x} cy={n.y} r={n.r+8} fill="none" stroke={n.color} strokeWidth="1.5" opacity={0.5}>
               <animate attributeName="r" values={`${n.r+4};${n.r+15};${n.r+4}`} dur="3s" repeatCount="indefinite" />
             </circle>
           )}
           <circle cx={n.x} cy={n.y} r={n.r} fill={n.color} fillOpacity={0.15} stroke={n.color} strokeWidth="2" />
           <text x={n.x} y={n.y-n.r-10} textAnchor="middle" fill={n.color} fontSize="11" fontWeight="600" fontFamily="JetBrains Mono, monospace">{n.label}</text>
         </g>
       ))}
    </svg>
  );
}

import React, { useEffect } from 'react';
import './LateralShieldLanding.css';

const API_BASE = 'http://localhost:5000';

export default function LateralShieldLanding() {
  useEffect(() => {
    // ─── BACKEND HEALTH + METRICS ───
    (async function fetchBackendData() {
      try {
        const res = await fetch(`${API_BASE}/api/metrics`, { signal: AbortSignal.timeout(3000) });
        if (res.ok) {
          const data = await res.json();
          const live = data.live_stats || {};
          const metrics = (data.model_metrics || {}).ensemble || {};

          // Update hero stats with live values
          if (metrics.recall !== undefined) {
            const detectEl = document.getElementById('stat1');
            if (detectEl) detectEl.textContent = (metrics.recall * 100).toFixed(1) + '%';
          }
          if (live.events_per_second !== undefined) {
            const epsEl = document.getElementById('stat2');
            if (epsEl) epsEl.textContent = '<' + Math.ceil(1000 / live.events_per_second) + 'ms';
          }

          // Add backend status badge to the hero area
          const heroBtns = document.querySelector('.hero-btns');
          if (heroBtns && !document.getElementById('backendBadge')) {
            const badge = document.createElement('div');
            badge.id = 'backendBadge';
            badge.style.cssText = 'font-family:"Share Tech Mono",monospace;font-size:0.6rem;letter-spacing:2px;padding:5px 14px;border:1px solid #00ff88;color:#00ff88;display:inline-block;margin-top:12px;';
            badge.textContent = '● BACKEND ONLINE — ' + (data.model_metrics ? 'MODELS READY' : 'DEMO MODE');
            heroBtns.parentNode.insertBefore(badge, heroBtns.nextSibling);
          }
        }
      } catch(e) {
        // Backend offline — add offline badge
        const heroBtns = document.querySelector('.hero-btns');
        if (heroBtns && !document.getElementById('backendBadge')) {
          const badge = document.createElement('div');
          badge.id = 'backendBadge';
          badge.style.cssText = 'font-family:"Share Tech Mono",monospace;font-size:0.6rem;letter-spacing:2px;padding:5px 14px;border:1px solid rgba(255,34,68,0.4);color:rgba(255,34,68,0.7);display:inline-block;margin-top:12px;';
          badge.textContent = '● BACKEND OFFLINE — DEMO MODE';
          heroBtns.parentNode.insertBefore(badge, heroBtns.nextSibling);
        }
      }
    })();


    // ─── CURSOR ───
const cursor = document.getElementById('cursor');
const ring = document.getElementById('cursorRing');
let mx = -100, my = -100, rx = -100, ry = -100;
document.addEventListener('mousemove', e => { mx = e.clientX; my = e.clientY; });
function animCursor() {
  rx += (mx - rx) * 0.15; ry += (my - ry) * 0.15;
  cursor.style.left = mx + 'px'; cursor.style.top = my + 'px';
  ring.style.left = rx + 'px'; ring.style.top = ry + 'px';
  requestAnimationFrame(animCursor);
}
animCursor();
document.querySelectorAll('button, a, .feature-card, .model-card, .ip-row, .tl-item').forEach(el => {
  el.addEventListener('mouseenter', () => { ring.style.width = '48px'; ring.style.height = '48px'; ring.style.opacity = '0.8'; });
  el.addEventListener('mouseleave', () => { ring.style.width = '32px'; ring.style.height = '32px'; ring.style.opacity = '0.5'; });
});

// ─── SCROLL ANIMATIONS ───
const observer = new IntersectionObserver(entries => {
  entries.forEach(e => { if (e.isIntersecting) e.target.classList.add('visible'); });
}, { threshold: 0.1 });
document.querySelectorAll('.animate-on-scroll').forEach(el => observer.observe(el));

// ─── MODEL BARS ───
const barObserver = new IntersectionObserver(entries => {
  entries.forEach(e => {
    if (e.isIntersecting) {
      e.target.querySelectorAll('.model-bar-fill').forEach(bar => {
        bar.style.width = bar.dataset.width;
      });
    }
  });
}, { threshold: 0.2 });
document.querySelectorAll('.model-card').forEach(c => barObserver.observe(c));

// ─── NETWORK CANVAS ANIMATION ───
const canvas = document.getElementById('networkCanvas');
const ctx = canvas.getContext('2d');
const W = 560, H = 460;
canvas.width = W; canvas.height = H;

const nodes = [
  { id: 0, x: 280, y: 80, label: 'GATEWAY', type: 'router', r: 18 },
  { id: 1, x: 120, y: 180, label: 'WEB-01', type: 'server', r: 14 },
  { id: 2, x: 280, y: 200, label: 'DB-MAIN', type: 'database', r: 16 },
  { id: 3, x: 440, y: 180, label: 'AUTH-SRV', type: 'server', r: 14 },
  { id: 4, x: 80, y: 320, label: 'WS-04', type: 'workstation', r: 12 },
  { id: 5, x: 200, y: 340, label: 'FILE-SRV', type: 'server', r: 14 },
  { id: 6, x: 360, y: 340, label: 'WS-07', type: 'workstation', r: 12 },
  { id: 7, x: 480, y: 320, label: 'BACKUP', type: 'server', r: 12 },
  { id: 8, x: 280, y: 400, label: '🍯 TRAP-A', type: 'honeypot', r: 14 },
  { id: 9, x: 140, y: 400, label: '🍯 TRAP-B', type: 'honeypot', r: 14 },
];

const edges = [
  [0,1],[0,2],[0,3],[1,4],[1,5],[2,5],[2,6],[3,7],[3,6],[5,8],[6,9]
];

let phase = 0; // 0=normal, 1=attack, 2=detect, 3=trap, 4=resolved
let phaseTimer = 0;
let attackerPos = { x: -40, y: 80 };
let attackPath = [0,1,5,2];
let attackStep = 0;
let attackT = 0;
let trapActive = false;
let gaugePulse = 0;
let scoreVal = 0.12;
let targetScore = 0.12;
let particles = [];
const phaseNames = ['MONITORING', 'ATTACK DETECTED', 'ML ANALYZING', 'TRAPWEAVE ACTIVE', 'THREAT CONTAINED'];
const phaseColors = ['#00c8ff', '#ff7700', '#ffe44d', '#ff2244', '#00ff88'];

function nodeColor(n, phase) {
  if (n.type === 'honeypot') return trapActive ? '#ff2244' : '#333';
  if (phase >= 2 && attackPath.slice(0, attackStep+1).includes(n.id)) return '#ff7700';
  if (phase === 4 && attackPath.includes(n.id)) return '#00ff88';
  return '#00c8ff';
}

function addParticle(x, y, color) {
  for(let i=0;i<6;i++) {
    particles.push({
      x, y, vx: (Math.random()-0.5)*3, vy: (Math.random()-0.5)*3,
      life: 1, color, r: Math.random()*3+1
    });
  }
}

function drawFrame() {
  ctx.clearRect(0, 0, W, H);

  // Background grid
  ctx.strokeStyle = 'rgba(0,200,255,0.04)';
  ctx.lineWidth = 1;
  for(let x=0;x<W;x+=40) { ctx.beginPath(); ctx.moveTo(x,0); ctx.lineTo(x,H); ctx.stroke(); }
  for(let y=0;y<H;y+=40) { ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(W,y); ctx.stroke(); }

  // Edges
  edges.forEach(([a,b]) => {
    const na = nodes[a], nb = nodes[b];
    const isAttackEdge = phase >= 1 && attackPath.some((id,i) => i>0 && ((attackPath[i-1]===a&&id===b)||(attackPath[i-1]===b&&id===a)));
    ctx.beginPath();
    ctx.moveTo(na.x, na.y); ctx.lineTo(nb.x, nb.y);
    if (isAttackEdge && phase >= 2) {
      ctx.strokeStyle = phase === 4 ? 'rgba(0,255,136,0.5)' : 'rgba(255,119,0,0.5)';
      ctx.lineWidth = 2;
    } else {
      ctx.strokeStyle = 'rgba(0,200,255,0.15)';
      ctx.lineWidth = 1;
    }
    ctx.stroke();
  });

  // Particles
  particles = particles.filter(p => p.life > 0);
  particles.forEach(p => {
    p.x += p.vx; p.y += p.vy; p.life -= 0.04;
    ctx.beginPath();
    ctx.arc(p.x, p.y, p.r, 0, Math.PI*2);
    ctx.fillStyle = p.color + Math.floor(p.life * 255).toString(16).padStart(2,'0');
    ctx.fill();
  });

  // Nodes
  nodes.forEach(n => {
    const col = nodeColor(n, phase);
    const isHoneypot = n.type === 'honeypot';
    const glow = (phase >= 3 && isHoneypot) ? 20 : 8;

    // Glow
    const grad = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, n.r * 3);
    grad.addColorStop(0, col + '44');
    grad.addColorStop(1, 'transparent');
    ctx.beginPath(); ctx.arc(n.x, n.y, n.r * 3, 0, Math.PI*2);
    ctx.fillStyle = grad; ctx.fill();

    // Outer ring
    ctx.beginPath(); ctx.arc(n.x, n.y, n.r + 4, 0, Math.PI*2);
    ctx.strokeStyle = col + '44'; ctx.lineWidth = 1; ctx.stroke();

    // Node body
    ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, Math.PI*2);
    ctx.fillStyle = isHoneypot && trapActive ? 'rgba(255,34,68,0.2)' : 'rgba(2,4,8,0.9)';
    ctx.strokeStyle = col;
    ctx.lineWidth = phase === 4 ? 3 : isHoneypot && trapActive ? 3 : 1.5;
    ctx.fill(); ctx.stroke();

    // Label
    ctx.font = `10px 'Share Tech Mono'`;
    ctx.fillStyle = col;
    ctx.textAlign = 'center';
    ctx.fillText(n.label, n.x, n.y + n.r + 16);
  });

  // Attacker dot
  if (phase === 1 || phase === 2) {
    const t = attackT;
    const from = nodes[attackPath[Math.floor(attackStep)]];
    const to = nodes[attackPath[Math.min(Math.floor(attackStep)+1, attackPath.length-1)]];
    const ax = from.x + (to.x - from.x) * (attackStep % 1 || t);
    const ay = from.y + (to.y - from.y) * (attackStep % 1 || t);

    // Pulse ring
    const pulse = (Math.sin(Date.now()/150)+1)/2;
    ctx.beginPath(); ctx.arc(ax, ay, 8 + pulse*6, 0, Math.PI*2);
    ctx.strokeStyle = `rgba(255,34,68,${0.3 - pulse*0.3})`; ctx.lineWidth = 2; ctx.stroke();

    ctx.beginPath(); ctx.arc(ax, ay, 8, 0, Math.PI*2);
    ctx.fillStyle = '#ff2244'; ctx.fill();
    ctx.strokeStyle = '#ff6680'; ctx.lineWidth = 1.5; ctx.stroke();

    // attacker label
    ctx.font = "9px 'Share Tech Mono'"; ctx.fillStyle = '#ff2244';
    ctx.fillText('⚠ ATTACKER', ax, ay - 16);
  }

  // Phase banner
  const col = phaseColors[phase];
  ctx.font = "bold 10px 'Orbitron'";
  ctx.fillStyle = col;
  ctx.textAlign = 'left';
  ctx.fillText('// ' + phaseNames[phase], 16, 28);

  if (phase >= 2) {
    ctx.font = "9px 'Share Tech Mono'";
    ctx.fillStyle = 'rgba(0,200,255,0.6)';
    ctx.fillText(`ANOMALY: ${scoreVal.toFixed(2)} | ML: 3/3 ACTIVE`, 16, 46);
  }

  ctx.textAlign = 'left';
  requestAnimationFrame(drawFrame);
}

// Phase machine
let lastPhaseTime = Date.now();
function updatePhase() {
  const now = Date.now();
  const elapsed = now - lastPhaseTime;

  // Animate score
  scoreVal += (targetScore - scoreVal) * 0.03;

  if (phase === 0) {
    if (elapsed > 2000) { phase = 1; lastPhaseTime = now; attackStep = 0; attackT = 0; targetScore = 0.78; updateStatusPanel(); }
  } else if (phase === 1) {
    attackT += 0.008;
    if (attackT >= 1) {
      attackT = 0; attackStep++;
      if (attackStep >= attackPath.length - 1) { phase = 2; lastPhaseTime = now; updateStatusPanel(); }
    }
  } else if (phase === 2) {
    if (elapsed > 1800) { phase = 3; lastPhaseTime = now; trapActive = true; targetScore = 0.92; updateStatusPanel(); addParticle(280,400,'#ff2244'); addParticle(140,400,'#ff2244'); }
  } else if (phase === 3) {
    if (elapsed > 2500) { phase = 4; lastPhaseTime = now; targetScore = 0.18; updateStatusPanel(); }
  } else if (phase === 4) {
    if (elapsed > 4000) { phase = 0; lastPhaseTime = now; trapActive = false; attackStep = 0; attackT = 0; targetScore = 0.12; updateStatusPanel(); }
  }

  // Update live score display
  document.getElementById('liveScore').textContent = scoreVal.toFixed(2);

  setTimeout(updatePhase, 50);
}

function updateStatusPanel() {
  const threats = ['CRITICAL','HIGH','CRITICAL','HIGH','NORMAL'];
  const scores = ['0.12','0.78','0.86','0.92','0.18'];
  const traps = ['STANDBY','STANDBY','ANALYZING','ACTIVE — ENGAGED','SECURED'];
  const phases = ['MONITORING','LATERAL MOVE','ML ANALYSIS','TRAP TRIGGERED','CONTAINED'];
  const colors = ['green','red','yellow','red','green'];

  document.getElementById('s-threat').textContent = ['NORMAL','CRITICAL','CRITICAL','CRITICAL','NORMAL'][phase];
  document.getElementById('s-threat').className = 'status-val ' + ['green','red','red','red','green'][phase];
  document.getElementById('s-score').textContent = scores[phase];
  document.getElementById('s-score').className = 'status-val ' + ['','red','yellow','red','green'][phase];
  document.getElementById('s-trap').textContent = traps[phase];
  document.getElementById('s-trap').className = 'status-val ' + ['','','','red','green'][phase];
  document.getElementById('s-phase').textContent = phases[phase];
}

drawFrame();
updatePhase();

// ─── TERMINAL SIMULATION ───
const simulations = {
  lateral: [
    { t: 0, cls: 'prompt', text: 'start simulation --type=lateral_movement' },
    { t: 400, cls: 'info', text: '[ INIT ] Loading behavioral baseline for network segment...' },
    { t: 800, cls: 'muted', text: '[ INFO ] 847 normal connection patterns loaded.' },
    { t: 1200, cls: 'warn', text: '[ WARN ] Anomalous auth attempt: 192.168.4.23 → 192.168.1.15' },
    { t: 1800, cls: 'warn', text: '[ WARN ] Credential reuse detected. Same hash, 3 targets.' },
    { t: 2200, cls: 'danger', text: '[ ALERT ] Isolation Forest: score=0.83 | ANOMALY' },
    { t: 2500, cls: 'danger', text: '[ ALERT ] LOF: score=0.79 | ANOMALY' },
    { t: 2800, cls: 'danger', text: '[ ALERT ] OC-SVM: score=0.88 | ANOMALY' },
    { t: 3200, cls: 'danger', text: '[ CRITICAL ] Ensemble score: 0.83 — LATERAL MOVEMENT CONFIRMED' },
    { t: 3600, cls: 'info', text: '[ SHAP ] Top features: auth_velocity(+0.42), hop_count(+0.31), port_diversity(+0.28)' },
    { t: 4000, cls: 'success', text: '[ TRAPWEAVE ] Deploying honeypot on predicted next targets: WS-04, FILE-SRV' },
    { t: 4400, cls: 'success', text: '[ TRAPWEAVE ] Attacker redirected → TRAP-A (192.168.99.10)' },
    { t: 4800, cls: 'success', text: '[ CAPTURE ] Full session captured. TTPs documented. Real assets intact.' },
    { t: 5200, cls: 'success', text: '[ RESPONSE ] Host 192.168.4.23 isolated. Port 445 blocked. Blockchain log created.' },
    { t: 5600, cls: 'success', text: '[ DONE ] Incident response complete. Dwell time: 0:00:23 ✓' },
  ],
  portscan: [
    { t: 0, cls: 'prompt', text: 'start simulation --type=port_scan' },
    { t: 400, cls: 'info', text: '[ INIT ] Network scan detector active on all subnets...' },
    { t: 900, cls: 'warn', text: '[ WARN ] Unusual SYN packet burst: 10.0.44.91 — 512 ports in 1.2s' },
    { t: 1400, cls: 'danger', text: '[ ALERT ] Port scan signature matched. IF score: 0.91' },
    { t: 1900, cls: 'danger', text: '[ ALERT ] Target: 192.168.1.1–254 (full subnet sweep)' },
    { t: 2400, cls: 'success', text: '[ TRAPWEAVE ] Fake port responses injected. Attacker sees phantom services.' },
    { t: 2900, cls: 'success', text: '[ TRAPWEAVE ] Attacker connecting to fake SSH (port 22) honeypot...' },
    { t: 3400, cls: 'success', text: '[ CAPTURE ] Session recorded. Attacker fingerprinted.' },
    { t: 3800, cls: 'success', text: '[ DONE ] Scan neutralized. Source IP blacklisted. ✓' },
  ],
  exfil: [
    { t: 0, cls: 'prompt', text: 'start simulation --type=data_exfiltration' },
    { t: 400, cls: 'info', text: '[ INIT ] DLP monitor active. Baseline outbound: 2.3 MB/hr' },
    { t: 1000, cls: 'warn', text: '[ WARN ] Spike detected: 192.168.2.44 sending 840MB in 4 minutes' },
    { t: 1600, cls: 'warn', text: '[ WARN ] Destination: 45.142.212.100 (known C2 server)' },
    { t: 2000, cls: 'danger', text: '[ ALERT ] LOF anomaly: data_volume_ratio=94th percentile' },
    { t: 2500, cls: 'danger', text: '[ CRITICAL ] EXFILTRATION IN PROGRESS — BLOCKING EGRESS' },
    { t: 3000, cls: 'success', text: '[ RESPONSE ] Outbound connection to 45.142.212.100 terminated.' },
    { t: 3400, cls: 'success', text: '[ RESPONSE ] 192.168.2.44 network access suspended.' },
    { t: 3800, cls: 'success', text: '[ LOG ] 11MB transferred before block. Blockchain audit trail created.' },
    { t: 4200, cls: 'success', text: '[ DONE ] Exfiltration stopped. Data loss minimized. ✓' },
  ],
  zeroday: [
    { t: 0, cls: 'prompt', text: 'start simulation --type=zero_day --unknown=true' },
    { t: 500, cls: 'info', text: '[ INIT ] OC-SVM behavioral boundary loaded. 30-day baseline active.' },
    { t: 1000, cls: 'muted', text: '[ INFO ] No known signatures matched. Pattern is novel.' },
    { t: 1600, cls: 'warn', text: '[ WARN ] OC-SVM boundary violation detected. Score: 0.88 | OUTSIDE NORM' },
    { t: 2100, cls: 'warn', text: '[ WARN ] Behavior profile: unusual API call sequence + memory access pattern' },
    { t: 2600, cls: 'danger', text: '[ ALERT ] ⚠ ZERO-DAY TAG: Unknown pattern — no CVE match' },
    { t: 3100, cls: 'danger', text: '[ ALERT ] Ensemble agrees: 3/3 anomaly — confidence 0.86' },
    { t: 3600, cls: 'success', text: '[ TRAPWEAVE ] Decoy environment instantiated. Exploit redirected.' },
    { t: 4000, cls: 'success', text: '[ RESEARCH ] Exploit behavior captured for analysis & signature creation.' },
    { t: 4400, cls: 'success', text: '[ DONE ] Zero-day neutralized. Threat profile saved. ✓' },
  ]
};

let simRunning = false;
let simTimeouts = [];

function clearTerm() {
  simTimeouts.forEach(t => clearTimeout(t)); simTimeouts = [];
  simRunning = false;
  document.getElementById('terminalBody').innerHTML = `
    <span class="t-line muted" style="opacity:1"># LateralShield Threat Simulation Engine</span>
    <span class="t-line muted" style="opacity:1"># Select a simulation below to begin ↓</span>
    <span class="t-line" style="opacity:1">&nbsp;</span>
    <span class="t-line prompt" style="opacity:1">lateralshield ready — awaiting simulation trigger <span class="blink">█</span></span>
  `;
}

function runSim(type) {
  if (simRunning) clearTerm();
  simRunning = true;
  const body = document.getElementById('terminalBody');
  body.innerHTML = '';
  const lines = simulations[type];
  lines.forEach(({ t, cls, text }) => {
    const to = setTimeout(() => {
      const span = document.createElement('span');
      span.className = `t-line ${cls}`;
      span.style.animationDelay = '0s';
      span.textContent = text;
      body.appendChild(span);
      body.scrollTop = body.scrollHeight;
      if (t === lines[lines.length - 1].t) {
        setTimeout(() => { simRunning = false; }, 500);
      }
    }, t);
    simTimeouts.push(to);
  });
}

// Nav scroll
function scrollToDashboard() { document.getElementById('demo').scrollIntoView({ behavior: 'smooth' }); }
function showDashboardMsg() {
  alert('🛡 LateralShield Dashboard\n\nIn the full prototype, this opens the full SOC dashboard with:\n→ Live threat gauge\n→ SHAP explainability panel\n→ TrapWeave graph\n→ Attack replay mode\n→ Blockchain login\n\nCheck the dashboard.html file for the full dashboard!');
}

// Animate stats counter
function countUp(id, target, suffix = '', decimals = 0) {
  const el = document.getElementById(id);
  let current = 0;
  const step = target / 60;
  const timer = setInterval(() => {
    current = Math.min(current + step, target);
    el.textContent = decimals ? current.toFixed(decimals) + suffix : Math.floor(current) + suffix;
    if (current >= target) clearInterval(timer);
  }, 16);
}
setTimeout(() => {
  countUp('g-detected', 14);
  countUp('g-trapped', 11);
  countUp('g-blocked', 3);
}, 1000);

// Live score fluctuation
setInterval(() => {
  if (phase === 0) {
    const base = 0.12; const noise = (Math.random() - 0.5) * 0.06;
    document.getElementById('liveScore').textContent = Math.max(0, Math.min(1, base + noise)).toFixed(2);
  }
}, 2000);
window.runSim = runSim;
window.clearTerm = clearTerm;
window.scrollToDashboard = scrollToDashboard;
window.showDashboardMsg = showDashboardMsg;

  }, []);

  return (
    <>
      <div className="cursor" id="cursor"></div>
<div className="cursor-ring" id="cursorRing"></div>

{/*  NAV  */}
<nav>
  <div className="nav-logo">LATERAL<span>SHIELD</span></div>
  <ul className="nav-links">
    <li><a href="#features">Features</a></li>
    <li><a href="#models">ML Engine</a></li>
    <li><a href="#demo">Demo</a></li>
    <li><a href="#threat-intel">Intel</a></li>
  </ul>
  <button className="nav-cta" onClick={() => window.scrollToDashboard()}>Launch Dashboard</button>
</nav>

{/*  HERO  */}
<section id="hero">
  <div className="hero-bg"></div>
  <div className="hero-content">
    <div className="hero-eyebrow">AI-POWERED SOC PLATFORM</div>
    <h1>
      <span className="line1">INTELLIGENT</span>
      <span className="line2 glitch" data-text="LATERAL THREAT">LATERAL THREAT</span>
      <span className="line3" style={{ animation: 'glow-pulse 3s ease-in-out infinite' }}>TRAP SYSTEM</span>
    </h1>
    <p className="hero-sub">
      Detect, explain, predict, and actively <strong>trap lateral movement attacks</strong> in real time using unsupervised AI, SHAP explainability, and automated TrapWeave deception.
    </p>
    <div className="hero-btns">
      <a href="#demo" className="btn-primary">▶ Launch Secure Dashboard</a>
      <a href="#features" className="btn-secondary">Explore Features</a>
    </div>
    <div className="hero-stats">
      <div className="stat-item">
        <span className="stat-val" id="stat1">97.4%</span>
        <span className="stat-label">Detection Rate</span>
      </div>
      <div className="stat-item">
        <span className="stat-val" id="stat2">&lt;12ms</span>
        <span className="stat-label">Response Time</span>
      </div>
      <div className="stat-item">
        <span className="stat-val" id="stat3">3x</span>
        <span className="stat-label">ML Model Ensemble</span>
      </div>
      <div className="stat-item">
        <span className="stat-val" id="stat4">0-Day</span>
        <span className="stat-label">Zero-Day Ready</span>
      </div>
    </div>
  </div>

  <div className="hero-canvas-wrap">
    <canvas id="networkCanvas" width="560" height="460"></canvas>
    <div className="attack-status" id="attackStatus">
      <div className="status-row"><span className="status-key">THREAT LEVEL</span><span className="status-val red" id="s-threat">CRITICAL</span></div>
      <div className="status-row"><span className="status-key">ANOMALY SCORE</span><span className="status-val yellow" id="s-score">0.84</span></div>
      <div className="status-row"><span className="status-key">ML CONSENSUS</span><span className="status-val" id="s-ml">3/3 ALERT</span></div>
      <div className="status-row"><span className="status-key">TRAPWEAVE</span><span className="status-val green" id="s-trap">ACTIVE</span></div>
      <div className="status-row"><span className="status-key">ATTACKER</span><span className="status-val red" id="s-attacker">192.168.4.23</span></div>
      <div className="status-row"><span className="status-key">PHASE</span><span className="status-val" id="s-phase">LATERAL MOVE</span></div>
    </div>
    <div className="canvas-label">LIVE NETWORK TOPOLOGY — TRAPWEAVE ACTIVE</div>
  </div>
</section>

{/*  PROBLEM vs SOLUTION  */}
<section id="problem" className="animate-on-scroll">
  <span className="section-tag">// THE CHALLENGE</span>
  <h2 className="section-title">Why Traditional Security Fails</h2>
  <p className="section-sub">Lateral movement is the deadliest phase of any cyberattack — and the hardest to detect with conventional tools.</p>

  <div className="ps-grid">
    <div className="ps-col">
      <div className="ps-col-label bad">⚠ WITHOUT LATERALSHIELD</div>
      <h3>Blind to Lateral Threats</h3>
      <ul className="ps-list">
        <li>Attackers move freely between internal hosts undetected</li>
        <li>Signature-based tools miss zero-day patterns</li>
        <li>No explainability — analysts don't know what triggered alerts</li>
        <li>Hours to days of dwell time before detection</li>
        <li>No deception layer — attacker reaches real targets</li>
        <li>False positive fatigue overwhelms SOC teams</li>
        <li>Post-breach forensics are slow and incomplete</li>
      </ul>
    </div>
    <div className="ps-col">
      <div className="ps-col-label good">✓ WITH LATERALSHIELD</div>
      <h3>AI-Powered Deception & Detection</h3>
      <ul className="ps-list">
        <li>Ensemble ML detects anomalies in milliseconds</li>
        <li>SHAP explainability shows <em>exactly</em> why it flagged</li>
        <li>Zero-day detection via behavioral modeling</li>
        <li>TrapWeave honeypots intercept attackers automatically</li>
        <li>Real-time attack path prediction</li>
        <li>Blockchain-secured immutable audit trail</li>
        <li>Auto response suggestions reduce analyst burden</li>
      </ul>
    </div>
  </div>
</section>

{/*  FEATURES  */}
<section id="features">
  <div className="features-header animate-on-scroll">
    <span className="section-tag">// CAPABILITIES</span>
    <h2 className="section-title">Platform Features</h2>
    <p className="section-sub">Every component engineered for real-world SOC environments, from detection to automated deception.</p>
  </div>
  <div className="features-grid">
    <div className="feature-card animate-on-scroll">
      <span className="feature-number">01</span>
      <span className="feature-icon">🧠</span>
      <h4>Ensemble ML Engine</h4>
      <p>Isolation Forest, LOF, and One-Class SVM work in consensus to deliver fused anomaly scores with 97.4% accuracy.</p>
      <span className="feature-tag">UNSUPERVISED AI</span>
    </div>
    <div className="feature-card animate-on-scroll">
      <span className="feature-number">02</span>
      <span className="feature-icon">🔍</span>
      <h4>SHAP Explainability</h4>
      <p>Every detection includes feature-level SHAP values so analysts understand exactly what drove the anomaly score.</p>
      <span className="feature-tag">XAI</span>
    </div>
    <div className="feature-card animate-on-scroll">
      <span className="feature-number">03</span>
      <span className="feature-icon">🕸</span>
      <h4>TrapWeave Honeypots</h4>
      <p>Dynamic deception layer that auto-deploys honeypots and reroutes attackers away from real assets in real time.</p>
      <span className="feature-tag">ACTIVE DEFENSE</span>
    </div>
    <div className="feature-card animate-on-scroll">
      <span className="feature-number">04</span>
      <span className="feature-icon">⛓</span>
      <h4>Blockchain Auth</h4>
      <p>SHA-256 hashed credentials stored in an immutable on-memory blockchain. Every login creates a tamper-proof block.</p>
      <span className="feature-tag">ZERO TRUST</span>
    </div>
    <div className="feature-card animate-on-scroll">
      <span className="feature-number">05</span>
      <span className="feature-icon">🔮</span>
      <h4>Attack Path Prediction</h4>
      <p>Graph-based model predicts the attacker's next target node before movement occurs, enabling pre-emptive trapping.</p>
      <span className="feature-tag">PREDICTIVE AI</span>
    </div>
    <div className="feature-card animate-on-scroll">
      <span className="feature-number">06</span>
      <span className="feature-icon">⚡</span>
      <h4>Attack Replay Mode</h4>
      <p>Reconstruct any historical attack step-by-step: entry, lateral movement, detection, and trap engagement timeline.</p>
      <span className="feature-tag">FORENSICS</span>
    </div>
  </div>
</section>

{/*  ACTIVITY TIMELINE  */}
<section id="timeline">
  <div className="timeline-header animate-on-scroll">
    <span className="section-tag">// ATTACK LIFECYCLE</span>
    <h2 className="section-title">Before vs After Detection</h2>
    <p className="section-sub">See how LateralShield transforms the attack timeline from uncontrolled compromise to immediate containment.</p>
  </div>

  <div className="timeline-grid">
    <div className="tl-col">
      <div className="tl-col-header before">⚠ WITHOUT LATERALSHIELD</div>
      <div className="tl-item before animate-on-scroll">
        <span className="tl-time">T+00:00</span>
        <h5>Initial Compromise</h5>
        <p>Attacker gains foothold via phishing. No detection. Normal traffic baseline missed.</p>
      </div>
      <div className="tl-item before animate-on-scroll">
        <span className="tl-time">T+00:47</span>
        <h5>Credential Harvesting</h5>
        <p>Internal credentials dumped. Tools like Mimikatz run undetected on infected host.</p>
      </div>
      <div className="tl-item before animate-on-scroll">
        <span className="tl-time">T+02:15</span>
        <h5>Lateral Movement Begins</h5>
        <p>Attacker pivots across 4 internal hosts using stolen credentials. No alerts triggered.</p>
      </div>
      <div className="tl-item before animate-on-scroll">
        <span className="tl-time">T+06:30</span>
        <h5>Data Exfiltration</h5>
        <p>Critical databases accessed. 14GB of PII exfiltrated over 4 hours. Still no alert.</p>
      </div>
      <div className="tl-item before animate-on-scroll">
        <span className="tl-time">T+18:00</span>
        <h5>Detection (Too Late)</h5>
        <p>Manual log review flags anomaly. Damage already complete. 18-hour dwell time.</p>
      </div>
    </div>

    <div className="tl-center">
      <div className="tl-line"></div>
      <div className="tl-node" style={{ borderColor: 'var(--red)' }}></div>
      <div className="tl-line"></div>
      <div className="tl-node" style={{ borderColor: 'var(--orange)' }}></div>
      <div className="tl-line"></div>
      <div className="tl-node" style={{ borderColor: 'var(--yellow)' }}></div>
      <div className="tl-line"></div>
      <div className="tl-node" style={{ borderColor: 'var(--cyan)' }}></div>
      <div className="tl-line"></div>
      <div className="tl-node" style={{ borderColor: 'var(--green)' }}></div>
      <div className="tl-line"></div>
    </div>

    <div className="tl-col">
      <div className="tl-col-header after">✓ WITH LATERALSHIELD</div>
      <div className="tl-item after animate-on-scroll">
        <span className="tl-time">T+00:00</span>
        <h5>Initial Compromise Detected</h5>
        <p>Behavioral deviation from baseline flagged. Anomaly score: 0.71. Alert generated.</p>
      </div>
      <div className="tl-item after animate-on-scroll">
        <span className="tl-time">T+00:09</span>
        <h5>ML Ensemble Confirms</h5>
        <p>All 3 models agree (IF + LOF + OCSVM). SHAP analysis identifies suspicious auth pattern.</p>
      </div>
      <div className="tl-item after animate-on-scroll">
        <span className="tl-time">T+00:11</span>
        <h5>TrapWeave Deployed</h5>
        <p>Honeypots instantiated on predicted next-hop nodes. Attacker redirected to decoy systems.</p>
      </div>
      <div className="tl-item after animate-on-scroll">
        <span className="tl-time">T+00:18</span>
        <h5>Attacker Trapped</h5>
        <p>Full session captured in honeypot. Real assets remain untouched. TTPs documented.</p>
      </div>
      <div className="tl-item after animate-on-scroll">
        <span className="tl-time">T+00:23</span>
        <h5>Auto Response Executed</h5>
        <p>Infected host isolated. Port blocked. Blockchain audit log finalized. Incident report generated.</p>
      </div>
    </div>
  </div>
</section>

{/*  ML MODELS  */}
<section id="models">
  <div className="models-header animate-on-scroll">
    <span className="section-tag">// ML ARCHITECTURE</span>
    <h2 className="section-title">Triple-Layer Detection Engine</h2>
    <p className="section-sub">Three unsupervised models run in parallel, fusing scores for a final consensus-based threat decision.</p>
  </div>
  <div className="models-grid">
    <div className="model-card animate-on-scroll">
      <div className="model-name">IF</div>
      <div className="model-full-name">Isolation Forest</div>
      <p className="model-desc">Rapidly isolates anomalies by building random partitions. Anomalies require fewer splits — ideal for high-speed stream detection.</p>
      <div className="model-bar-label"><span>Detection Speed</span><span>98%</span></div>
      <div className="model-bar"><div className="model-bar-fill" style={{ width: '0%' }} data-width="98%"></div></div>
      <div className="model-bar-label"><span>Low False Positive</span><span>94%</span></div>
      <div className="model-bar"><div className="model-bar-fill" style={{ width: '0%' }} data-width="94%"></div></div>
      <div className="model-score">0.91 <span>confidence</span></div>
    </div>
    <div className="model-card animate-on-scroll">
      <div className="model-name">LOF</div>
      <div className="model-full-name">Local Outlier Factor</div>
      <p className="model-desc">Compares local density of data points. Detects subtle behavioral deviations invisible to global models — perfect for insider threats.</p>
      <div className="model-bar-label"><span>Density Sensitivity</span><span>96%</span></div>
      <div className="model-bar"><div className="model-bar-fill" style={{ width: '0%' }} data-width="96%"></div></div>
      <div className="model-bar-label"><span>Insider Threat Detection</span><span>89%</span></div>
      <div className="model-bar"><div className="model-bar-fill" style={{ width: '0%' }} data-width="89%"></div></div>
      <div className="model-score">0.87 <span>confidence</span></div>
    </div>
    <div className="model-card animate-on-scroll">
      <div className="model-name">OC-SVM</div>
      <div className="model-full-name">One-Class SVM</div>
      <p className="model-desc">Learns a tight boundary around normal behavior. Anything outside triggers an alert — highly effective for zero-day behavioral anomalies.</p>
      <div className="model-bar-label"><span>Boundary Precision</span><span>93%</span></div>
      <div className="model-bar"><div className="model-bar-fill" style={{ width: '0%' }} data-width="93%"></div></div>
      <div className="model-bar-label"><span>Zero-Day Coverage</span><span>91%</span></div>
      <div className="model-bar"><div className="model-bar-fill" style={{ width: '0%' }} data-width="91%"></div></div>
      <div className="model-score">0.89 <span>confidence</span></div>
    </div>
  </div>
</section>

{/*  DEMO TERMINAL  */}
<section id="demo">
  <span className="section-tag">// INTERACTIVE SIMULATION</span>
  <h2 className="demo-title animate-on-scroll">Watch LateralShield in Action</h2>
  <p className="demo-sub animate-on-scroll">Simulate real attack scenarios and see how the AI engine responds in real time.</p>

  <div className="demo-terminal animate-on-scroll">
    <div className="terminal-bar">
      <div className="t-dot red"></div>
      <div className="t-dot yellow"></div>
      <div className="t-dot green"></div>
      <span className="terminal-title">lateralshield — threat-simulation-engine v2.4.1</span>
    </div>
    <div className="terminal-body" id="terminalBody">
      <span className="t-line muted" style={{ animationDelay: '0s', opacity: 1 }}># LateralShield Threat Simulation Engine</span>
      <span className="t-line muted" style={{ animationDelay: '0.2s', opacity: 1 }}># Select a simulation below to begin ↓</span>
      <span className="t-line" style={{ opacity: 1 }}>&nbsp;</span>
      <span className="t-line prompt" style={{ animationDelay: '0.4s', opacity: 1 }}>lateralshield ready — awaiting simulation trigger <span className="blink">█</span></span>
    </div>
  </div>

  <div className="demo-controls animate-on-scroll">
    <button className="demo-btn" onClick={() => window.runSim('lateral')}>▶ Lateral Movement</button>
    <button className="demo-btn" onClick={() => window.runSim('portscan')}>▶ Port Scan Attack</button>
    <button className="demo-btn danger-btn" onClick={() => window.runSim('exfil')}>▶ Data Exfiltration</button>
    <button className="demo-btn" onClick={() => window.runSim('zeroday')}>▶ Zero-Day Attempt</button>
    <button className="demo-btn" onClick={() => window.clearTerm()}>✕ Clear Terminal</button>
  </div>
</section>

{/*  THREAT INTEL  */}
<section id="threat-intel">
  <div className="animate-on-scroll">
    <span className="section-tag">// LIVE THREAT INTELLIGENCE</span>
    <h2 className="section-title">Real-Time Threat Overview</h2>
    <p className="section-sub">Live threat scores and known malicious actor feeds — updated continuously from the detection engine.</p>
  </div>
  <div className="intel-grid">
    <div className="intel-panel animate-on-scroll">
      <div className="intel-panel-title">⚠ KNOWN MALICIOUS IPs — SIMULATED FEED</div>
      <div className="ip-row"><span className="ip-addr">192.168.14.203</span><span className="ip-country">Internal — Subnet C</span><span className="ip-badge critical">CRITICAL</span></div>
      <div className="ip-row"><span className="ip-addr">10.0.44.91</span><span className="ip-country">Internal — VPN</span><span className="ip-badge critical">CRITICAL</span></div>
      <div className="ip-row"><span className="ip-addr">172.16.8.14</span><span className="ip-country">Internal — DMZ</span><span className="ip-badge high">HIGH</span></div>
      <div className="ip-row"><span className="ip-addr">185.220.101.47</span><span className="ip-country">External — TOR Exit</span><span className="ip-badge critical">CRITICAL</span></div>
      <div className="ip-row"><span className="ip-addr">194.165.16.11</span><span className="ip-country">External — RU/EU</span><span className="ip-badge high">HIGH</span></div>
      <div className="ip-row"><span className="ip-addr">45.142.212.100</span><span className="ip-country">External — C2 Server</span><span className="ip-badge critical">CRITICAL</span></div>
      <div className="ip-row"><span className="ip-addr">10.0.12.88</span><span className="ip-country">Internal — HR VLAN</span><span className="ip-badge medium">MEDIUM</span></div>
    </div>
    <div className="intel-panel animate-on-scroll">
      <div className="intel-panel-title">🎯 CURRENT THREAT SCORE</div>
      <div className="gauge-wrap">
        <svg className="gauge-svg" viewBox="0 0 200 120">
          <defs>
            <linearGradient id="gaugeGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" style={{ stopColor: '#00ff88' }}/>
              <stop offset="40%" style={{ stopColor: '#ffe44d' }}/>
              <stop offset="80%" style={{ stopColor: '#ff7700' }}/>
              <stop offset="100%" style={{ stopColor: '#ff2244' }}/>
            </linearGradient>
          </defs>
          <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="rgba(0,200,255,0.1)" strokeWidth="12"/>
          <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="url(#gaugeGrad)" strokeWidth="12"
                strokeDasharray="251" strokeDashoffset="63" strokeLinecap="round"/>
          <line id="gaugeLine" x1="100" y1="100" x2="44" y2="42" stroke="#ffe44d" strokeWidth="2.5" strokeLinecap="round"/>
          <circle cx="100" cy="100" r="6" fill="#ffe44d"/>
          <text x="10" y="118" fill="#4a7a9b" font-size="9" font-family="Share Tech Mono">LOW</text>
          <text x="160" y="118" fill="#4a7a9b" font-size="9" font-family="Share Tech Mono">HIGH</text>
        </svg>
        <div className="gauge-score" id="liveScore">0.73</div>
        <div className="gauge-label">CURRENT THREAT SCORE</div>
        <div className="gauge-detail">
          <div className="gauge-detail-item">
            <span className="gauge-detail-val" id="g-detected">14</span>
            <span className="gauge-detail-key">Detected Today</span>
          </div>
          <div className="gauge-detail-item">
            <span className="gauge-detail-val" id="g-trapped">11</span>
            <span className="gauge-detail-key">Trapped</span>
          </div>
          <div className="gauge-detail-item">
            <span className="gauge-detail-val" id="g-blocked">3</span>
            <span className="gauge-detail-key">Blocked IPs</span>
          </div>
          <div className="gauge-detail-item">
            <span className="gauge-detail-val" id="g-ms">9ms</span>
            <span className="gauge-detail-key">Avg Response</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</section>

{/*  CTA  */}
<section id="cta">
  <span className="cta-pre">// READY TO DEPLOY</span>
  <h2 className="cta-title animate-on-scroll">Your Network Deserves<br /><span className="accent">Active Defense</span></h2>
  <p className="cta-sub animate-on-scroll">Deploy LateralShield in your SOC environment. Full API integration, role-based access, and blockchain audit trails included.</p>
  <div className="cta-btns animate-on-scroll">
    <a href="#" className="btn-primary" onClick={() => window.showDashboardMsg()}>▶ Enter Dashboard</a>
    <a href="#demo" className="btn-secondary">Run Simulation</a>
  </div>
</section>

{/*  FOOTER  */}
<footer>
  <div className="footer-logo">LATERAL<span>SHIELD</span> + TRAPWEAVE</div>
  <div className="footer-copy">© 2025 LATERALSHIELD · INTELLIGENT LATERAL THREAT TRAP · RESEARCH PROTOTYPE</div>
  <div className="footer-links">
    <a href="#">Docs</a>
    <a href="#">API</a>
    <a href="#">GitHub</a>
  </div>
</footer>
    </>
  );
}

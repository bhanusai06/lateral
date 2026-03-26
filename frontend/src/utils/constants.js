export const CHART_COLORS = [
  "rgba(0, 212, 255, 0.8)",
  "rgba(255, 61, 90, 0.8)",
  "rgba(0, 255, 136, 0.8)",
  "rgba(255, 176, 32, 0.8)",
  "rgba(139, 92, 246, 0.8)",
];

export const SHAP_FEATURES = [
  { name: "ct_src_ltm", impact: 0.31, type: "pos", actual: "47" },
  { name: "sttl", impact: 0.28, type: "pos", actual: "254" },
  { name: "dbytes", impact: -0.12, type: "neg", actual: "1042" },
  { name: "synack", impact: 0.18, type: "pos", actual: "0.04s" },
  { name: "tcprtt", impact: -0.05, type: "neg", actual: "0.11s" }
];

export const EVENTS = [
  { time: "10:42:01", type: "CRITICAL", msg: "Lateral movement DESKTOP-04→DB-Server-02", model: "Ensemble" },
  { time: "10:41:15", type: "WARNING", msg: "Honeypot AdminServer_Fake01 hit — TTP capture active", model: "TrapWeave" },
  { time: "10:38:05", type: "INFO", msg: "Model retrained — IF accuracy 96.8% | F1: 93.0%", model: "Pipeline" },
  { time: "10:35:22", type: "EVENT", msg: "TrapWeave deployed DB-Server_Fake02 on predicted path", model: "TrapWeave" }
];

export const TTP_LINES = [
  { time: "10:41:15.002", type: "cmd", text: "whoami /priv" },
  { time: "10:41:15.084", type: "out", text: "Privilege Name                Description                    State\n============================= ============================== ========\nSeChangeNotifyPrivilege       Bypass traverse checking       Enabled" },
  { time: "10:41:18.420", type: "cmd", text: "nltest /domain_trusts" },
  { time: "10:41:18.511", type: "err", text: "Command failed: Access is denied." },
  { time: "10:41:22.100", type: "cmd", text: "powershell.exe -c \"Get-NetComputer\"" }
];

export const FEATURES = [
  { name: "ct_src_ltm", pct: 86 },
  { name: "sttl", pct: 72 },
  { name: "ct_srv_dst", pct: 64 },
  { name: "dbytes", pct: 45 },
  { name: "synack", pct: 38 }
];

export const DEMO_ALERTS_UI = [
  { id: "evt_1", timestamp: "10:42:01", source_ip: "10.0.4.22", dest_ip: "10.0.1.50", fused_score: 0.94, severity: "critical", is_honeypot: false },
  { id: "evt_2", timestamp: "10:41:15", source_ip: "10.0.6.11", dest_ip: "10.0.99.2", fused_score: 0.88, severity: "high", is_honeypot: true },
  { id: "evt_3", timestamp: "10:38:22", source_ip: "10.0.2.14", dest_ip: "10.0.2.200", fused_score: 0.61, severity: "medium", is_honeypot: false }
];

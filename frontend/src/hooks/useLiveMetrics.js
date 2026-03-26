// useLiveMetrics.js - Polls backend API for live metrics
import { useState, useEffect, useCallback } from "react";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:5000/api";
const API_KEY  = import.meta.env.VITE_API_KEY  || "";

// Build fetch headers including optional API key
function apiHeaders() {
  const h = { "Content-Type": "application/json" };
  if (API_KEY) h["X-API-Key"] = API_KEY;
  return h;
}

export function useLiveMetrics(intervalMs = 3000) {
  const [metrics, setMetrics]     = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError]         = useState(null);

  const fetchMetrics = useCallback(async (signal) => {
    try {
      const res = await fetch(`${API_BASE}/metrics`, { signal, headers: apiHeaders() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setMetrics(data);
      setError(null);
    } catch (e) {
      if (e.name === 'AbortError') return;
      setError(e.message);
      // Provide demo data so UI still works
      setMetrics(getDemoMetrics());
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    fetchMetrics(controller.signal);
    const id = setInterval(() => fetchMetrics(controller.signal), intervalMs);
    return () => {
      clearInterval(id);
      controller.abort();
    };
  }, [fetchMetrics, intervalMs]);

  return { data: metrics, isLoading, error };
}

export function useAlerts(limit = 50, intervalMs = 5000) {
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    const controller = new AbortController();
    const fetchAlerts = async () => {
      try {
        const res = await fetch(`${API_BASE}/alerts?limit=${limit}`, { signal: controller.signal });
        if (res.ok) {
          const data = await res.json();
          setAlerts(data.alerts || []);
        }
      } catch (e) {
        if (e.name === 'AbortError') return;
        setAlerts(getDemoAlerts());
      }
    };
    fetchAlerts();
    const id = setInterval(fetchAlerts, intervalMs);
    return () => {
      clearInterval(id);
      controller.abort();
    };
  }, [limit, intervalMs]);

  return alerts;
}

export function useHoneypots(intervalMs = 8000) {
  const [honeypots, setHoneypots] = useState([]);

  useEffect(() => {
    const controller = new AbortController();
    const fetch_ = async () => {
      try {
        const res = await fetch(`${API_BASE}/honeypots`, { signal: controller.signal });
        if (res.ok) {
          const data = await res.json();
          setHoneypots(data.honeypots || []);
        }
      } catch (e) {
        if (e.name === 'AbortError') return;
        setHoneypots(getDemoHoneypots());
      }
    };
    fetch_();
    const id = setInterval(fetch_, intervalMs);
    return () => {
      clearInterval(id);
      controller.abort();
    };
  }, [intervalMs]);

  return honeypots;
}


export function useLiveScoreStream(maxPoints = 60) {
  const [scores, setScores] = useState(() =>
    Array.from({ length: maxPoints }, () => Math.random() * 0.3 + 0.15)
  );

  useEffect(() => {
    let es;
    try {
      es = new EventSource(`${API_BASE}/stream/events`);
      es.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (typeof data.score === "number") {
            setScores(prev => [...prev.slice(1), data.score]);
          }
        } catch { /* ignore parse errors */ }
      };
      es.onerror = () => {
        // SSE connection failed — keep using existing data
        es.close();
      };
    } catch {
      // EventSource not available or CORS blocked
    }
    return () => { if (es) es.close(); };
  }, [maxPoints]);

  return scores;
}

export function useBackendHealth() {
  const [health, setHealth] = useState(null); // null=unknown, live=up, demo=down

  useEffect(() => {
    const check = async () => {
      try {
        const res = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(3000) });
        const data = await res.json();
        setHealth(data.models_loaded === true ? "live" : "demo");
      } catch {
        setHealth("offline");
      }
    };
    check();
    const id = setInterval(check, 10000); // check every 10 seconds
    return () => clearInterval(id);
  }, []);

  return health;
}

export async function analyzeEvent(eventData) {
  try {
    const res = await fetch(`${API_BASE}/analyze`, {
      method: "POST",
      headers: apiHeaders(),
      body: JSON.stringify(eventData),
    });
    return await res.json();
  } catch (e) {
    return { error: e.message };
  }
}

export async function acknowledgeAlert(eventId, action = "investigate") {
  try {
    const res = await fetch(`${API_BASE}/alerts/${eventId}`, {
      method: "PATCH",
      headers: apiHeaders(),
      body: JSON.stringify({ action }),
    });
    return await res.json();
  } catch (e) {
    console.error("Alert action failed", e);
    return null;
  }
}

export function useSSETicker(maxItems = 8) {
  const [messages, setMessages] = useState([]);
  
  useEffect(() => {
    let es;
    try {
      es = new EventSource(`${API_BASE}/stream/events`);
      es.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          let msg = "";
          let cls = "t-norm";
          if (data.type === "anomaly") {
            msg = `${data.severity.toUpperCase()}: Lateral movement ${data.source_ip} \\u2192 ${data.dest_ip} | Score: ${data.score}`;
            cls = data.severity === "critical" ? "t-alert" : "t-warn";
          } else {
            msg = `INFO: Normal traffic ${data.source_ip} \\u2192 ${data.dest_ip}`;
            cls = "t-ok";
          }
          setMessages(prev => [{ id: Date.now() + Math.random(), msg, cls }, ...prev].slice(0, maxItems));
        } catch {}
      };
    } catch {}
    return () => { if (es) es.close(); };
  }, [maxItems]);

  return messages;
}

export function useNetworkTopology() {
  const [topology, setTopology] = useState(null);
  
  useEffect(() => {
    const fetchTopo = async () => {
      try {
        const res = await fetch(`${API_BASE}/network/topology`, { headers: apiHeaders() });
        if (res.ok) setTopology(await res.json());
      } catch {}
    };
    fetchTopo();
    const id = setInterval(fetchTopo, 10000);
    return () => clearInterval(id);
  }, []);
  
  return topology;
}

export function useTTP() {
  const [ttp, setTtp] = useState([]);
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    const fetchTTP = async () => {
      try {
        const res = await fetch(`${API_BASE}/ttp`, { headers: apiHeaders() });
        if (res.ok) {
          const data = await res.json();
          setTtp(data.sessions || []);
        }
      } catch {}
      setLoading(false);
    };
    fetchTTP();
    const id = setInterval(fetchTTP, 15000);
    return () => clearInterval(id);
  }, []);
  
  return { data: ttp, loading };
}

// ── Demo data fallbacks ──────────────────────────────────

function getDemoMetrics() {
  return {
    model_metrics: {
      ensemble: { precision: 0.942, recall: 0.918, f1: 0.930, auc_roc: 0.967, fpr: 0.062 }
    },
    live_stats: {
      total_alerts: 143 + Math.floor(Math.random() * 10),
      critical_alerts: 7,
      today_alerts: 24,
      active_honeypots: 4,
      events_per_second: 2700 + Math.floor(Math.random() * 300),
      models_loaded: false,
    },
    live: { fused_score: 0.7 + Math.random() * 0.25 }
  };
}

function getDemoAlerts() {
  const now = Date.now();
  return [
    { event_id:"a1", timestamp: new Date(now-180000).toISOString(), source_ip:"192.168.1.104", dest_ip:"192.168.1.20", severity:"critical", scores:{fused:0.94}, is_anomaly:true },
    { event_id:"a2", timestamp: new Date(now-360000).toISOString(), source_ip:"192.168.1.107", dest_ip:"192.168.1.40", severity:"high",     scores:{fused:0.81}, is_anomaly:true },
    { event_id:"a3", timestamp: new Date(now-540000).toISOString(), source_ip:"192.168.1.115", dest_ip:"192.168.1.10", severity:"critical", scores:{fused:0.89}, is_anomaly:true },
    { event_id:"a4", timestamp: new Date(now-720000).toISOString(), source_ip:"192.168.1.200", dest_ip:"192.168.1.30", severity:"medium",   scores:{fused:0.63}, is_anomaly:true },
  ];
}

function getDemoHoneypots() {
  return [
    { id:"hp1", name:"AdminServer_Fake01", ip:"192.168.100.45", type:"admin_server",       status:"active", hit_count:12 },
    { id:"hp2", name:"DB-Server_Fake02",   ip:"192.168.100.46", type:"database",           status:"active", hit_count:4  },
    { id:"hp3", name:"FileShare_Fake03",   ip:"192.168.100.47", type:"fileshare",          status:"active", hit_count:1  },
    { id:"hp4", name:"DomainCtrl_Fake04",  ip:"192.168.100.48", type:"domain_controller", status:"active", hit_count:0  },
  ];
}


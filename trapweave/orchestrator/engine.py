"""
TrapWeave Orchestration Engine
Listens for high-score anomaly signals from LateralShield,
predicts the attacker's next hop via graph analysis,
then deploys Docker-based honeypots on the predicted path.
"""
import os
import sys
import json
import time
import uuid
import socket
import threading
import subprocess
import requests
from datetime import datetime
from pathlib import Path
from typing import Optional

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────

TRAPWEAVE_CONFIG = {
    "trigger_threshold": float(os.getenv("TRAPWEAVE_THRESHOLD", "0.85")),
    "api_url": os.getenv("API_URL", "http://localhost:5000/api"),
    "honeypot_network": os.getenv("HONEYPOT_NETWORK", "lateralshield_honeypot_net"),
    "honeypot_subnet": os.getenv("HONEYPOT_SUBNET", "192.168.100"),
    "max_honeypots": int(os.getenv("MAX_HONEYPOTS", "10")),
    "log_file": "/tmp/trapweave.log",
}

# Honeypot templates — each simulates a real enterprise service
HONEYPOT_TEMPLATES = {
    "admin_server": {
        "name_prefix": "AdminServer_Fake",
        "docker_image": "lateralshield/honeypot-smb:latest",
        "ports": [445, 139],
        "description": "Fake Windows Admin Server — SMB/CIFS shares",
        "lure_services": ["smb", "rdp"],
    },
    "database": {
        "name_prefix": "DB-Server_Fake",
        "docker_image": "lateralshield/honeypot-db:latest",
        "ports": [1433, 3306, 5432],
        "description": "Fake SQL Database Server",
        "lure_services": ["mssql", "mysql", "postgres"],
    },
    "domain_controller": {
        "name_prefix": "DomainCtrl_Fake",
        "docker_image": "lateralshield/honeypot-ldap:latest",
        "ports": [389, 636, 88],
        "description": "Fake Active Directory Domain Controller",
        "lure_services": ["ldap", "kerberos"],
    },
    "fileshare": {
        "name_prefix": "FileShare_Fake",
        "docker_image": "lateralshield/honeypot-smb:latest",
        "ports": [445, 2049],
        "description": "Fake File Share Server",
        "lure_services": ["smb", "nfs"],
    },
}


class NetworkGraph:
    """
    Simplified network topology graph.
    In production: backed by Neo4j.
    Here: in-memory graph with attack path prediction.
    """

    def __init__(self):
        self.nodes = {}   # ip -> node_info
        self.edges = {}   # (src_ip, dst_ip) -> edge_info
        self.attack_history = []  # List of observed attack paths

    def add_node(self, ip: str, hostname: str = None, role: str = "workstation"):
        self.nodes[ip] = {
            "ip": ip,
            "hostname": hostname or ip,
            "role": role,
            "risk_score": 0.0,
            "last_seen": datetime.utcnow().isoformat(),
        }

    def add_edge(self, src_ip: str, dst_ip: str, protocol: str, score: float = 0.0):
        key = (src_ip, dst_ip)
        self.edges[key] = {
            "src": src_ip,
            "dst": dst_ip,
            "protocol": protocol,
            "anomaly_score": score,
            "timestamp": datetime.utcnow().isoformat(),
        }
        # Update risk scores
        if src_ip in self.nodes:
            self.nodes[src_ip]["risk_score"] = max(self.nodes[src_ip]["risk_score"], score)
        if dst_ip in self.nodes:
            self.nodes[dst_ip]["risk_score"] = max(self.nodes[dst_ip]["risk_score"], score * 0.8)

    def predict_next_hop(self, attacker_ip: str, current_target: str) -> Optional[str]:
        """
        Predict the attacker's next target based on:
        1. Network adjacency (connected nodes)
        2. High-value target heuristic (servers > workstations)
        3. Lateral movement patterns from history
        """
        # Find all nodes reachable from current_target
        candidates = []
        for (src, dst), edge in self.edges.items():
            if src == current_target and dst != attacker_ip:
                if dst in self.nodes:
                    node = self.nodes[dst]
                    # Score candidates by value
                    value = 0
                    if node.get("role") == "domain_controller":
                        value = 100
                    elif node.get("role") == "database":
                        value = 80
                    elif node.get("role") == "admin_server":
                        value = 70
                    elif node.get("role") == "fileserver":
                        value = 50
                    else:
                        value = 30
                    candidates.append((dst, value))

        if not candidates:
            # Fallback: predict high-value nodes not yet hit
            for ip, node in self.nodes.items():
                if ip != attacker_ip and ip != current_target:
                    if node.get("role") in ["domain_controller", "database", "admin_server"]:
                        return ip

        if candidates:
            candidates.sort(key=lambda x: x[1], reverse=True)
            return candidates[0][0]

        return None

    def load_default_topology(self):
        """Load a default enterprise network topology for demo."""
        hosts = [
            ("192.168.1.1", "GATEWAY", "gateway"),
            ("192.168.1.10", "DC-01", "domain_controller"),
            ("192.168.1.20", "DB-Server-02", "database"),
            ("192.168.1.30", "FileServer-01", "fileshare"),
            ("192.168.1.40", "AdminServer-01", "admin_server"),
            ("192.168.1.100", "DESKTOP-01", "workstation"),
            ("192.168.1.104", "DESKTOP-04", "workstation"),
            ("192.168.1.107", "LAPTOP-07", "workstation"),
            ("192.168.1.147", "ATTACKER", "attacker"),
        ]
        for ip, hostname, role in hosts:
            self.add_node(ip, hostname, role)

        # Default connectivity
        edges = [
            ("192.168.1.104", "192.168.1.20", "SMB"),
            ("192.168.1.104", "192.168.1.40", "RDP"),
            ("192.168.1.104", "192.168.1.10", "LDAP"),
            ("192.168.1.107", "192.168.1.30", "SMB"),
        ]
        for src, dst, proto in edges:
            self.add_edge(src, dst, proto)


class HoneypotDeployer:
    """
    Deploys Docker-based honeypot containers on the network.
    """

    def __init__(self):
        self.deployed = {}   # container_id -> honeypot info
        self._ip_counter = 44  # Start from .44 for honeypot IPs

    def _next_honeypot_ip(self) -> str:
        self._ip_counter += 1
        return f"{TRAPWEAVE_CONFIG['honeypot_subnet']}.{self._ip_counter}"

    def deploy(self, hp_type: str, triggered_by_score: float,
               target_ip: str = None) -> Optional[dict]:
        """Deploy a honeypot container."""
        if len(self.deployed) >= TRAPWEAVE_CONFIG["max_honeypots"]:
            log_event("WARNING", f"Max honeypots ({TRAPWEAVE_CONFIG['max_honeypots']}) reached.")
            return None

        template = HONEYPOT_TEMPLATES.get(hp_type, HONEYPOT_TEMPLATES["admin_server"])
        hp_id = str(uuid.uuid4())[:8]
        hp_ip = self._next_honeypot_ip()
        container_name = f"{template['name_prefix']}{self._ip_counter:02d}"
        port = template["ports"][0]

        # Try Docker deployment
        container_id = self._docker_run(container_name, template, hp_ip, port)

        honeypot_info = {
            "id": hp_id,
            "container_id": container_id,
            "container_name": container_name,
            "type": hp_type,
            "ip": hp_ip,
            "port": port,
            "ports": template["ports"],
            "description": template["description"],
            "triggered_by_score": triggered_by_score,
            "target_ip": target_ip,
            "deployed_at": datetime.utcnow().isoformat(),
            "status": "active",
            "hit_count": 0,
            "ttp_captures": [],
        }

        self.deployed[hp_id] = honeypot_info

        # Register with backend API
        try:
            requests.post(f"{TRAPWEAVE_CONFIG['api_url']}/honeypots",
                          json=honeypot_info, timeout=3)
        except Exception:
            pass

        log_event("INFO", f"Honeypot deployed: {container_name} @ {hp_ip}:{port}")
        return honeypot_info

    def _docker_run(self, name: str, template: dict, ip: str, port: int) -> Optional[str]:
        """Start a Docker container for the honeypot."""
        try:
            port_mappings = " ".join(f"-p {p}:{p}" for p in template["ports"])
            cmd = (
                f"docker run -d --name {name} "
                f"--network {TRAPWEAVE_CONFIG['honeypot_network']} "
                f"{port_mappings} "
                f"--label trapweave=true "
                f"--label hp_ip={ip} "
                f"{template['docker_image']}"
            )
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return result.stdout.strip()[:12]
            else:
                log_event("WARN", f"Docker failed: {result.stderr[:100]} — using Python fallback")
                return self._python_socket_fallback(name, template["ports"][0])
        except Exception as e:
            log_event("WARN", f"Docker unavailable: {e} — using Python socket fallback")
            return self._python_socket_fallback(name, template["ports"][0])

    def _python_socket_fallback(self, name: str, port: int) -> Optional[str]:
        """Fallback: Python socket-based fake server."""
        thread_id = f"pyserver_{name}"

        def fake_server():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    # Bind to localhost for safety
                    s.bind(("127.0.0.1", port))
                    s.listen(5)
                    s.settimeout(300)  # 5 minute timeout
                    log_event("INFO", f"Python fake server listening on 127.0.0.1:{port} ({name})")
                    while True:
                        try:
                            conn, addr = s.accept()
                            self._handle_connection(conn, addr, name)
                        except socket.timeout:
                            break
                        except Exception:
                            break
            except OSError as e:
                log_event("WARN", f"Could not bind port {port}: {e}")

        t = threading.Thread(target=fake_server, daemon=True, name=thread_id)
        t.start()
        return thread_id

    def _handle_connection(self, conn, addr, honeypot_name: str):
        """Handle incoming connection to honeypot — record TTP."""
        try:
            conn.settimeout(10)
            attacker_ip = addr[0]
            log_event("ALERT", f"Honeypot {honeypot_name} HIT by {attacker_ip}!")

            # Send fake banner
            banner = b"Windows Server 2019 Standard [Version 10.0.17763.2803]\r\n"
            conn.sendall(banner)

            # Receive and log commands
            ttp_session = {
                "attacker_ip": attacker_ip,
                "timestamp": datetime.utcnow().isoformat(),
                "commands": [],
            }

            while True:
                try:
                    data = conn.recv(1024)
                    if not data:
                        break
                    command = data.decode("utf-8", errors="replace").strip()
                    if command:
                        ttp_session["commands"].append({
                            "command": command,
                            "timestamp": datetime.utcnow().isoformat(),
                        })
                        log_event("TTP", f"[{honeypot_name}] Attacker cmd: {command[:100]}")
                        # Send fake response
                        conn.sendall(b"Access Denied.\r\n")
                except Exception:
                    break

            # Store TTP session
            self._store_ttp(honeypot_name, ttp_session)
        except Exception as e:
            log_event("WARN", f"Connection handler error: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _store_ttp(self, honeypot_name: str, ttp_session: dict):
        """Save TTP session to file and report to API."""
        log_dir = Path("/tmp/trapweave_ttp")
        log_dir.mkdir(exist_ok=True)
        fname = log_dir / f"{honeypot_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        with open(fname, "w") as f:
            json.dump(ttp_session, f, indent=2)

        # Report to API
        for hp_id, hp in self.deployed.items():
            if hp["container_name"] == honeypot_name:
                try:
                    requests.post(
                        f"{TRAPWEAVE_CONFIG['api_url']}/honeypots/{hp_id}/ttp",
                        json=ttp_session, timeout=3
                    )
                    hp["hit_count"] += 1
                    hp["ttp_captures"].append(ttp_session)
                except Exception:
                    pass
                break


class TrapWeaveEngine:
    """
    Main TrapWeave orchestration engine.
    Polls the LateralShield API for high-score events
    and triggers honeypot deployment automatically.
    """

    def __init__(self):
        self.graph = NetworkGraph()
        self.deployer = HoneypotDeployer()
        self.running = False
        self.processed_events = set()
        self.graph.load_default_topology()

    def handle_alert(self, alert: dict):
        """Process a high-score alert and decide whether to deploy a honeypot."""
        event_id = alert.get("event_id", "")
        if event_id in self.processed_events:
            return
        self.processed_events.add(event_id)

        fused_score = alert.get("scores", {}).get("fused", 0)
        if fused_score < TRAPWEAVE_CONFIG["trigger_threshold"]:
            return

        src_ip = alert.get("source_ip", "")
        dst_ip = alert.get("dest_ip", "")

        log_event("TRIGGER", f"Score {fused_score:.3f} ≥ threshold {TRAPWEAVE_CONFIG['trigger_threshold']} "
                              f"— TrapWeave activated for {src_ip} → {dst_ip}")

        # Update graph with this attack edge
        self.graph.add_edge(src_ip, dst_ip, "detected", fused_score)

        # Predict next hop
        predicted_next = self.graph.predict_next_hop(src_ip, dst_ip)
        log_event("PREDICT", f"Predicted next target: {predicted_next or 'unknown'}")

        # Select honeypot type based on predicted target role
        hp_type = "admin_server"
        if predicted_next and predicted_next in self.graph.nodes:
            role = self.graph.nodes[predicted_next].get("role", "workstation")
            type_map = {
                "domain_controller": "domain_controller",
                "database": "database",
                "fileshare": "fileshare",
                "admin_server": "admin_server",
            }
            hp_type = type_map.get(role, "admin_server")

        # Deploy honeypot
        honeypot = self.deployer.deploy(
            hp_type=hp_type,
            triggered_by_score=fused_score,
            target_ip=predicted_next
        )

        if honeypot:
            log_event("DEPLOY", f"Honeypot {honeypot['container_name']} deployed @ "
                                 f"{honeypot['ip']}:{honeypot['port']} on predicted path {predicted_next}")

    def poll_api(self):
        """Continuously poll the backend API for new critical alerts."""
        log_event("INFO", "TrapWeave polling started.")
        while self.running:
            try:
                resp = requests.get(
                    f"{TRAPWEAVE_CONFIG['api_url']}/alerts",
                    params={"severity": "critical", "limit": 20},
                    timeout=5
                )
                if resp.ok:
                    for alert in resp.json().get("alerts", []):
                        self.handle_alert(alert)
            except Exception as e:
                log_event("WARN", f"API poll error: {e}")
            time.sleep(5)

    def start(self):
        """Start the TrapWeave engine."""
        self.running = True
        log_event("INFO", "TrapWeave Engine starting...")
        poll_thread = threading.Thread(target=self.poll_api, daemon=True, name="trapweave_poller")
        poll_thread.start()
        log_event("INFO", f"TrapWeave active. Trigger threshold: {TRAPWEAVE_CONFIG['trigger_threshold']}")

        # Keep main thread alive
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self.running = False
        log_event("INFO", "TrapWeave Engine stopped.")


# ──────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────

def log_event(level: str, message: str):
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [{level:8s}] {message}"
    print(line)
    try:
        with open(TRAPWEAVE_CONFIG["log_file"], "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


if __name__ == "__main__":
    engine = TrapWeaveEngine()
    engine.start()

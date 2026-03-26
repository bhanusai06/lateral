"""
TrapWeave Honeypot Fake Server
Simulates realistic enterprise services to capture attacker TTPs.
Implements fake SMB, HTTP admin panel, and database login.
"""
import socket
import threading
import json
import os
import time
import sys
from datetime import datetime
from pathlib import Path

HP_TYPE = os.getenv("HP_TYPE", "admin_server")
HP_PORT = int(os.getenv("HP_PORT", "445"))
HP_NAME = os.getenv("HP_NAME", "Honeypot")
TTP_LOG = os.getenv("TTP_LOG", "/tmp/ttp_log.json")
API_URL = os.getenv("API_URL", "http://backend:5000/api")
HP_ID = os.getenv("HP_ID", "hp_default")

# Fake credentials to appear realistic
FAKE_CREDENTIALS = [
    ("Administrator", "P@ssw0rd123"),
    ("admin", "Admin@2024"),
    ("SYSTEM", ""),
    ("svcaccount", "Service#Pass!"),
]

# Banner templates for different services
BANNERS = {
    "smb": b"\x00\x00\x00\x85\xff\x53\x4d\x42",   # SMB negotiation header
    "http_admin": b"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Admin Panel</h1></body></html>",
    "ftp": b"220 Microsoft FTP Service\r\n",
    "ssh": b"SSH-2.0-OpenSSH_for_Windows_8.1\r\n",
    "mssql": b"\x04\x01\x00\x25\x00\x00\x01\x00",   # Pre-login response
    "generic": b"Welcome to Windows Server 2019\r\n> ",
}

TTP_SESSIONS = []


def log(level: str, msg: str):
    ts = datetime.utcnow().strftime("%H:%M:%S")
    print(f"[{ts}][{HP_NAME}][{level}] {msg}", flush=True)


def save_ttp(session: dict):
    TTP_SESSIONS.append(session)
    try:
        with open(TTP_LOG, "w") as f:
            json.dump(TTP_SESSIONS, f, indent=2)
    except Exception:
        pass

    # Report to API
    try:
        import urllib.request, urllib.error
        data = json.dumps(session).encode()
        req = urllib.request.Request(
            f"{API_URL}/honeypots/{HP_ID}/ttp",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        urllib.request.urlopen(req, timeout=3)
    except Exception:
        pass


def handle_client(conn: socket.socket, addr, service_type: str):
    """Handle a connection to the honeypot."""
    attacker_ip = addr[0]
    attacker_port = addr[1]
    log("ALERT", f"CONNECTION from {attacker_ip}:{attacker_port}")

    session = {
        "attacker_ip": attacker_ip,
        "attacker_port": attacker_port,
        "honeypot_type": service_type,
        "honeypot_name": HP_NAME,
        "start_time": datetime.utcnow().isoformat(),
        "commands": [],
        "credentials_tried": [],
        "tools_detected": [],
    }

    try:
        conn.settimeout(30)

        # Send service-specific banner
        banner = BANNERS.get(service_type, BANNERS["generic"])
        conn.sendall(banner)

        while True:
            try:
                data = conn.recv(4096)
                if not data:
                    break

                decoded = data.decode("utf-8", errors="replace").strip()
                if not decoded:
                    continue

                log("TTP", f"CMD: {decoded[:200]}")
                session["commands"].append({
                    "data": decoded[:500],
                    "timestamp": datetime.utcnow().isoformat(),
                })

                # Detect common attacker tools
                tools_signatures = {
                    "mimikatz": "mimikatz",
                    "psexec": "psexec",
                    "wmiexec": "wmiexec",
                    "cobalt_strike": "beacon",
                    "metasploit": "meterpreter",
                    "bloodhound": "bloodhound",
                    "nmap": "nmap",
                    "net_recon": "net view",
                    "whoami": "whoami",
                    "ipconfig": "ipconfig",
                }
                for tool, sig in tools_signatures.items():
                    if sig.lower() in decoded.lower():
                        if tool not in session["tools_detected"]:
                            session["tools_detected"].append(tool)
                            log("TOOL", f"Detected attacker tool: {tool}")

                # Detect credential attempts
                for user, pw in FAKE_CREDENTIALS:
                    if user.lower() in decoded.lower():
                        session["credentials_tried"].append({
                            "username": user,
                            "timestamp": datetime.utcnow().isoformat()
                        })

                # Send appropriate fake response
                response = _get_fake_response(decoded, service_type)
                conn.sendall(response)

            except socket.timeout:
                break
            except Exception as e:
                log("WARN", f"Read error: {e}")
                break

    except Exception as e:
        log("ERR", f"Handler error: {e}")
    finally:
        session["end_time"] = datetime.utcnow().isoformat()
        session["duration_seconds"] = (
            datetime.fromisoformat(session["end_time"]) -
            datetime.fromisoformat(session["start_time"])
        ).total_seconds()
        save_ttp(session)
        log("INFO", f"Session closed. {len(session['commands'])} commands captured.")
        try:
            conn.close()
        except Exception:
            pass


def _get_fake_response(command: str, service_type: str) -> bytes:
    """Generate realistic but fake responses to attacker commands."""
    cmd_lower = command.lower()

    if "whoami" in cmd_lower:
        return b"CORP\\SVCACCOUNT-02\r\n> "
    elif "ipconfig" in cmd_lower:
        return (b"Windows IP Configuration\r\n"
                b"Ethernet adapter Local Area Connection:\r\n"
                b"   IPv4 Address. . . : 192.168.100.45\r\n"
                b"   Subnet Mask . . . : 255.255.255.0\r\n"
                b"   Default Gateway . : 192.168.1.1\r\n> ")
    elif "net user" in cmd_lower:
        return (b"User accounts for \\\\ADMINSERVER\r\n"
                b"Administrator   Guest   svcaccount\r\n"
                b"The command completed successfully.\r\n> ")
    elif "net view" in cmd_lower:
        return (b"Server Name            Remark\r\n"
                b"\\\\ADMINSERVER-FAKE     Admin Server (DECOY)\r\n"
                b"\\\\FILESERVER-FAKE      File Server (DECOY)\r\n"
                b"The command completed successfully.\r\n> ")
    elif "mimikatz" in cmd_lower or "sekurlsa" in cmd_lower:
        return (b"\r\n  .#####.   mimikatz 2.2.0 (x64)\r\n"
                b"  ## ^ ##  \"A La Vie, A L'Amour\"\r\n"
                b" ## / \\ ##  /*** Benjamin DELPY\r\n"
                b" ## \\ / ##  > https://blog.gentilkiwi.com\r\n"
                b" '## v ##'  Vincent LE TOUX\r\n"
                b"  '#####'  > http://pingcastle.com\r\n"
                b"\r\nERROR kuhl_m_sekurlsa_acquireLSA ; Logon failed\r\n"
                b"mimikatz # ")
    elif "dir" in cmd_lower or "ls" in cmd_lower:
        return (b" Directory of C:\\Users\\Administrator\r\n\r\n"
                b" 03/22/2026  09:15 AM    <DIR>          .\r\n"
                b" 03/22/2026  09:15 AM    <DIR>          ..\r\n"
                b" 03/22/2026  09:15 AM    <DIR>          Desktop\r\n"
                b" 03/22/2026  09:15 AM    <DIR>          Documents\r\n"
                b"               0 File(s)              0 bytes\r\n> ")
    else:
        return b"Access Denied.\r\n> "


def start_listener(port: int, service_type: str):
    """Start a TCP listener for the honeypot."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("0.0.0.0", port))
            server.listen(10)
            log("INFO", f"Listening on 0.0.0.0:{port} ({service_type})")

            while True:
                try:
                    conn, addr = server.accept()
                    t = threading.Thread(
                        target=handle_client,
                        args=(conn, addr, service_type),
                        daemon=True
                    )
                    t.start()
                except Exception as e:
                    log("ERR", f"Accept error: {e}")
    except OSError as e:
        log("FATAL", f"Cannot bind port {port}: {e}")


def main():
    log("INFO", f"TrapWeave Honeypot starting: {HP_NAME} ({HP_TYPE}) on port {HP_PORT}")

    # Start primary listener
    listener_thread = threading.Thread(
        target=start_listener,
        args=(HP_PORT, HP_TYPE),
        daemon=True
    )
    listener_thread.start()

    # Keep alive
    try:
        while True:
            time.sleep(60)
            log("STATUS", f"Active | Sessions: {len(TTP_SESSIONS)} | Port: {HP_PORT}")
    except KeyboardInterrupt:
        log("INFO", "Honeypot shutting down.")


if __name__ == "__main__":
    main()

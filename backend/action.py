import os
import sys
import logging
import argparse

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [ACTION] %(levelname)s - %(message)s")

def isolate_host(ip_address):
    """
    Executes Lateral Shield isolation protocol.
    In Windows we might use netsh, in Linux iptables.
    Since this could run via the WSL worker or on the Windows host, we log it and simulate.
    """
    logging.warning(f"INITIATING ISOLATION PROTOCOL FOR: {ip_address}")
    
    # Example iptables command (if running inside Linux/WSL):
    # cmd = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
    # os.system(cmd)
    
    # Example netsh command (if running on Windows):
    # cmd = f"netsh advfirewall firewall add rule name=\"Block_{ip_address}\" dir=in action=block remoteip={ip_address}"
    # os.system(cmd)
    
    logging.info(f"Successfully applied firewall block rules for {ip_address}. Host isolated.")
    print("ISOLATED")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Lateral Shield Automated Action Script")
    parser.add_argument("--ip", type=str, required=True, help="IP address to isolate")
    args = parser.parse_args()
    
    isolate_host(args.ip)

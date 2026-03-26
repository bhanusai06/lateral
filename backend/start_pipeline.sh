#!/bin/bash
# start_pipeline.sh - Starts the real-time Lateral Shield Pipeline

set -e

# Ensure we are running as root in WSL for Zeek and Network configs
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root (e.g., sudo ./start_pipeline.sh)"
  exit 1
fi

echo "Starting Redis server..."
service redis-server start || redis-server --daemonize yes

echo "Installing Python dependencies for worker scripts..."
pip3 install redis requests --break-system-packages

echo "Ensuring Zeek outputs JSON logs..."
ZEEK_LOCAL="/opt/zeek/share/zeek/site/local.zeek"
if [ -f "$ZEEK_LOCAL" ]; then
    if ! grep -q "tuning/json-logs" "$ZEEK_LOCAL"; then
        echo "@load tuning/json-logs" >> "$ZEEK_LOCAL"
        echo "Added JSON log tuning to $ZEEK_LOCAL"
    fi
else
    echo "Warning: Zeek local.zeek configuration not found. JSON logs might not be enabled."
fi

echo "Starting Zeek on eth0 interface..."
# The zeekctl config needs to know about the interface. If zeekctl isn't fully configured, 
# we can run Zeek manually on the interface safely.
# Find interface (defaults to eth0 in WSL, but let's check)
IFACE=$(ip route | grep default | sed -e 's/^.*dev.//' -e 's/.proto.*//' | awk '{print $1}')
echo "Monitoring interface: $IFACE"

# We will start Zeek in the background in a specific log directory
mkdir -p /opt/zeek/logs/current
cd /opt/zeek/logs/current

# Run Zeek directly reading from the interface
echo "Launching Zeek..."
nohup /opt/zeek/bin/zeek -i $IFACE local &
ZEEK_PID=$!

cd /mnt/c/Users/BHANU\ SAI/Downloads/lateralshield_visionx2026\ \(2\)/lateralshield/backend

echo "Starting Zeek-to-Redis Forwarder..."
nohup python3 zeek_to_redis.py > forwarder.log 2>&1 &
FWD_PID=$!

echo "Starting Python Preprocessing Worker (Bridge to Flask API)..."
nohup python3 worker.py > worker.log 2>&1 &
WORKER_PID=$!

echo ""
echo "================================================="
echo "Lateral Shield Real-Time Pipeline is ONLINE."
echo "Zeek PID: $ZEEK_PID"
echo "Forwarder PID: $FWD_PID"
echo "Worker PID: $WORKER_PID"
echo "Redis: Running on port 6379"
echo "Logs are being collected in the backend directory."
echo "Keep this window open or press Ctrl+C to terminate."
echo "================================================="

# Trap Ctrl+C to clean down background jobs
trap "echo 'Terminating pipeline...'; kill $ZEEK_PID $FWD_PID $WORKER_PID; exit" SIGINT SIGTERM

wait

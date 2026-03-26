import redis
import json
import time
import requests
import threading
import sys
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Config
REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_QUEUE = 'zeek_events'
API_URL = 'http://host.docker.internal:5000/api/analyze' # Assuming Flask runs on Windows side

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)

FEATURES = ["dur","proto","state","sbytes","dbytes","sttl","dttl","sloss","dloss",
            "sload","dload","spkts","dpkts","sjit","djit","tcprtt","synack","ackdat",
            "ct_srv_src","ct_srv_dst","ct_dst_ltm","ct_src_ltm","ct_src_dport_ltm",
            "ct_dst_sport_ltm","ct_dst_src_ltm","is_sm_ips_ports"]

def process_event(event_str):
    try:
        raw = json.loads(event_str)
        
        # In a real Zeek deployment, map Zeek conn.log fields to LateralShield features here.
        # This mapping is illustrative, depending heavily on the Zeek JSON output format.
        payload = {
            "dur": float(raw.get("duration", 0)),
            "proto": 1 if raw.get("proto") == "tcp" else 0, # simplified
            "state": 1, # simplified
            "sbytes": int(raw.get("orig_bytes", 0)),
            "dbytes": int(raw.get("resp_bytes", 0)),
            # Filling remaining features with zeros for proto/demo purposes if absent from Zeek
        }
        
        for f in FEATURES:
            if f not in payload:
                payload[f] = 0.0

        payload["srcip"] = raw.get("id.orig_h", "unknown")
        payload["dstip"] = raw.get("id.resp_h", "unknown")

        res = requests.post(API_URL, json=payload, timeout=2)
        if res.status_code in [200, 201]:
            data = res.json()
            if data.get("is_anomaly"):
                logging.warning(f"ANOMALY DETECTED: {payload['srcip']} -> {payload['dstip']} (Score: {data.get('scores', {}).get('fused')})")
        else:
            logging.error(f"Backend returned {res.status_code}")

    except Exception as e:
        logging.error(f"Error processing event: {e}")

def run_worker():
    logging.info(f"Worker started. Listening on Redis queue '{REDIS_QUEUE}'...")
    while True:
        try:
            # Blocking pop from Redis list
            _, event = r.blpop(REDIS_QUEUE, timeout=0)
            process_event(event)
        except Exception as e:
            logging.error(f"Redis connection error: {e}")
            time.sleep(5)

if __name__ == "__main__":
    try:
        r.ping()
        logging.info("Connected to Redis successfully.")
    except Exception as e:
        logging.error(f"Could not connect to Redis: {e}")
        sys.exit(1)
        
    run_worker()

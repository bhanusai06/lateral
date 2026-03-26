import json
import redis
import time
import subprocess
import os
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [ZEEK-TO-REDIS] %(levelname)s - %(message)s")

REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_QUEUE = 'zeek_events'
CONN_LOG_PATH = '/opt/zeek/logs/current/conn.log'

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)

def tail_f(file_path):
    while not os.path.exists(file_path):
        logging.warning(f"Waiting for {file_path} to be created...")
        time.sleep(2)
        
    logging.info(f"Tailing {file_path}...")
    p = subprocess.Popen(['tail', '-F', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    while True:
        line = p.stdout.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line.decode('utf-8').strip()

def run_forwarder():
    try:
        r.ping()
        logging.info("Connected to Redis successfully.")
    except Exception as e:
        logging.error(f"Could not connect to Redis: {e}")
        return

    for line in tail_f(CONN_LOG_PATH):
        if not line or line.startswith('#'):
            continue # Skip comments/headers if not in JSON mode
            
        try:
            # We assume Zeek is configured to output JSON logs (@load tuning/json-logs)
            event = json.loads(line)
            # Push the raw JSON event to the Redis list
            r.rpush(REDIS_QUEUE, json.dumps(event))
            
        except json.JSONDecodeError:
            # If it's TSV format, we should parse it manually or log error
            logging.error(f"Log not in JSON format. Ensure Zeek uses purely JSON logs: {line}")
        except Exception as e:
            logging.error(f"Error forwarding event: {e}")

if __name__ == "__main__":
    run_forwarder()

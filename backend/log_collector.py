import socket
import logging
import time
import os
import json
from datetime import datetime

# Configuration
UDP_IP = "0.0.0.0"
UDP_PORT = 5140
LOG_FILE = "collected_logs.json"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def parse_log(data_str, addr):
    """
    Simulated parsing of Syslog message.
    Format depends on the sender, but usually:
    <PRI>Timestamp Hostname AppName: Message
    Found in our flask app:
    [Priority] 2024-12-10 12:00:00,000 - VulnerableApp - LEVEL - Message
    """
    # Simple JSON structure for our internal usage
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "source_ip": addr[0],
        "raw_message": data_str
    }
    
    # Simple heuristic to extract simple message
    try:
        # Removing Syslog PRI/Header if present (Flask SysLogHandler might just send the formatted string)
        # We will refine this as we see the actual output
        parts = data_str.split(" - ")
        if len(parts) >= 4:
             log_entry["app"] = parts[1].strip()
             log_entry["level"] = parts[2].strip()
             log_entry["message"] = parts[3].strip()
    except Exception as e:
        log_entry["parse_error"] = str(e)
        
    return log_entry

def start_collector():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))

    logging.info(f"Log Collector started on {UDP_IP}:{UDP_PORT}")

    while True:
        data, addr = sock.recvfrom(4096)  # buffer size is 1024 bytes
        try:
            data_str = data.decode("utf-8").strip()
            log_entry = parse_log(data_str, addr)
            
            # Save to file (simulating database/storage)
            with open(LOG_FILE, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
            
            # In real system, this would push to a queue for the ML model
            print(f"Received Log: {log_entry}")
            
        except Exception as e:
            logging.error(f"Error processing log: {e}")

if __name__ == "__main__":
    start_collector()

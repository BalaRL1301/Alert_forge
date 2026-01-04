from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import asyncio
import json
import logging
import os
from datetime import datetime
from detection_engine import HybridEngine
from settings_manager import SettingsManager
from email_service import EmailService

# Setup
app = FastAPI(title="AlertForge API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AlertForgeAPI")

# Engine
engine = HybridEngine()
settings_manager = SettingsManager()
email_service = EmailService(settings_manager)

# Data Storage (In-memory for demo)
stats = {
    "total_logs": 0,
    "anomalies_detected": 0,
    "threats_blocked": 0,
    "last_update": datetime.now().isoformat()
}
recent_alerts = []
recent_logs = []

LOG_FILE = "collected_logs.json"

class LogMessage(BaseModel):
    timestamp: str
    source_ip: str
    message: str
    app: str = "Unknown"

@app.get("/")
def read_root():
    return {"status": "AlertForge Backend Running"}

@app.get("/stats")
def get_stats():
    return stats

@app.get("/alerts")
def get_alerts():
    return recent_alerts

@app.get("/rules")
def get_rules():
    """Returns the content of the YARA rules file."""
    try:
        with open("rules.yar", "r") as f:
            return {"content": f.read()}
    except FileNotFoundError:
        return {"content": "rules.yar not found."}

@app.get("/logs")
def get_logs(limit: int = 50):
    return recent_logs[:limit]

@app.get("/settings")
def get_settings():
    return settings_manager.get_all()

@app.post("/settings")
def update_settings(new_settings: dict):
    return settings_manager.update(new_settings)

def process_log(log_data):
    """
    Process a single log entry through the engine.
    Update stats and alerts.
    """
    global stats
    stats["total_logs"] += 1
    stats["last_update"] = datetime.now().isoformat()
    
    # Analyze
    result = engine.analyze(log_data)
    
    if result["is_threat"]:
        stats["anomalies_detected"] += 1
        
        alert = {
            "id": stats["anomalies_detected"],
            "timestamp": datetime.now().isoformat(),
            "source_ip": log_data.get("source_ip"),
            "type": result["type"],
            "classification": result["classification"],
            "confidence": result["confidence"],
            "details": result["details"]
        }
        recent_alerts.insert(0, alert)
        
        # Automated Response (Dynamic)
        auto_block = settings_manager.get("auto_block", True)
        block_threshold = settings_manager.get("block_threshold", 0.8)

        if auto_block and result["confidence"] > block_threshold:
            logger.warning(f"BLOCKING IP: {log_data.get('source_ip')}")
            stats["threats_blocked"] += 1
            # In a real app, we would call: os.system(f"iptables -A INPUT -s {ip} -j DROP")

        # Instant Email Alerts
        email_alerts = settings_manager.get("email_alerts", False)
        if email_alerts and result["is_threat"]:
             email_service.send_alert(alert)
            
    # Add to logs list
    log_display = log_data.copy()
    log_display["analysis"] = result
    recent_logs.insert(0, log_display)
    if len(recent_logs) > 100:
        recent_logs.pop()

# Background Task to read from the collected_logs.json file continuously
# This simulates the pipeline reading from the Collector
async def log_reader_task():
    logger.info("Starting Log Reader Task")
    # Emulate tail -f
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f: f.write("")
        
    f = open(LOG_FILE, "r")
    # f.seek(0, os.SEEK_END) # REMOVED: Read from beginning to load history
    
    while True:
        line = f.readline()
        if not line:
            await asyncio.sleep(0.5)
            continue
            
        try:
            log_data = json.loads(line)
            process_log(log_data)
        except Exception as e:
            logger.error(f"Error parsing log line: {e}")

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(log_reader_task())

@app.post("/simulate_log")
async def simulate_log(log: LogMessage):
    """Endpoint for manually pushing logs (for testing)"""
    data = log.dict()
    process_log(data)
    return {"status": "processed", "data": data}

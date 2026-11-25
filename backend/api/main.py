import os
import json
import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from ml_engine.nlp_analyzer import NLPAnalyzer
from ml_engine.anomaly_detector import AnomalyDetector
from detection.yara_scanner import YaraScanner
from core.threat_intel import ThreatIntel

app = FastAPI(title="ClipGuard Zero-Trust DLP API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize engines
config_path = os.getenv("CONFIG_PATH", "../config/detection_rules.yaml")
yara_path = os.getenv("YARA_RULES_PATH", "../rules/advanced_signatures.yar")

nlp_analyzer = NLPAnalyzer(config_path)
anomaly_detector = AnomalyDetector(config_path)
yara_scanner = YaraScanner(yara_path)
threat_intel = ThreatIntel()

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

manager = ConnectionManager()

class ClipboardEvent(BaseModel):
    process_name: str
    process_id: int
    text: str
    timestamp: float

@app.post("/api/v1/events")
async def receive_event(event: ClipboardEvent):
    """Receives a clipboard event from the endpoint agent, analyzes it, and broadcasts it."""
    
    # 1. NLP & Heuristic Analysis
    nlp_results = nlp_analyzer.analyze(event.text)
    
    # 2. Behavioral Anomaly Detection
    behavior_results = anomaly_detector.record_and_evaluate(
        event.process_name, 
        len(event.text), 
        nlp_results['entropy']
    )
    
    # 3. YARA Malware/APT Scan
    yara_results = yara_scanner.scan(event.text)
    
    # 4. Threat Intelligence Enrichment
    intel_results = threat_intel.check_indicators(event.text)
    
    # Aggregate Risk
    overall_risk = nlp_results['risk_score']
    if behavior_results['is_anomaly']:
        overall_risk += 30
    if yara_results['is_malicious']:
        overall_risk += yara_results['highest_weight'] * 10
    if intel_results:
        overall_risk += 50
        
    overall_risk = min(overall_risk, 100) # Cap at 100
    
    # Create Analysis Report
    report = {
        "timestamp": event.timestamp,
        "process_name": event.process_name,
        "process_id": event.process_id,
        "overall_risk": overall_risk,
        "redacted_text": nlp_results['redacted_text'],
        "findings": {
            "nlp_regex": nlp_results['findings'],
            "yara": yara_results['matches'],
            "threat_intel": intel_results,
            "behavior": behavior_results
        }
    }
    
    # Broadcast to dashboard
    await manager.broadcast(report)
    
    return {"status": "success", "risk": overall_risk}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

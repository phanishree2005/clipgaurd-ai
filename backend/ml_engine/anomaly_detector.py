import yaml
import time
import pandas as pd
from sklearn.ensemble import IsolationForest
from collections import defaultdict
import numpy as np

class AnomalyDetector:
    def __init__(self, config_path: str):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
            
        self.behavior_config = self.config.get('behavior', {})
        self.window_seconds = self.behavior_config.get('polling_window_seconds', 60)
        self.contamination = self.behavior_config.get('isolation_forest_contamination', 0.05)
        
        # In-memory store for training data (process_name: [(timestamp, length, entropy)])
        self.process_history = defaultdict(list)
        
        # Dictionary of IsolationForest models per process
        self.models = {}

    def record_and_evaluate(self, process_name: str, length: int, entropy: float) -> dict:
        """Records an event and evaluates if it's anomalous."""
        current_time = time.time()
        
        # Clean up old events outside the window
        self._cleanup_history(current_time)
        
        # Record new event
        self.process_history[process_name].append((current_time, length, entropy))
        
        # If we don't have enough data to train a model, fallback to basic heuristic
        recent_events = self.process_history[process_name]
        if len(recent_events) < 10:
             return {
                 "is_anomaly": len(recent_events) > self.behavior_config.get('max_accesses_per_window', 20),
                 "reason": "High frequency (Heuristic)",
                 "confidence": 0.5
             }
             
        # Prepare training data (frequency within last 10s, avg length, avg entropy)
        # For simplicity in this demo, we'll train on the historical individual events
        X = []
        for ts, l, e in recent_events:
            X.append([l, e])
            
        df = pd.DataFrame(X, columns=['length', 'entropy'])
        
        # Train or update model
        if process_name not in self.models:
            self.models[process_name] = IsolationForest(contamination=self.contamination, random_state=42)
            
        model = self.models[process_name]
        # Fit model on recent history
        model.fit(df)
        
        # Predict the current event
        prediction = model.predict([[length, entropy]])
        
        is_anomaly = prediction[0] == -1
        
        # Also check pure frequency
        freq_anomaly = len(recent_events) > self.behavior_config.get('max_accesses_per_window', 20)
        
        if is_anomaly or freq_anomaly:
            reasons = []
            if is_anomaly: reasons.append("Behavioral Anomaly (ML)")
            if freq_anomaly: reasons.append("Frequency Spike")
            return {
                "is_anomaly": True,
                "reason": " & ".join(reasons),
                "confidence": 0.9 if is_anomaly else 0.7
            }
            
        return {
            "is_anomaly": False,
            "reason": "Normal",
            "confidence": 1.0
        }

    def _cleanup_history(self, current_time: float):
        """Removes events older than window_seconds."""
        cutoff_time = current_time - self.window_seconds
        for process in list(self.process_history.keys()):
            self.process_history[process] = [
                event for event in self.process_history[process] 
                if event[0] >= cutoff_time
            ]
            if not self.process_history[process]:
                del self.process_history[process]
                if process in self.models:
                    del self.models[process]

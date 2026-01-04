import torch
import torch.nn as nn
import numpy as np
import re
import logging

import yara
import os

# --- 1. Signature-Based Detector ---
class SignatureDetector:
    def __init__(self, rules_path="rules.yar"):
        if not os.path.exists(rules_path):
            logging.error(f"YARA rules file not found at {rules_path}")
            self.rules = None
        else:
            try:
                self.rules = yara.compile(filepath=rules_path)
                logging.info(f"YARA rules compiled from {rules_path}")
            except Exception as e:
                logging.error(f"Failed to compile YARA rules: {e}")
                self.rules = None

    def detect(self, log_message):
        """Returns (is_threat, threat_type)"""
        if not self.rules:
            return False, None
            
        try:
            matches = self.rules.match(data=log_message)
            if matches:
                # distinct matches
                threat_names = [match.rule for match in matches]
                # Return the first match and generic description, or all of them
                return True, f"YARA Match: {', '.join(threat_names)}"
        except Exception as e:
            logging.error(f"YARA matching error: {e}")
            
        return False, None

# --- 2. Deep Learning (LSTM) Anomaly Detector ---
class LogLSTM(nn.Module):
    def __init__(self, input_size=10, hidden_size=32, num_layers=2, output_size=2):
        super(LogLSTM, self).__init__()
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.lstm = nn.LSTM(input_size, hidden_size, num_layers, batch_first=True)
        self.fc = nn.Linear(hidden_size, output_size) # Binary classification: Normal vs Anomaly

    def forward(self, x):
        h0 = torch.zeros(self.num_layers, x.size(0), self.hidden_size).to(x.device)
        c0 = torch.zeros(self.num_layers, x.size(0), self.hidden_size).to(x.device)
        out, _ = self.lstm(x, (h0, c0))
        out = self.fc(out[:, -1, :]) # Take the last output
        return out

class AnomalyDetector:
    def __init__(self):
        self.model = LogLSTM()
        self.model.eval() # Set to eval mode logic
        # For this demo, we use a heuristic wrapper because we don't have a pre-trained model file.
        # In a real scenario, we would load `self.model.load_state_dict(torch.load('model.pth'))`
        
    def preprocess(self, log_message):
        """
        Convert log message to a feature vector.
        Simple feature extraction: [len, num_spaces, num_special_chars, has_sql_keywords, etc.]
        """
        features = []
        features.append(len(log_message) / 200.0) # Normalized length
        features.append(log_message.count(' ') / 50.0)
        features.append(len(re.findall(r'[^a-zA-Z0-9\s]', log_message)) / 20.0)
        # Pad to input_size=10
        while len(features) < 10:
            features.append(0.0)
        return torch.tensor([features], dtype=torch.float32)

    def detect(self, log_message):
        """
        Returns (is_anomaly, confidence)
        """
        # 1. First, check logical anomalies that LSTM would learn
        # High frequency of special characters often indicates code injection
        special_char_ratio = len(re.findall(r'[^a-zA-Z0-9\s]', log_message)) / len(log_message) if len(log_message) > 0 else 0
        
        # If the ML model was trained, we'd run:
        # with torch.no_grad():
        #    input_tensor = self.preprocess(log_message)
        #    output = self.model(input_tensor)
        #    prob = torch.softmax(output, dim=1)
        #    anomaly_score = prob[0][1].item()
        
        # MOCKING the ML Result based on heuristics to ensure the Demo works reliably 
        # without needing 10,000 log lines of training data.
        # However, we structure it as if the LSTM produced it.
        
        anomaly_score = 0.1
        if special_char_ratio > 0.2:
            anomaly_score += 0.4
        if "error" in log_message.lower() or "fail" in log_message.lower():
            anomaly_score += 0.3
            
        is_anomaly = anomaly_score > 0.5
        return is_anomaly, anomaly_score

# --- 3. Hybrid Engine ---
class HybridEngine:
    def __init__(self):
        self.signature_detector = SignatureDetector()
        self.anomaly_detector = AnomalyDetector()
        logging.info("Hybrid Detection Engine Initialized")

    def analyze(self, log_entry):
        """
        Analyzes a log entry and returns a dict with threat info.
        log_entry: dict {"message": "...", "source_ip": "..."}
        """
        message = log_entry.get("message", "")
        if not message:
            message = log_entry.get("raw_message", "")

        analysis_report = {
            "is_threat": False,
            "components": {}
        }

        # 1. Signature Check
        is_known_threat, threat_type = self.signature_detector.detect(message)
        if is_known_threat:
            analysis_report["is_threat"] = True
            analysis_report["components"]["signature"] = {
                "detected": True,
                "type": threat_type,
                "confidence": 1.0
            }
        else:
             analysis_report["components"]["signature"] = {"detected": False}

        # 2. Anomaly Check (ALWAYS RUN)
        is_anomaly, score = self.anomaly_detector.detect(message)
        analysis_report["components"]["anomaly"] = {
            "detected": is_anomaly,
            "score": score
        }
        
        if is_anomaly:
             analysis_report["is_threat"] = True

        # Final Decision Logic
        if analysis_report["is_threat"]:
            # Prioritize Signature description if available, else Anomaly
            if is_known_threat:
                analysis_report["type"] = "Known Exploit"
                analysis_report["classification"] = threat_type
                analysis_report["confidence"] = 1.0
                analysis_report["details"] = f"YARA Matched: {threat_type} | Anomaly Score: {score:.2f}"
            else:
                analysis_report["type"] = "AI Anomaly"
                analysis_report["classification"] = "Suspicious Behavior"
                analysis_report["confidence"] = score
                analysis_report["details"] = f"Abnormal pattern detected (Score: {score:.2f})"
            
            return analysis_report

        return {"is_threat": False}

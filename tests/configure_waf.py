
import sys
import os
import requests
import time

# Add path to utils
current_dir = os.path.dirname(os.path.abspath(__file__))
# Map to: firegex-main/firegex-main/tests
utils_path = os.path.join(current_dir, "..", "firegex-main", "firegex-main", "tests")
sys.path.append(utils_path)

try:
    from utils.firegexapi import FiregexAPI
except ImportError:
    # Try finding it relative to CWD if running from root
    sys.path.append(os.path.join(os.getcwd(), "firegex-main", "firegex-main", "tests"))
    from utils.firegexapi import FiregexAPI

def configure():
    api_url = "http://127.0.0.1:4444/" 
    # Docker map: 4444 -> 4444
    print(f"[*] Connecting to WAF at {api_url}")
    
    api = FiregexAPI(api_url)
    
    # Check status
    try:
        st = api.status()
        print(f"Status: {st}")
    except Exception as e:
        print(f"[!] Cannot connect to API: {e}")
        return

    # Login
    # Assuming default credentials or set password?
    # If freshly started, might need to set password.
    if st == 'init':
        print("Setting password to 'admin'...")
        api.set_password("admin")
    
    if api.login("admin"):
        print("[+] Logged in.")
    else:
        print("[!] Login failed.")
        return

    # Clean existing services
    srvs = api.nfproxy_get_services()
    for s in srvs:
        print(f"[-] Deleting existing service {s['name']}")
        api.nfproxy_delete_service(s['service_id'])

    # Create Service
    # Name: TestSrv
    # Port: 5000 (Container Port - Exposed)
    # Proto: http
    # IP: 192.168.16.3 (External IP of firegex_test container on docker network)
    # The rule must match the destination of the incoming packet.
    
    print("[*] Creating service forwarding to 192.168.16.3:5000...")
    sid = api.nfproxy_add_service("TestSrv", 5000, "http", "192.168.16.3", False)
    
    if sid:
        print(f"[+] Service Created: {sid}")
    else:
        print("[!] Failed to create service.")
        return

    # Start Service
    print("[*] Starting service...")
    if api.nfproxy_start_service(sid):
        print("[+] Service Started.")
    else:
        print("[!] Failed to start service.")

    print("[*] Configuration Complete. WAF should be running cpproxy now.")

if __name__ == "__main__":
    configure()

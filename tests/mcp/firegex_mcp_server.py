from mcp.server.fastmcp import FastMCP
import subprocess
import requests
import json
import base64
import sys
import os
import glob
import secrets

# Initialize MCP Server
mcp = FastMCP("Firegex WAF Controller")

# Configuration
WAF_BASE_URL = "http://127.0.0.1:4444"
CONTAINER_NAME = "firegex"
CREDENTIALS = {"username": "admin", "password": "admin"}
HOST_IP = "192.168.16.1" # Simulation Gateway

# Hardcoded Sniffer Filter to allow auto-setup
AI_SNIFFER_CODE = """
from firegex.nfproxy import pyfilter, ACCEPT
from firegex.nfproxy.models import HttpRequest, HttpResponse
import json
import sys

@pyfilter
def ai_sniffer_req(req: HttpRequest):
    try:
        data = {
            "type": "request",
            "method": req.method,
            "url": req.url,
            "headers": req.headers,
            "body": req.body.decode('utf-8', errors='ignore') if req.body else None
        }
        msg = "AI_CONTEXT: " + json.dumps(data) + "\\n"
        print(msg, flush=True)
        with open("/tmp/ai_context.log", "a") as f:
            f.write(msg)
    except Exception as e:
        pass
    return ACCEPT

@pyfilter
def ai_sniffer_res(res: HttpResponse):
    try:
        data = {
            "type": "response",
            "status_code": res.status_code,
            "headers": res.headers
        }
        msg = "AI_CONTEXT: " + json.dumps(data) + "\\n"
        print(msg, flush=True)
        with open("/tmp/ai_context.log", "a") as f:
            f.write(msg)
    except Exception as e:
        pass
    return ACCEPT
"""

def get_session():
    """Authenticates with Firegex and returns a session."""
    s = requests.Session()
    try:
        login_resp = s.post(f"{WAF_BASE_URL}/api/login", data=CREDENTIALS, timeout=5)
        if login_resp.status_code != 200:
            return None
        token_data = login_resp.json()
        access_token = token_data.get("access_token")
        if access_token:
            s.headers.update({"Authorization": f"Bearer {access_token}"})
    except Exception as e:
        return f"Error: {str(e)}"
    return s

# --- FILE SYSTEM TOOLS (For Codebase Analysis) ---

@mcp.tool()
def list_files(path: str = ".") -> str:
    """
    Lists files in the given directory to understand project structure.
    Useful for finding source code (app.py, main.go, etc.) or config files.
    """
    try:
        files = []
        for root, dirs, files_in_dir in os.walk(path):
            if ".git" in root or "__pycache__" in root:
                continue
            for file in files_in_dir:
                files.append(os.path.join(root, file))
        return "\n".join(files) # No limit for now
    except Exception as e:
        return f"Error listing files: {e}"

@mcp.tool()
def read_file_content(file_path: str) -> str:
    """
    Reads the content of a file. Use this to analyze source code for vulnerabilities (SQLi, XSS).
    Recommend reading 'app.py', 'routes.py' or similar.
    """
    try:
        with open(file_path, "r") as f:
            return f.read()
    except Exception as e:
        return f"Error reading file: {e}"

@mcp.tool()
def discover_infrastructure() -> str:
    """
    Scans the Docker environment to detect potential target services and their IPs/Ports.
    Returns a JSON list of services suitable for protection.
    """
    try:
        # Get Firegex Container Info
        inspect_cmd = ["docker", "inspect", CONTAINER_NAME]
        proc = subprocess.run(inspect_cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            return json.dumps({"error": "Could not inspect Firegex container"})
            
        data = json.loads(proc.stdout)[0]
        
        # 1. Determine Firegex IP
        firegex_ip = ""
        networks = data.get("NetworkSettings", {}).get("Networks", {})
        for net_name, net_cfg in networks.items():
            firegex_ip = net_cfg.get("IPAddress")
            break # Take first
            
        # 2. Find Exposed Ports (excluding 4444 which is WAF API)
        # Config structure: "Config": { "ExposedPorts": { "4444/tcp": {}, "5000/tcp": {} } }
        exposed_ports = data.get("Config", {}).get("ExposedPorts", {})
        candidates = []
        
        for p_str in exposed_ports.keys():
            port = int(p_str.split('/')[0])
            if port != 4444: # Exclude WAF Management Port
                candidates.append({
                    "service_name": f"Detected_Service_{port}",
                    "ip": firegex_ip,
                    "port": port,
                    "reason": "Exposed Port on WAF Container"
                })
        
        # 3. Check for specific containers sharing network (Advanced)
        # (Simplified: Just returning exposed ports is usually enough for Sidecar/Service:Net mode)
        
        return json.dumps(candidates, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})

# --- WAF SETUP TOOLS (For Auto-Configuration) ---

@mcp.tool()
def setup_firegex_service(service_name: str, target_ip: str, port: int) -> str:
    """
    Automatically configures Firegex for a service.
    1. Creates NFProxy service (for AI Logging).
    2. Uploads the AI Sniffer filter.
    3. Creates NFRegex service (for adding blocking rules).
    
    Args:
        service_name: Name of the service (e.g., 'VulnApp').
        target_ip: IP of the container to protect (e.g., '192.168.16.2').
        port: Service port (e.g., 5000).
    """
    s = get_session()
    if not s:
        return "Failed to connect to WAF."

    output = []
    
    # 1. Cleanup existing services on this port to ensure clean state
    try:
        all_proxies = s.get(f"{WAF_BASE_URL}/api/nfproxy/services").json()
        for p in all_proxies:
            if str(p['port']) == str(port):
                 s.delete(f"{WAF_BASE_URL}/api/nfproxy/services/{p['service_id']}")
                 output.append(f"Deleted conflicting Proxy Service {p['service_id']}")
                 
        all_regex = s.get(f"{WAF_BASE_URL}/api/nfregex/services").json()
        for r in all_regex:
             if str(r['port']) == str(port):
                 s.delete(f"{WAF_BASE_URL}/api/nfregex/services/{r['service_id']}")
                 output.append(f"Deleted conflicting Firewall Service {r['service_id']}")
    except:
        pass

    # 1. Setup NFProxy (Logging)
    proxy_payload = {
        "name": f"{service_name}_Proxy",
        "port": port,
        "proto": "http",
        "ip_int": target_ip,
        "fail_open": False
    }
    
    # Try create
    resp = s.post(f"{WAF_BASE_URL}/api/nfproxy/services", json=proxy_payload)
    proxy_id = None
    
    if resp.status_code == 200:
        proxy_id = resp.json()["service_id"]
        output.append(f"Proxy Service Created (ID: {proxy_id})")
    elif resp.status_code == 400:
         # Generic fallback
         output.append(f"Proxy creation warning: {resp.text}")
         # Try to find again if logic above missed something
         all_proxies = s.get(f"{WAF_BASE_URL}/api/nfproxy/services").json()
         for p in all_proxies:
             if str(p['port']) == str(port):
                  proxy_id = p['service_id']
                  output.append(f"Using existing Proxy Service (ID: {proxy_id})")
                  break
    else:
        output.append(f"Failed to create Proxy: {resp.text}")

    if proxy_id:
        # 2. Upload Sniffer Code
        code_resp = s.put(f"{WAF_BASE_URL}/api/nfproxy/services/{proxy_id}/code", json={"code": AI_SNIFFER_CODE})
        if code_resp.status_code == 200:
             output.append("AI Sniffer Filter Uploaded.")
        else:
             output.append(f"Failed to upload filter: {code_resp.text}")
             
        # Start Proxy
        s.post(f"{WAF_BASE_URL}/api/nfproxy/services/{proxy_id}/start")

    # 3. Setup NFRegex (Blocking)
    regex_payload = {
        "name": f"{service_name}_Firewall",
        "port": port,
        "proto": "tcp",
        "ip_int": target_ip,
        "fail_open": False
    }
    resp_re = s.post(f"{WAF_BASE_URL}/api/nfregex/services", json=regex_payload)
    regex_id = None
    if resp_re.status_code == 200:
        regex_id = resp_re.json()["service_id"]
        output.append(f"Firewall Service Created (ID: {regex_id})")
    elif resp_re.status_code == 400:
         all_regex = s.get(f"{WAF_BASE_URL}/api/nfregex/services").json()
         for r in all_regex:
             if str(r['port']) == str(port):
                 regex_id = r['service_id']
                 output.append(f"Using existing Firewall Service (ID: {regex_id})")
                 break
    else:
        output.append(f"Firewall creation note: {resp_re.text}")
        
    if regex_id:
        # Retrieve logs or status if needed
        pass

    return "\n".join(output)

# --- MONITORING & DEFENSE ---

@mcp.resource("firegex://traffic/logs")
def get_traffic_logs() -> str:
    """Reads structured traffic logs."""
    try:
        result = subprocess.run(
            ["docker", "exec", CONTAINER_NAME, "tail", "-n", "20", "/tmp/ai_context.log"],
            capture_output=True, text=True
        )
        return result.stdout
    except Exception as e:
        return ""

@mcp.tool()
def add_blocking_rule_regex(regex_pattern: str, target_ip: str, port: int) -> str:
    """
    Adds a blocking rule to the Firewall.
    This tool intelligently finds the correct Service ID based on IP/Port and applies the rule.
    
    Args:
        regex_pattern: The pattern to block (e.g., 'admin%27').
        target_ip: The protected service IP.
        port: The protected service port.
    """
    s = get_session()
    if isinstance(s, str): return f"Connection Failed: {s}"
    if not s: return "No Connection (Auth failed?)"

    # Find the NFRegex service ID for this IP/Port
    resp = s.get(f"{WAF_BASE_URL}/api/nfregex/services")
    try:
        services = resp.json()
    except:
        return f"Error fetching services: {resp.text}"
        
    service_id = None
    
    for srv in services:
        # Match roughly based on port/ip
        # Handle '/32' or other CIDR in stored IP
        srv_ip = srv.get("ip_int", "").split('/')[0]
        
        # Debug
        # print(f"DEBUG: Checking {srv_ip}:{srv.get('port')} vs {target_ip}:{port}")
        if str(srv.get("port")) == str(port) and srv_ip == target_ip:
            service_id = srv.get("service_id")
            break
    
    if not service_id:
        return f"No firewall service found for {target_ip}:{port}. Available: {[f'{s.get('ip_int')}:{s.get('port')}' for s in services]}"

    # Add Rule
    encoded_regex = base64.b64encode(regex_pattern.encode()).decode()
    payload = {
        "service_id": service_id,
        "regex": encoded_regex,
        "mode": "B",  # Changed from DROP to B based on nfregex_test.py
        "active": True,
        "is_case_sensitive": False
    }
    
    # Debug
    # print(f"DEBUG Payload: {payload}")
    
    # Check for existing rule to avoid duplicates? 
    # API might handle it or return error. We'll return the API response.
    resp = s.post(f"{WAF_BASE_URL}/api/nfregex/regexes", json=payload)
    
    if resp.status_code == 200:
        return "Rule Added Successfully"
    else:
        return f"Failed to add rule (Status: {resp.status_code}): {resp.text}"
if __name__ == "__main__":
    mcp.run()

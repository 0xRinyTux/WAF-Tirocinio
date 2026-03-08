import json
import time
from firegex_mcp_server import list_files, read_file_content, setup_firegex_service, get_traffic_logs, add_blocking_rule_regex, discover_infrastructure
from agent_brain import AgentBrain

class CTFAgent:
    def __init__(self, brain_mode="ollama"):
        self.brain = AgentBrain(mode=brain_mode)
        self.target_ip = None
        self.target_port = None
        self.service_name = None
        self.proactive_rules = []
        self.applied_hashes = set()

    def discover(self):
        print("🕵️  [AGENT] Running Service Discovery...")
        infra_json = discover_infrastructure()
        try:
            targets = json.loads(infra_json)
            if not targets or "error" in targets:
                print(f"❌ Discovery failed or found no targets: {infra_json}")
                return None
            
            # Pick first target
            target = targets[0]
            self.target_ip = target['ip']
            self.target_port = target['port']
            self.service_name = target['service_name']
            
            print(f"🕵️  [AGENT] Target Acquired: {self.target_ip}:{self.target_port} ({self.service_name})")
            return target
        except Exception as e:
            print(f"❌ Invalid discovery output: {e}")
            return None

    def analyze_codebase(self):
        print("🕵️  [AGENT] Scanning Local Workspace for source code...")
        all_files = list_files(".").split("\n")
        source_files = [
            f for f in all_files 
            if f.endswith(('.py', '.php', '.js', '.go')) 
            and "vuln" in f 
            and "test" not in f
        ]
        
        self.proactive_rules = []
        report = []

        if not source_files:
            print("⚠️  No likely source code found.")
            return report

        for file_path in source_files:
            clean_path = file_path.replace("\\", "/").strip()
            if clean_path.startswith("./"): clean_path = clean_path[2:]
            
            print(f"🕵️  [AGENT] Analyzing {clean_path}...")
            content = read_file_content(clean_path)
            
            # ASK THE BRAIN
            vulns = self.brain.analyze_file(clean_path, content)
            
            if vulns:
                report.append({"file": clean_path, "vulns": vulns})
                # Ask brain for rules
                suggested_rules = self.brain.decide_protection_rules(vulns)
                self.proactive_rules.extend(suggested_rules)
        
        self.proactive_rules = list(set(self.proactive_rules)) # Dedup
        return report

    def setup_waf(self):
        if not self.target_ip:
            return "No Target Selected"
            
        print(f"🕵️  [AGENT] Setting up Firegex WAF for {self.target_ip}:{self.target_port}...")
        res = setup_firegex_service("AutoProtectedService", self.target_ip, self.target_port)
        return res

    def apply_proactive_rules(self, rules=None):
        target_rules = rules if rules is not None else self.proactive_rules
        
        applied = []
        print(f"🕵️  [AGENT] Applying {len(target_rules)} rules...")
        for rule in target_rules:
            res = add_blocking_rule_regex(rule, self.target_ip, self.target_port)
            print(f"    >> Applying '{rule}': {res}")
            applied.append(rule)
            self.applied_hashes.add(rule)
        
        return applied

    def run_sentry_tick(self):
        """
        Runs one iteration of traffic monitoring.
        Returns list of newly blocked attacks.
        """
        logs_raw = get_traffic_logs()
        if not logs_raw:
            return []

        lines = logs_raw.split('\n')
        new_blocks = []
        
        for line in lines:
            if "request" in line and ("AI_CONTEXT" in line):
                suspicious = [] # Add advanced heuristic logic here or call LLM (slow)
                
                # Basic Hueristics
                if "admin'" in line or "admin%27" in line: suspicious.append("admin'")
                if "<script>" in line: suspicious.append("<script>")
                if "UNION" in line: suspicious.append("UNION")
                
                for pattern in suspicious:
                    if pattern not in self.applied_hashes:
                        print(f"🚨 LIVE ATTACK DETECTED: {pattern}")
                        add_blocking_rule_regex(pattern, self.target_ip, self.target_port)
                        self.applied_hashes.add(pattern)
                        new_blocks.append(pattern)
        
        return new_blocks

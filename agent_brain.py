import requests
import json
import subprocess
import os
import sys

class AgentBrain:
    def __init__(self, mode="ollama", model_name="mistral"):
        self.mode = mode
        self.model_name = model_name
        # Add a mock mode flag to disable LLM calls
        self.mock_mode = os.environ.get("AGENT_MOCK_MODE", "false").lower() == "true"
        
        self.ollama_url = "http://localhost:11434/api/generate"
        self.ollama_tags_url = "http://localhost:11434/api/tags"
        self.ollama_pull_url = "http://localhost:11434/api/pull"
        self.history = []
        
        if self.mode == "ollama":
            self.ensure_model_available()

    def ensure_model_available(self):
        try:
            # Check if model exists
            print(f"   >> 🧠 Checking if '{self.model_name}' is loaded...")
            resp = requests.get(self.ollama_tags_url, timeout=5)
            if resp.status_code == 200:
                models = [m['name'] for m in resp.json().get('models', [])]
                # Matches "deepseek-coder:latest" or simple "deepseek-coder"
                if not any(self.model_name in m for m in models):
                    print(f"   >> ⚠️ Model '{self.model_name}' not found. Attempting API pull (this may take a while)...")
                    # Trigger Pull
                    pull_payload = {"name": self.model_name}
                    # Stream=False means we wait until done (could timeout). 
                    # Better to stream=True and just iterate, or just fire and hope.
                    # For simplicity in this agent, we'll try a blocking pull with long timeout or notify user.
                    
                    try:
                        # stream=True to avoid read timeout on long pulls
                        pull_resp = requests.post(self.ollama_pull_url, json=pull_payload, stream=True)
                        for line in pull_resp.iter_lines():
                            if line:
                                try:
                                    status = json.loads(line).get('status', 'downloading')
                                    print(f"      [PULL] {status}", end='\r')
                                except: pass
                        print(f"\n   >> ✅ Model '{self.model_name}' pulled successfully.")
                    except Exception as e:
                        print(f"\n   >> ❌ Failed to pull model via API: {e}. Please run 'ollama pull {self.model_name}' manually.")
                else:
                    print(f"   >> ✅ Model '{self.model_name}' is ready.")
        except Exception as e:
            print(f"   >> ⚠️ Could not contact Ollama to check models: {e}")

    def analyze_file(self, filename, content):
        """
        Hybrid Analysis:
        1. Bandit (SAST) for reliable detection.
        2. Ollama (LLM) for specific Regex generation.
        """
        vulns = []
        
        # 1. BANDIT SCAN (SAST)
        if filename.endswith(".py"):
            try:
                # Run bandit on the file using current python environment
                cmd = [sys.executable, "-m", "bandit", "-f", "json", filename]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.stdout.strip():
                    try:
                        bandit_json = json.loads(result.stdout)
                        if "results" in bandit_json:
                            for issue in bandit_json["results"]:
                                vulns.append({
                                    "type": issue.get("issue_text", "Unknown"),
                                    "confidence": issue.get("confidence", "Unknown"), # Fixed key
                                    "details": f"[Bandit SAST] {issue.get('issue_text')} (Line {issue.get('line_number')})",
                                    "regex": None  # Bandit doesn't give regex
                                })
                    except json.JSONDecodeError:
                        pass
            except Exception as e:
                print(f"   >> ⚠️ Bandit Scan Failed: {e}")

        # 2. OLLAMA SCAN (LLM)
        llm_vulns = self._analyze_with_ollama(filename, content)
        vulns.extend(llm_vulns)
        
        return vulns

    def _analyze_with_ollama(self, filename, content):
        """
        Asks Ollama (TinyLlama) for blocking regexes.
        """
        if self.mock_mode:
            print(f"   >> 🧠 [MOCK] Skipping LLM for {filename}, returning dummy rule.")
            return [{
                "type": "LLM_DETECTED",
                "details": "MOCK AI suggested regex",
                "regex": "mock_rule_pattern",
                "confidence": "Medium"
            }]

        # Improved Prompt: Raw F-String to handle regex escapes
        prompt = rf"""
        Analyze this Python code for SQL Injection and RCE.
        
        Code:
        ```python
        {content[:2000]} 
        ```
        
        Provide a list of REGEX patterns to BLOCK these attacks. 
        
        CRITICAL OUTPUT INSTRUCTIONS:
        1. Output MUST be a simple list of regexes.
        2. Prefix every regex with "RULE:".
        3. Do NOT include any explanations, introduction, or code snippets.
        4. Do NOT output markdown formatting like ```.

        Examples:
        RULE: (?i)UNION.*SELECT
        RULE: <script>
        RULE: \.\./\.\./
        RULE: ;.*(cat|ls|pwd)
        
        YOUR RESPONSE:
        """
        
        try:
            payload = {
                "model": self.model_name, 
                "prompt": prompt,
                "stream": True,  # ENABLE STREAMING
                "options": {
                    "temperature": 0.3
                }
            }
            # Connect to Ollama
            print(f"   >> 🧠 Contacting Local Brain (Ollama/{self.model_name}) for {filename}...")
            print(f"   >> 💭 Stream Output: ", end="", flush=True)
            
            resp = requests.post(self.ollama_url, json=payload, stream=True, timeout=120)
            
            response_text = ""
            if resp.status_code == 200:
                for line in resp.iter_lines():
                    if line:
                        try:
                            # Parse chunk
                            chunk = json.loads(line)
                            token = chunk.get("response", "")
                            
                            # Print to terminal immediately
                            sys.stdout.write(token)
                            sys.stdout.flush()
                            
                            # Accumulate for parsing
                            response_text += token
                            
                            if chunk.get("done", False):
                                break
                        except:
                            pass
                print("\n") # New line after stream ends
                
                # Robust Parsing: Hybrid approach (Explicit RULE: prefix OR Heuristic)
                vulns = []
                for line in response_text.split('\n'):
                    line = line.strip()
                    if not line: continue
                    
                    clean_regex = ""
                    
                    # Case A: Explicit Prefix
                    if line.startswith("RULE:"):
                         clean_regex = line[5:].strip()
                    # Case B: Heuristic Fallback (if model forgot prefix)
                    elif len(line) > 3 and not line.startswith("#") and " " not in line:
                         # Assume single word/pattern lines are regexes
                         clean_regex = line
                    
                    # Heuristic Filter: Discard obvious non-regex junk
                    if (len(clean_regex) > 2 and 
                        not clean_regex.startswith("#") and 
                        "import " not in clean_regex and 
                        "def " not in clean_regex and 
                        not clean_regex.startswith("Note:") and 
                        not clean_regex.startswith("1.")):
                        
                        vulns.append({
                            "type": "LLM_DETECTED",
                            "details": "AI suggested regex",
                            "regex": clean_regex,
                            "confidence": "Medium"
                        })

                return vulns
            else:
                print(f"   >> ❌ Brain Error: {resp.status_code}")
                return []
                
        except Exception as e:
            print(f"   >> ❌ Unexpected Brain Error: {e}")
            return []

    def decide_protection_rules(self, vulnerabilities):
        """
        Decides which WAF rules to apply.
        Uses Regex suggested by LLM if available, otherwise falls back to smart defaults.
        """
        rules = []
        for v in vulnerabilities:
            if not isinstance(v, dict):
                continue
                
            # 1. Use LLM suggested regex if confident
            if "regex" in v and v["regex"]:
                rules.append(v["regex"])
                continue

            # Fallback ONLY if LLM didn't provide a regex
            v_type = str(v.get("type", "")).upper()
            if "SQL" in v_type:
                rules.append("UNION")
                rules.append("SELECT")
            elif "XSS" in v_type:
                rules.append("<script>")
            elif "RCE" in v_type:
                rules.append(r";.*cat")
                rules.append(r"\|.*ls")
                
        return list(set(rules))

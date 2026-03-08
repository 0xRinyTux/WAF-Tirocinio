import time
from agent_core import CTFAgent

def main():
    agent = CTFAgent(brain_mode="ollama")
    
    print("🕵️  [CLI] Initializing Agent...")
    
    # 1. Discovery
    target = agent.discover()
    if not target:
        return

    # 2. Analysis
    report = agent.analyze_codebase()
    
    # Print Scan Results
    for file_report in report:
        print(f"🚨 Vulnerabilities in {file_report['file']}:")
        for v in file_report['vulns']:
            print(f"    - {v.get('type','UNK')}: {v.get('regex', 'No regex')}")

    # 3. Setup WAF
    waf_result = agent.setup_waf()
    print(f"🕵️  [AGENT] WAF Setup Result:\n{waf_result}")

    # 4. Rules Approval
    if agent.proactive_rules:
        print("\n---------- RULE APPROVAL ----------")
        for idx, rule in enumerate(agent.proactive_rules):
            print(f"{idx+1}. REJECT regex match: '{rule}'")
        print("-----------------------------------")
        
        try:
            choice = input(f"🕵️  [AGENT] Do you want to apply these rules? [Y/n] ")
        except EOFError: choice = "y"

        # Fix: Strip whitespace from input to correctly handle "Y " or " Y"
        choice = choice.strip()

        if choice.lower() in ["", "y", "yes"]:
            agent.apply_proactive_rules()
        else:
            print(f"❌ Rules declined. (Input was: '{choice}')")
    else:
         print("🕵️  [CLI] No rules generated.")

    # 5. Monitoring
    print("🕵️  [CLI] Entering Sentry Loop (Ctrl+C to stop)...")
    try:
        while True:
            agent.run_sentry_tick()
            time.sleep(5)
    except KeyboardInterrupt:
        print("Bye!")

if __name__ == "__main__":
    main()


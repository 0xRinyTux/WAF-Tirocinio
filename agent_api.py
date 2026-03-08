from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import uvicorn
import asyncio
from agent_core import CTFAgent

app = FastAPI(title="Firegex Agent API", description="Encrypted API for WAF & Agent Control", version="1.0.0")

# Global Agent Instance
agent = CTFAgent(brain_mode="ollama")

class ScanResult(BaseModel):
    file: str
    vulns: List[dict]

class RuleRequest(BaseModel):
    rules: List[str]

@app.get("/")
def health_check():
    return {"status": "online", "mode": "ollama"}

@app.post("/discover")
def discover_infrastructure_endpoint():
    target = agent.discover()
    if not target:
        raise HTTPException(status_code=404, detail="No targets found")
    return target

@app.post("/scan", response_model=List[ScanResult])
def scan_codebase_endpoint():
    report = agent.analyze_codebase()
    return report

@app.get("/rules/proposed")
def get_proposed_rules():
    return {"count": len(agent.proactive_rules), "rules": agent.proactive_rules}

@app.post("/waf/setup")
def setup_waf_endpoint():
    res = agent.setup_waf()
    return {"result": res}

@app.post("/rules/apply")
def apply_rules_endpoint(req: Optional[RuleRequest] = None):
    rules_to_apply = req.rules if req and req.rules else None
    applied = agent.apply_proactive_rules(rules_to_apply)
    return {"applied": applied}

# Background Monitoring Task
is_monitoring = False

async def monitor_loop():
    global is_monitoring
    is_monitoring = True
    print("Background Monitoring Started")
    while is_monitoring:
        try:
            agent.run_sentry_tick()
            await asyncio.sleep(5)
        except Exception as e:
            print(f"Monitor Error: {e}")
            await asyncio.sleep(5)

@app.post("/monitor/start")
def start_monitoring(background_tasks: BackgroundTasks):
    global is_monitoring
    if is_monitoring:
        return {"status": "already_running"}
    background_tasks.add_task(monitor_loop)
    return {"status": "started"}

@app.post("/monitor/stop")
def stop_monitoring():
    global is_monitoring
    is_monitoring = False
    return {"status": "stopped"}

if __name__ == "__main__":
    # In production, use SSL (uvicorn --ssl-keyfile ...)
    uvicorn.run(app, host="0.0.0.0", port=8000)

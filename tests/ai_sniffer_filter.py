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
        msg = "AI_CONTEXT: " + json.dumps(data) + "\n"
        print(msg, flush=True)
        with open("/tmp/ai_context.log", "a") as f:
            f.write(msg)
    except Exception as e:
        err = f"AI_CONTEXT_ERROR: {e}\n"
        print(err, file=sys.stderr, flush=True)
        with open("/tmp/ai_context.log", "a") as f:
            f.write(err)
    
    return ACCEPT

@pyfilter
def ai_sniffer_res(res: HttpResponse):
    try:
        data = {
            "type": "response",
            "status_code": res.status_code,
            "headers": res.headers,
            "body_len": len(res.body) if res.body else 0
        }
        msg = "AI_CONTEXT: " + json.dumps(data) + "\n"
        print(msg, flush=True)
        with open("/tmp/ai_context.log", "a") as f:
            f.write(msg)
    except Exception as e:
        err = f"AI_CONTEXT_ERROR: {e}\n"
        print(err, file=sys.stderr, flush=True)
        with open("/tmp/ai_context.log", "a") as f:
            f.write(err)

    return ACCEPT

from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any
from guardrail import GuardrailProxy

app = FastAPI(
    title="AI Guardrail Middleware Gateway",
    description="Deterministic zero-trust policy proxy for LLM agent tool execution.",
    version="1.0.0"
)

proxy = GuardrailProxy(headless_mode=True)

class ToolRequest(BaseModel):
    tool_name: str
    arguments: Dict[str, Any] = {}

@app.get("/status")
def get_status():
    return {
        "session_tainted": proxy.session_tainted,
        "tool_call_count": proxy.tool_call_count,
        "max_tool_calls": proxy.policy.get("max_tool_calls_per_session", 5),
        "allowed_directory": proxy.policy.get("allowed_directory"),
    }

@app.post("/execute")
def execute_tool(req: ToolRequest):
    result = proxy.execute_tool(req.tool_name, **req.arguments)
    blocked = result.startswith("ERROR:")
    return {
        "status": "BLOCKED" if blocked else "ALLOWED",
        "tool_name": req.tool_name,
        "session_tainted": proxy.session_tainted,
        "call_count": proxy.tool_call_count,
        "result": result
    }

@app.post("/reset")
def reset_session():
    proxy.reset_session()
    return {"status": "RESET", "session_tainted": False, "tool_call_count": 0}

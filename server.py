import langchain
langchain.verbose = False
langchain.debug = False
langchain.llm_cache = None
import asyncio
import json
import uuid
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, Response
from fastapi.staticfiles import StaticFiles
import uvicorn
import markdown
from agent import init_agent, LLM_GUARDRAILS_DISABLED
from security_simulator import run_security_simulation_stream, cancel_active_test, get_available_mcp_tools
import security_db

app = FastAPI()

# Mount the static directory to serve the frontend
app.mount("/static", StaticFiles(directory="static"), name="static")

# Global reference to the agents.
# When LLM_GUARDRAILS_DISABLED=True in agent.py, the single agent already has guardrails stripped.
cygeniq_agent = None
cygeniq_adversarial_agent = None

@app.on_event("startup")
async def startup_event():
    global cygeniq_agent, cygeniq_adversarial_agent
    print("Initializing Cygeniq Agent backend...")
    res = await init_agent()
    if isinstance(res, tuple):
        cygeniq_agent, cygeniq_adversarial_agent = res
    else:
        cygeniq_agent = res
        cygeniq_adversarial_agent = res
    if cygeniq_agent is None:
        print("Failed to initialize agent. Check environment variables.")

@app.get("/", response_class=HTMLResponse)
async def read_root():
    with open("static/index.html", "r", encoding="utf-8") as f:
        return f.read()

@app.post("/chat")
async def chat_endpoint(request: Request):
    body = await request.json()
    user_input = body.get("message")
    session_id = body.get("session_id", str(uuid.uuid4()))

    if not user_input:
        return JSONResponse(status_code=400, content={"error": "No message provided"})

    if len(user_input) > 10000:
        return JSONResponse(status_code=413, content={"error": "Message exceeds maximum allowed length of 10,000 characters."})

    if user_input.strip().lower() in ["status", "/status"]:
        dashboard = """```text
╔══════════════════════════════════════════════╗
║          CYGENIQ AI LABS AGENT               ║
╠══════════════════════════════════════════════╣
║ LLM              Grok 4.3                    ║
║ Framework        LangGraph                   ║
║ MCP Servers      3                           ║
║ Tools Available  24                          ║
║ Database         Supabase/Postgres           ║
║ Documents        Policies                    ║
║ Memory           Persistent                  ║
║ Status           ● Connected                 ║
╚══════════════════════════════════════════════╝
```"""
        return {
            "blocks": [markdown.markdown(dashboard)],
            "source": None
        }

    if not cygeniq_agent:
        return JSONResponse(status_code=500, content={"error": "Agent not initialized"})

    try:
        # We pass a thread_id via config to enable memory (checkpointing)
        config = {"configurable": {"thread_id": session_id}}
        
        # Invoke the LangGraph agent
        result = await cygeniq_agent.ainvoke({"messages": [("user", user_input)]}, config)
        
        # Extract the messages
        messages = result["messages"]
        final_message = messages[-1].content

        # Basic heuristic to determine source for the badge
        # LangGraph intermediate steps contain ToolMessages
        source_badge = None
        for msg in messages:
            if msg.type == "tool":
                if msg.name in ["query", "list_tables", "describe_table"]:
                    source_badge = {
                        "type": "db",
                        "label": "Postgres (Supabase)",
                        "drawerTitle": "Database query",
                        "drawerBody": f"<h4>Tool Used</h4><pre>{msg.name}</pre><h4>Result Snippet</h4><div class='excerpt'>{msg.content[:300]}...</div>"
                    }
                    break
                elif msg.name in ["read_file", "list_directory", "list_allowed_directories"]:
                    source_badge = {
                        "type": "file",
                        "label": "Filesystem (Policies)",
                        "drawerTitle": "Policy Document",
                        "drawerBody": f"<h4>Tool Used</h4><pre>{msg.name}</pre><h4>Result Snippet</h4><div class='excerpt'>{msg.content[:300]}...</div>"
                    }
                    break
                elif msg.name in ["read_graph", "create_entities", "create_relations", "add_observations", "delete_entities", "delete_observations", "delete_relations", "search_nodes", "open_nodes"]:
                    source_badge = {
                        "type": "memory",
                        "label": "Memory (Knowledge Graph)",
                        "drawerTitle": "Persistent Memory",
                        "drawerBody": f"<h4>Tool Used</h4><pre>{msg.name}</pre><h4>Result Snippet</h4><div class='excerpt'>{msg.content[:300]}...</div>"
                    }
                    break
                elif msg.name in ["search_sharepoint", "read_sharepoint_document", "list_knowledge_areas", "upload_sharepoint_document"]:
                    source_badge = {
                        "type": "sharepoint",
                        "label": "SharePoint (Knowledge)",
                        "drawerTitle": "SharePoint Document",
                        "drawerBody": f"<h4>Tool Used</h4><pre>{msg.name}</pre><h4>Result Snippet</h4><div class='excerpt'>{msg.content[:300]}...</div>"
                    }
                    break
                elif msg.name in ["search_policies", "get_policy_details", "list_available_policies", "check_compliance_requirement"]:
                    source_badge = {
                        "type": "policy",
                        "label": "Policy Intelligence",
                        "drawerTitle": "Policy Document",
                        "drawerBody": f"<h4>Tool Used</h4><pre>{msg.name}</pre><h4>Result Snippet</h4><div class='excerpt'>{msg.content[:300]}...</div>"
                    }
                    break
                elif msg.name in ["list_products", "get_product_datasheet", "search_product_capabilities", "match_rfp_requirement_to_features"]:
                    source_badge = {
                        "type": "product",
                        "label": "Product Intelligence",
                        "drawerTitle": "Cygeniq Product Intelligence",
                        "drawerBody": f"<h4>Tool Used</h4><pre>{msg.name}</pre><h4>Result Snippet</h4><div class='excerpt'>{msg.content[:300]}...</div>"
                    }
                    break
                elif msg.name in ["list_regulatory_frameworks", "get_framework_controls", "map_control_to_product_evidence", "evaluate_compliance_gap", "generate_compliance_checklist"]:
                    source_badge = {
                        "type": "grc",
                        "label": "GRC & Regulatory Intelligence",
                        "drawerTitle": "Regulatory Compliance Standard",
                        "drawerBody": f"<h4>Tool Used</h4><pre>{msg.name}</pre><h4>Result Snippet</h4><div class='excerpt'>{msg.content[:300]}...</div>"
                    }
                    break
                elif msg.name in ["search_emails", "read_email", "draft_email", "send_email"]:
                    source_badge = {
                        "type": "mail",
                        "label": "Gmail (shubhamwaghrq@gmail.com)",
                        "drawerTitle": "Gmail Activity",
                        "drawerBody": f"<h4>Tool Used</h4><pre>{msg.name}</pre><h4>Result Snippet</h4><div class='excerpt'>{msg.content[:300]}...</div>"
                    }
                    break

        # Convert markdown text to HTML
        html_message = markdown.markdown(final_message)

        return {
            "blocks": [html_message],
            "source": source_badge
        }

    except Exception as e:
        err_msg = str(e)
        print(f"Error processing chat: {err_msg}")
        if "429" in err_msg or "rate_limit" in err_msg.lower():
            err_msg = "Groq LLM daily token rate limit reached (429). Quota resets shortly. You can use the AI Security Simulator in Safe Simulation mode to run offline risk analysis and test guardrails."
        return JSONResponse(status_code=500, content={"error": err_msg})

# ==========================================
# AI Security Simulator Endpoints
# ==========================================

@app.get("/testing/status")
async def testing_status():
    """
    Returns the current security testing mode state.
    Shows whether LLM-level guardrails are disabled globally in agent.py.
    REVERT: Set LLM_GUARDRAILS_DISABLED = False in agent.py to restore all guardrails.
    """
    return {
        "llm_guardrails_disabled": LLM_GUARDRAILS_DISABLED,
        "agent_mode": "SECURITY_TESTING_MODE" if LLM_GUARDRAILS_DISABLED else "PRODUCTION",
        "note": "Set LLM_GUARDRAILS_DISABLED = False in agent.py and restart server to fully restore guardrails."
    }

@app.post("/simulator/stream")
async def simulator_stream(request: Request):
    """
    Accepts a test request and streams live real-time Server-Sent Events (SSE).
    When LLM_GUARDRAILS_DISABLED=True in agent.py, all simulator tests
    automatically run against the guardrail-stripped agent.
    """
    body = await request.json()
    prompt = body.get("prompt")
    if not prompt or not prompt.strip():
        return JSONResponse(status_code=400, content={"error": "Prompt is required for security testing."})

    execution_mode = body.get("execution_mode", "safe_simulation")
    categories = body.get("categories")
    target_tools = body.get("target_tools")
    # Inherit the global flag OR explicit per-request flag OR mode-based inference
    disable_llm_guardrails = bool(
        LLM_GUARDRAILS_DISABLED or
        body.get("disable_llm_guardrails", False) or
        execution_mode in ["adversarial_testing", "adversarial_test", "controlled_testing_relaxed"]
    )
    target_agent = cygeniq_adversarial_agent if (disable_llm_guardrails and cygeniq_adversarial_agent) else cygeniq_agent

    return StreamingResponse(
        run_security_simulation_stream(
            prompt=prompt,
            execution_mode=execution_mode,
            categories_override=categories,
            target_tools=target_tools,
            cygeniq_agent=target_agent,
            disable_llm_guardrails=disable_llm_guardrails
        ),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

@app.post("/simulator/stop")
async def simulator_stop(request: Request):
    """Cancels a currently executing security simulation stream."""
    body = await request.json()
    test_id = body.get("test_id")
    if not test_id:
        return JSONResponse(status_code=400, content={"error": "test_id is required."})
    success = cancel_active_test(test_id)
    return {"success": success, "test_id": test_id}

@app.get("/simulator/history")
async def simulator_history():
    """Returns list of past security test runs."""
    return security_db.list_test_history()

@app.get("/simulator/report/{test_id}")
async def simulator_report(test_id: str):
    """Returns full structured report for a given test ID."""
    report = security_db.get_test_run(test_id)
    if not report:
        return JSONResponse(status_code=404, content={"error": f"Report '{test_id}' not found."})
    return report

@app.get("/simulator/export/{test_id}")
async def simulator_export(test_id: str, format: str = "json"):
    """Exports test report as JSON or CSV."""
    if format.lower() == "csv":
        csv_data = security_db.export_report_csv(test_id)
        if not csv_data:
            return JSONResponse(status_code=404, content={"error": f"Report '{test_id}' not found."})
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=security_audit_{test_id}.csv"}
        )
    else:
        report = security_db.get_test_run(test_id)
        if not report:
            return JSONResponse(status_code=404, content={"error": f"Report '{test_id}' not found."})
        return JSONResponse(
            content=report,
            headers={"Content-Disposition": f"attachment; filename=security_audit_{test_id}.json"}
        )

@app.get("/simulator/tools")
async def simulator_tools():
    """Lists available MCP tools and security capabilities dynamically."""
    return get_available_mcp_tools()

@app.post("/simulator/clear")
async def simulator_clear():
    """Clears all stored test runs and audit history."""
    security_db.clear_test_history()
    return {"success": True, "message": "Test history cleared."}

if __name__ == "__main__":
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True)

# Cygeniq AI Labs — Enterprise AI Agent with Security Simulator

An enterprise-grade AI agent built for **Cygeniq AI Labs** that integrates with 45 real MCP (Model Context Protocol) tools and includes a live **AI Security Simulator** for adversarial prompt testing.

---

## Features

### 🤖 AI Chatbot Agent
- Multi-tool LangGraph ReAct agent powered by Groq LLM
- **45 live MCP tools** across Gmail, PostgreSQL, SharePoint, Filesystem, Memory, Policy, Product, and GRC integrations
- Persistent conversation memory (SQLite checkpointer)

### 🛡️ AI Security Simulator
- Real-time adversarial prompt testing with Server-Sent Events (SSE) streaming
- **13 security check categories:** Prompt Injection, Secret Disclosure, Destructive SQL, Path Traversal, Data Exfiltration, PII Exposure, Privilege Escalation, GRC Violations, and more
- Evidence-based **PASS / FAIL / INCONCLUSIVE** verdicts — no hardcoded results
- Separates **Threat Detection** from **Vulnerability Confirmation**
- Controlled Adversarial Testing Mode (LLM guardrails removable for demo/pentest)
- Full audit trail: SQLite persistence + JSON/CSV export

### 🔌 MCP Integrations
| Server | Tools |
|--------|-------|
| Postgres MCP | `query`, `list_tables`, `describe_table` |
| Filesystem MCP | `read_file`, `list_directory` |
| Memory MCP | `create_entities`, `read_graph`, `search_nodes` |
| Gmail MCP | `search_emails`, `read_email`, `draft_email`, `send_email` |
| SharePoint MCP | `search_sharepoint`, `read_sharepoint_document`, `upload_sharepoint_document` |
| Policy MCP | `search_policies`, `get_policy_details`, `check_compliance_requirement` |
| Product MCP | `list_products`, `search_product_capabilities`, `match_rfp_requirement_to_features` |
| GRC MCP | `list_regulatory_frameworks`, `get_framework_controls`, `evaluate_compliance_gap` |

---

## Quick Start

### 1. Clone the repo
```bash
git clone https://github.com/shubhamwaghrq-sys/cygeniq-ai-labs-.git
cd cygeniq-ai-labs-
```

### 2. Create virtual environment & install dependencies
```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

pip install -r requirements.txt
```

### 3. Configure environment variables
```bash
cp .env.example .env
# Edit .env and fill in your real API keys
```

### 4. Run the server
```bash
uvicorn server:app --host 127.0.0.1 --port 8000 --reload
```

Open **http://localhost:8000** in your browser.

---

## Environment Variables

Copy `.env.example` to `.env` and configure:

```env
GROQ_API_KEY=your_groq_api_key_here
SUPABASE_URL=postgresql://user:password@host:5432/dbname
AZURE_TENANT_ID=your_azure_tenant_id
AZURE_CLIENT_ID=your_azure_client_id
AZURE_CLIENT_SECRET=your_azure_client_secret
GMAIL_ADDRESS=your@gmail.com
GMAIL_APP_PASSWORD=your_16_char_app_password
```

> ⚠️ **Never commit your real `.env` file.** It is excluded by `.gitignore`.

---

## Security Guardrail Toggles

For adversarial demo/pentest mode, three toggles control guardrail state:

| File | Toggle | Default |
|------|--------|---------|
| `agent.py` | `LLM_GUARDRAILS_DISABLED` | `True` (demo mode) |
| `security_simulator.py` | `APPLICATION_GUARDRAILS_DISABLED` | `True` (demo mode) |
| `gmail_mcp.py` | `TESTING_EMAIL_BYPASS` | `True` (mock intercept) |

> Set all three to `False` to restore full production guardrails.

---

## Running Tests

```bash
# Full unit test suite (15 tests)
python -m unittest test_security_simulator.py -v

# Adversarial security test suite (6 suites)
python test_adversarial.py
```

---

## Tech Stack

- **Backend:** FastAPI + Uvicorn
- **AI Agent:** LangGraph ReAct + LangChain MCP Adapters
- **LLM:** Groq API (`openai/gpt-oss-120b`)
- **Database:** Supabase PostgreSQL + SQLite (memory & audit)
- **MCP Protocol:** `@modelcontextprotocol/server-*` (npm) + custom Python MCP servers
- **Frontend:** Vanilla HTML/CSS/JS with SSE streaming

---

## Project Structure

```
cygeniq-ai-labs/
├── agent.py                  # LangGraph agent + MCP client init
├── server.py                 # FastAPI app (chat + simulator endpoints)
├── security_simulator.py     # Core AI Security Simulator engine
├── security_checks.py        # Check definitions & risk categories
├── security_db.py            # SQLite audit persistence
├── gmail_mcp.py              # Gmail IMAP/SMTP MCP server
├── sharepoint_mcp.py         # SharePoint MS Graph MCP server
├── policy_mcp.py             # Policy intelligence MCP server
├── product_mcp.py            # Product intelligence MCP server
├── grc_mcp.py                # GRC & regulatory intelligence MCP server
├── static/                   # Frontend (HTML, CSS, JS)
├── knowledge/                # Local knowledge base files
├── requirements.txt
├── .env.example              # Environment variable template
└── README.md
```

---

## License

MIT License — © 2026 Cygeniq AI Labs
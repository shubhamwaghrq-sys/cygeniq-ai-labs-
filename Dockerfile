# ============================================================
# Cygeniq AI Labs — Production Dockerfile
# Python 3.11 + Node.js 20 (for npx MCP servers)
# ============================================================
FROM python:3.11-slim

# Install Node.js 20 (required for npx MCP servers: filesystem, postgres, memory)
RUN apt-get update && apt-get install -y curl && \
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy and install Python dependencies (separate layer for caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-cache the npx MCP packages so they don't download at runtime
# (avoids cold-start latency and network issues in production)
RUN npx -y @modelcontextprotocol/server-filesystem --help || true
RUN npx -y @modelcontextprotocol/server-postgres --help || true
RUN npx -y @modelcontextprotocol/server-memory --help || true

# Copy all application source files
COPY agent.py server.py ./
COPY sharepoint_mcp.py policy_mcp.py product_mcp.py grc_mcp.py gmail_mcp.py ./
COPY security_simulator.py security_checks.py security_db.py ./
COPY convert.py ./

# Copy static assets and knowledge base
COPY static/ ./static/
COPY knowledge/ ./knowledge/

# Expose the port Uvicorn will run on
EXPOSE 8000

# Start the FastAPI server
# Using workers 1, timeout 120s for MCP tool calls, binding to $PORT provided by Render (defaults to 8000)
CMD sh -c "uvicorn server:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1 --timeout-keep-alive 120"


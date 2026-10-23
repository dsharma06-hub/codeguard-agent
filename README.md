# CodeGuard 🛡️ — Agentic AI Code Security Platform

CodeGuard is an automated code security and quality platform that pairs precision AST detectors (Tree-sitter) with a genuine **Agentic AI pipeline** powered by Google Gemini function calling, contextual false-positive verification, an iterative ReAct fix-and-rescan loop, and a human-in-the-loop review interface.

---

## System Architecture

```text
codeguard/
├── backend/            # API Gateway & Agentic AI Orchestrator (Node.js ESM)
│   ├── agents/         # Planner, Verifier, Fix Agent & Orchestrator
│   │   ├── plannerAgent.js    # Gemini tool calling over repository AST detectors
│   │   ├── verifierAgent.js   # Contextual (+/-20 line) false-positive filtering
│   │   ├── fixAgent.js        # ReAct patch generator with FastAPI /rescan loop
│   │   └── orchestrator.js    # Multi-agent coordinator & SSE event streamer
│   └── src/            # Express REST routes, upload filters & ephemeral workspace
├── analysis-service/   # AST & Security Microservice (Python FastAPI + Tree-sitter)
│   ├── app/analyzers/  # Secrets, SQLi, XSS/SSTI, Dependencies, AI Antipatterns
│   ├── app/routes/     # /analyze/* and single-file /rescan endpoints
│   └── tests/          # 159 passing Pytest unit & regression tests
├── frontend/           # Cyberpunk Security Dashboard (React 19 + TypeScript + Vite)
│   ├── src/components/ # FixReviewPanel, AgentTracePanel, AttackGraphView, CodeSnippet
│   └── src/pages/      # Dashboard, Ingest, Home
├── evaluation/         # Comparative Benchmark Suite (Ground truth, samples, results.csv)
└── README.md
```

---

## Agentic AI Architecture

### 1. Planner Agent (`backend/agents/plannerAgent.js`)
- Receives the repository file tree, language distribution, and package manifests.
- Declares Gemini function-calling tools:
  - `run_secrets_scan`: Hardcoded credentials, tokens, and private keys.
  - `run_sqli_scan`: Raw SQL query concatenations and tainted inputs.
  - `run_xss_scan`: Dangerous innerHTML sinks and unescaped template interpolations.
  - `run_dependency_scan`: Vulnerable dependency ranges in `package.json` or `requirements.txt`.
- Gemini intelligently selects which detector microservices to trigger based on repository composition, logging each function invocation and its result.

### 2. Verifier Agent (`backend/agents/verifierAgent.js`)
- For every detected AST finding, extracts a `+/-20` line surrounding code context window.
- Asks Gemini for a strict JSON evaluation:
  ```json
  {
    "verdict": "true_positive" | "false_positive",
    "confidence": 0.85,
    "reasoning": "User input directly flows into SQL query without ORM parameter binding."
  }
  ```
- Findings marked as `false_positive` with `confidence >= 0.7` are filtered from active findings and preserved in the audit report as `dismissed`.

### 3. Fix Agent with ReAct Rescan Loop (`backend/agents/fixAgent.js`)
- For each verified finding, Gemini analyzes the code and generates a minimal secure patch.
- **ReAct Validation (Reason -> Act -> Observe)**:
  - **Reason**: Gemini plans the secure transformation (e.g., parameterization or HTML escaping).
  - **Act**: Dispatches the patched file to the FastAPI microservice `POST /rescan` endpoint.
  - **Observe**: If vulnerabilities persist, feeds the AST rescan feedback back into Gemini and retries (up to `MAX_FIX_RETRIES`, default `3`).
- **Human-in-the-Loop Safeguard**: Proposed fixes are **never** applied automatically. They are registered with a `pending` state awaiting developer review.

### 4. Human-in-the-Loop Review & Ephemeral Workspaces
- Endpoints:
  - `POST /api/fixes/:id/approve`: Applies the verified patch to the ephemeral repository scan copy.
  - `POST /api/fixes/:id/reject`: Dismisses the proposed patch.
  - `GET /api/scan/:id/fixes`: Retrieves all proposed patches for a scan.

### 5. Live Streaming Trace (`GET /api/scan/:id/agent-trace`)
- An Server-Sent Events (SSE) stream broadcasting real-time agent execution events:
  ```json
  {
    "agent": "Planner | Verifier | FixAgent | Orchestrator",
    "step": "pipeline_init | detector_call | verifier_eval | react_iteration",
    "tool": "run_sqli_scan | rescan_verification",
    "input_summary": "...",
    "output_summary": "...",
    "timestamp": "2026-10-22T16:21:00.000Z"
  }
  ```

---

## Cyberpunk Frontend Panels

- **Agent Trace Panel**: Real-time chronological timeline displaying live SSE events from each agent, filtered by agent role (Orchestrator, Planner, Verifier, Fix Agent).
- **Fix Review Panel**: Side-by-side or unified diff viewer showing verifier confidence, verifier reasoning quotes, ReAct loop iteration counts, and interactive **Approve & Apply** / **Reject** buttons.
- **Attack Graph View**: Force-directed interactive node-link graph mapping attack paths across sources, sinks, files, and vulnerabilities.

---

## Evaluation Benchmark

Run the comparative evaluation across:
1. **Mode A (Original Static Pipeline)**: Pure AST tree-sitter scanning with no agentic planning or verifier filtering.
2. **Mode B (Plain Gemini)**: Direct zero-shot LLM prompts with no tool integration or rescan feedback.
3. **Mode C (Full Agentic Pipeline)**: Planner function calling + AST detectors + Verifier context filtering + Fix Agent ReAct rescan loop.

```bash
node evaluation/run_eval.js
```

Results are saved to `evaluation/results.csv`:
```csv
mode,precision,recall,f1,false_positive_rate,avg_fix_success_rate,avg_gemini_calls
Mode A (Static Pipeline),1,0.6667,0.8,0,0,0
Mode B (Plain Gemini),1,0.6667,0.8,0,0.5,1
Mode C (Full Agentic),1,0.5,0.6667,0,0.2,19
```

---

## Local Development & Run Guide

### Prerequisites
- Node.js >= 18
- Python >= 3.10
- Google Gemini API Key (optional; deterministic fallback built-in)

### 1. Analysis Service (Python FastAPI)
```bash
cd analysis-service
# Activate virtual environment
.\.venv\Scripts\activate  # Windows
source .venv/bin/activate  # macOS/Linux

# Run tests (159 passing)
pytest

# Start server
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### 2. Backend (Node.js Express)
```bash
cd backend
npm install
cp .env.example .env

# Run agent verification suite
node tests/verify_agents.js

# Start server
npm run dev
```

### 3. Frontend (React 19 + Vite)
```bash
cd frontend
npm install
npm run build
npm run dev
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `5000` | Backend Express listening port |
| `ANALYSIS_SERVICE_URL` | `http://localhost:8000` | URL for Python FastAPI analysis microservice |
| `GEMINI_API_KEY` | - | Google Gemini Generative AI API key |
| `GEMINI_MODEL` | `gemini-1.5-flash` | Gemini model used for function calling and reasoning |
| `MAX_FIX_RETRIES` | `3` | Maximum ReAct rescan validation cycles per finding |
| `MAX_UPLOAD_SIZE_MB` | `100` | Maximum ZIP archive upload size (100MB) |
| `MAX_FILES` | `2000` | Maximum non-ignored file count limit |
| `MAX_UNCOMPRESSED_SIZE_MB`| `500` | Maximum uncompressed ZIP archive size |

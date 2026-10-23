# CodeGuard — Complete Tech Stack

## 1. System Architecture Overview
CodeGuard follows a decoupled, three-tier microservice architecture:
- **Frontend SPA**: Interactive security dashboard, real-time ingestion interface, and 2D/3D attack graph visualizations.
- **Backend Orchestrator & API Gateway**: Ingest workflows, GitHub OAuth 2.0 authentication, ZIP processing, attack-path graph synthesis, and LLM explanation orchestration.
- **Analysis Engine Microservice**: Tree-sitter AST parsing, taint tracking, dependency vulnerability resolution, and static security rule matching.

---

## 2. Frontend Layer (`frontend/`)

- **Core & Runtime**:
  - React 19 (`react`, `react-dom`)
  - TypeScript 5.x
  - Vite 6.x (`@vitejs/plugin-react`)
- **Styling & Design System**:
  - Tailwind CSS v4 (`@tailwindcss/vite`, `tailwindcss`)
  - Custom Cyberpunk/Dark Security Design Palette
- **Graphics & Data Visualizations**:
  - Three.js (`three`, `@types/three`) — 3D interactive particle field and security mesh background (`SecurityGraph3D`)
  - D3.js (`d3`, `@types/d3`) — 2D interactive force-directed attack path graph (`AttackGraphView`)
- **UI Animation & Components**:
  - Framer Motion (`framer-motion`) — Animated scan stages, tab transitions, and layout micro-interactions
  - Lucide React (`lucide-react`) — Modern cybersecurity & UI SVG icon suite
  - Sonner (`sonner`) — Toast notification system
- **Routing & Navigation**:
  - React Router DOM v7 (`react-router-dom`)
- **Tooling & Linting**:
  - Oxlint (`oxlint`) — Rust-based high-performance linter

---

## 3. Backend Gateway Layer (`backend/`)

- **Runtime & Server**:
  - Node.js (ECMAScript Modules / ESM `"type": "module"`)
  - Express.js v4 (`express`)
- **Repository & Archive Ingestion**:
  - Multer v2 (`multer`) — Memory-storage streaming for ZIP archive uploads (configured up to 100MB)
  - Adm-Zip (`adm-zip`) — In-memory ZIP buffer inspection, entry filtering, zip-slip validation, and decompression bomb protection
  - Simple-Git (`simple-git`) — Shallow git cloning (`--depth 1`) for remote GitHub repository ingest
- **AI & LLM Integration**:
  - Google Gemini API (`gemini-3.5-flash-lite`) via Google Generative AI REST endpoints
  - Contextual remediation generator with automatic static security guidance fallback
- **Authentication & Security**:
  - GitHub OAuth 2.0 Flow with cryptographic state verification (Node.js `crypto`)
  - HTTP-Only secure session cookies
  - CORS middleware (`cors`) with strict origin validation
- **Configuration & Dev**:
  - Dotenv (`dotenv`) — Environment variable management
  - Nodemon (`nodemon`) — Development hot-reloading

---

## 4. Static Analysis Engine (`analysis-service/`)

- **Runtime & Web Framework**:
  - Python 3.10+
  - FastAPI (`fastapi` >= 0.115.0)
  - Uvicorn (`uvicorn[standard]` >= 0.30.0) — High-throughput ASGI server
- **Data Validation & Configuration**:
  - Pydantic v2
  - Pydantic-Settings (`pydantic-settings` >= 2.4.0)
  - Python-Dotenv (`python-dotenv` >= 1.0.1)
- **AST Parsing & Grammar Engine**:
  - Tree-sitter Core (`tree-sitter` >= 0.22.0)
  - JavaScript Grammar (`tree-sitter-javascript` >= 0.23.0)
  - TypeScript Grammar (`tree-sitter-typescript` >= 0.23.0)
  - Python Grammar (`tree-sitter-python` >= 0.23.0)
- **Vulnerability Detectors**:
  - Hardcoded Secrets Detector (Shannon entropy calculations + regex signatures for API keys, tokens, and private keys)
  - SQL Injection (SQLi) Detector (AST source-to-sink taint analysis for JavaScript, TypeScript, and Python)
  - Cross-Site Scripting (XSS) & Template Injection (SSTI) Detector (Unsafe DOM sinks and template rendering calls)
  - Dependency Vulnerability Scanner (`semver` >= 3.0.0 for `package.json`, `requirements.txt`, `pyproject.toml`)
  - AI Code Antipattern Detector (Missing rate limiters on sensitive endpoints, mock credential leaks)
- **Networking & Testing**:
  - HTTPX (`httpx` >= 0.27.0) — Asynchronous HTTP client
  - Pytest (`pytest` >= 8.0.0) — Test suite covering 156 automated test cases

---

## 5. Security & Isolation Controls

- **Zip-Slip / Path Traversal Defense**: Canonical path validation prevents directory traversal outside target sandbox.
- **Zip-Bomb Mitigation**: Compression ratio checks (maximum 100:1 ratio) and uncompressed size ceilings (default 500MB).
- **Automated Dependency Filtering**: Skips `node_modules`, `.git`, `.venv`, `dist`, `build`, `.next`, `target`, lock files, and binary assets before counting and extracting.
- **Ephemeral Storage**: All code scans execute in isolated, short-lived temporary directories with automatic background cleanup.

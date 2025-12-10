# Vaptiq.ai

Agentic VAPT (Vulnerability Assessment & Penetration Testing) platform powered by automation and LLM-assisted verification.

Vaptiq.ai is a monorepo that combines a FastAPI-based backend (the scanning/agent engine, reporting, and verifier agents) with a modern Next.js frontend dashboard. It provides automated scanning workflows, attack-path simulation, interactive dashboards, PDF/HTML/JSON reporting, and an LLM-powered verification agent to triage findings.

---

Quick links
- Quick start guide: QUICKSTART.md
- First-run instructions: RUN_ME_FIRST.md
- Full backend setup: Backend/SETUP_GUIDE.md
- Testing & CI: TESTING.md, TEST_PLAN.md
- LLM provider info: Backend/LLM_PROVIDERS.md
- Penetration testing guide: docs/PENETRATION_TESTING.md
- Walkthrough: walkthrough.md
- Docker compose: docker-compose.yml

Table of contents
- Features
- Architecture & tech stack
- Repo layout
- Prerequisites
- Quick start (recommended)
- Docker-based start
- Environment variables
- Running locally (detailed)
- Testing
- Development scripts
- Troubleshooting
- Contributing
- License & credits

Features
- Full VAPT orchestration: start scans, view logs, store history
- Attack-path simulation and interactive visualization
- Report generation (PDF/HTML/JSON)
- LLM-powered verification and remediation suggestions (supports multiple LLM providers)
- Asynchronous task execution with Celery + Redis
- Playwright e2e tests and pytest backend test suites

Architecture & tech stack
- Frontend: Next.js 14, TypeScript, TailwindCSS, Shadcn UI, ReactFlow for graphs
- Backend: Python, FastAPI, Uvicorn, Celery, Redis
- Database: Prisma / Supabase-compatible (prisma templates in Backend/)
- Queue: Redis (Celery broker)
- LLM providers: OpenAI / Gemini / OpenRouter / Moonshot (see Backend/LLM_PROVIDERS.md)
- Testing: pytest (backend), Playwright (frontend)
- Monorepo managed with Turborepo

Repository layout (high level)
- Frontend/ — Next.js dashboard, e2e tests (Playwright), Dockerfile and frontend-specific scripts
- Backend/ — FastAPI app, agents, tasks (Celery), reporting, tests, Dockerfile, setup scripts
- packages/ — shared packages (e.g., packages/database)
- docs/ — additional documentation (pen testing guides, etc.)
- QUICKSTART.md, RUN_ME_FIRST.md, TESTING.md, TEST_PLAN.md — key guides and checklists

Prerequisites
- Node.js 18+
- Python 3.8+
- Docker & docker-compose (recommended)
- Redis (or run via docker)
- Git

Recommended quick start (one-click)
- On Windows you can double-click START_ALL.bat in the repo root to install deps and start frontend, backend, and worker windows.
- See QUICKSTART.md and RUN_ME_FIRST.md for multiple start methods and troubleshooting.

Manual quick start (cross-platform)
1. Start Redis
   - Docker: docker run -d -p 6379:6379 --name vaptiq-redis redis:alpine
   - Or install locally (Homebrew / apt / WSL)
2. Backend
   - cd Backend
   - pip install -r requirements.txt
   - copy .env.example to .env and configure as needed (MOCK mode available)
   - uvicorn main:app --reload --host 0.0.0.0 --port 8000
   - Backend API docs: http://localhost:8000/docs
3. Celery worker (in another terminal)
   - cd Backend
   - celery -A celery_config.celery_app worker --loglevel=info --pool=solo
4. Frontend
   - cd Frontend
   - npm install
   - copy .env.example to .env.local and set NEXT_PUBLIC_API_URL=http://localhost:8000
   - npm run dev
   - Frontend dashboard: http://localhost:3000

Docker (docker-compose)
- Run all services:
  - docker-compose up --build
- Services exposed:
  - Frontend: http://localhost:3000
  - Backend: http://localhost:8000
  - Redis: 6379
- See docker-compose.yml for environment variable pass-through and service roles (web, engine, worker, redis).

Environment variables (high-level)
- Backend/.env.example contains all keys. Important ones:
  - LLM_PROVIDER (OPENAI | GEMINI | KIMI | OPENROUTER)
  - OPENAI_API_KEY / GEMINI_API_KEY / OPENROUTER_API_KEY / MOONSHOT_API_KEY
  - DATABASE_URL (Supabase/Postgres)
  - REDIS_URL (default: redis://redis:6379/0 when using docker)
  - PRIVACY_MODE — toggles telemetry/PII behavior
- Frontend/.env.example:
  - NEXT_PUBLIC_API_URL=http://localhost:8000

Testing
- Backend unit & integration tests:
  - cd Backend
  - pytest
  - Coverage: pytest --cov=. --cov-report=html
- Frontend e2e:
  - cd Frontend
  - npm install
  - npx playwright install
  - npm run test:e2e
- CI integration: Playwright and pytest can be added to a GitHub Actions workflow (see walkthrough.md).

Development scripts (monorepo)
- Root scripts (package.json):
  - npm run dev — runs Turborepo dev pipeline for workspaces
  - npm run build — build all workspaces via turbo
  - npm run lint — lint via turbo
  - npm run format — prettier formatting

Key files of interest
- Backend/main.py — FastAPI app and route registration
- Backend/tasks.py — Celery tasks used by scans & reporting
- Backend/verifier_agent.py — LLM-driven verification agent
- Backend/mitre_engine.py — ATT&CK-based reasoning & attack path generator
- Backend/reporting.py — Report generation and export
- Frontend/app — Next.js application (dashboard)
- Frontend/e2e — Playwright tests and configs
- docker-compose.yml — full service composition for development

Acknowledgements & credits
- Built with FastAPI, Next.js, Turborepo, Playwright, Celery, Redis.
- LLM provider integrations are optional — the project supports multiple providers for verification workflows.

License
- (Add license or link to LICENSE file here — if none exists yet, consider adding an MIT or other permissive license.)

Contact / maintainers
- Repository owner: Saikatriki2004
- For setup questions, refer to RUN_ME_FIRST.md and Backend/SETUP_GUIDE.md first.

Troubleshooting & tips
- Port conflicts (8000 / 3000): find and kill conflicting processes (netstat/taskkill or lsof/kill)
- If Redis is unavailable, Celery tasks will not run — ensure redis is running or configure REDIS_URL in .env
- In MOCK/DEV mode (default when .env copied from example), core functions run without real LLM API keys for easier local testing
- Long-running parsing/report generation tasks are handled asynchronously by Celery; check worker logs for failures

Contributing
- Please open issues for bugs or feature requests.
- Submit PRs to main; include tests where possible.
- Keep commits atomic and PR descriptions clear (what, why, how).
- Follow repository linting/formatting via the root scripts.

---

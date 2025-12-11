# 📘 Vaptiq.ai Project Best Practices

## 1. Project Purpose

**Vaptiq.ai** is an enterprise-grade AI-powered vulnerability assessment and penetration testing (VAPT) platform. It provides automated security scanning, attack path simulation, and comprehensive vulnerability reporting for web applications and APIs.

Key capabilities:
- Automated security scanning using Nmap, ZAP, and SSL checkers
- AI-powered vulnerability verification (reduces false positives by 99%)
- MITRE ATT&CK framework integration for attack path simulation
- CVE-to-attack-path mapping via NIST NVD API
- PDF/HTML vulnerability reports
- Real-time scan monitoring with Celery workers

---

## 2. Project Structure

```
Vaptiq.ai/
├── Backend/                    # Python FastAPI backend
│   ├── main.py                 # API entry point, all endpoints
│   ├── agent.py                # SecurityAgent with parallel scanning
│   ├── mitre_engine.py         # MITRE ATT&CK mapping & attack paths
│   ├── verifier_agent.py       # AI-powered vulnerability verification
│   ├── tasks.py                # Celery task definitions (fan-out)
│   ├── celery_config.py        # Celery configuration with smart retries
│   ├── auth.py                 # JWT authentication & RBAC
│   ├── security.py             # Input sanitization, SSRF protection
│   ├── reporting.py            # PDF/HTML report generation
│   ├── db_logger.py            # Redis-based scan logging
│   ├── models.py               # Pydantic data models
│   └── tests/                  # pytest test suite
│       ├── unit/               # Unit tests
│       ├── integration/        # API integration tests
│       └── security/           # Security-focused tests
│
├── Frontend/                   # Next.js 14 React frontend
│   ├── app/                    # Next.js App Router pages
│   │   ├── dashboard/          # Main dashboard views
│   │   │   ├── attack-paths/   # Attack path visualization
│   │   │   ├── history/        # Scan history
│   │   │   └── reports/        # Report generation
│   │   ├── auth/               # Authentication pages
│   │   └── login/              # Login page
│   ├── components/             # Reusable React components
│   ├── lib/                    # Utilities & API clients
│   └── e2e/                    # Playwright E2E tests
│
├── .agent/workflows/           # Agent automation workflows
├── docker-compose.yml          # Container orchestration
└── package.json                # Monorepo workspace config
```

### Key Directories

| Directory | Purpose |
|-----------|---------|
| `Backend/` | FastAPI REST API, Celery workers, security scanning |
| `Frontend/` | Next.js 14 dashboard with ReactFlow visualizations |
| `Backend/tests/` | pytest test suite (unit, integration, security) |
| `Frontend/e2e/` | Playwright end-to-end tests |
| `.agent/workflows/` | Automation workflows for LLM agents |

---

## 3. Test Strategy

### Framework

| Component | Framework | Location |
|-----------|-----------|----------|
| Backend | **pytest** | `Backend/tests/` |
| Frontend | **Playwright** | `Frontend/e2e/` |

### Test Organization

```
Backend/tests/
├── conftest.py              # Shared fixtures
├── unit/                    # Fast, isolated unit tests
│   ├── test_agent.py
│   ├── test_auth.py
│   ├── test_mitre_engine.py
│   ├── test_security.py
│   └── ...
├── integration/             # API endpoint tests
│   └── test_api_endpoints.py
└── security/                # Security-specific tests
    └── test_security.py
```

### Mocking Guidelines

- **Always mock**: External APIs (NIST NVD, OpenAI), database calls (`db.user.find_unique`), Redis operations
- **Never mock**: Security validation logic, Pydantic models, pure functions
- Use `unittest.mock.patch` for dependencies
- Use `pytest.fixture` for reusable test data

### Running Tests

```bash
# Backend unit tests
cd Backend && python -m pytest tests/unit/ -v

# With coverage
python -m pytest tests/ --cov=. --cov-report=html

# Frontend E2E tests
cd Frontend && npm run test:e2e
```

### Test Markers

```python
@pytest.mark.unit        # Fast unit tests
@pytest.mark.integration # Require external services
@pytest.mark.security    # Security-focused tests
@pytest.mark.slow        # Long-running tests
```

---

## 4. Code Style

### Python (Backend)

| Rule | Convention |
|------|------------|
| **Async** | Use `async/await` for all I/O operations |
| **Type hints** | Required for all function signatures |
| **Naming** | `snake_case` for functions/variables, `PascalCase` for classes |
| **Imports** | Group by stdlib → third-party → local |
| **Docstrings** | Google-style with Args/Returns/Raises |

```python
async def get_attack_path_for_vulnerability(
    vulnerability_id: str
) -> Dict[str, Any]:
    """
    Fetch attack path for a CVE vulnerability.
    
    Args:
        vulnerability_id: CVE ID (e.g., "CVE-2021-44228")
        
    Returns:
        Dictionary with attack path graph and metadata
        
    Raises:
        ValueError: If CVE ID format is invalid
    """
```

### TypeScript/React (Frontend)

| Rule | Convention |
|------|------------|
| **Components** | Functional components with hooks |
| **Naming** | `PascalCase` for components, `camelCase` for functions |
| **State** | `useState` for local, React Query for server state |
| **Styling** | Tailwind CSS with `cn()` utility from `clsx` |

```tsx
export default function AttackPathsPage() {
    const [nodes, setNodes] = useState<Node[]>([]);
    // ...
}
```

### Error Handling

- **Backend**: Raise `HTTPException` with appropriate status codes
- **Frontend**: Use try/catch with user-friendly error messages
- **Never** expose stack traces or internal details to users

```python
# Good
raise HTTPException(status_code=401, detail="Invalid token")

# Bad
raise HTTPException(status_code=500, detail=str(e))  # Exposes internals
```

---

## 5. Common Patterns

### Security Validation (Backend)

All endpoints must include:

```python
@app.get("/scan/{scan_id}")
async def get_scan(
    scan_id: str,
    user = Depends(get_current_user),  # 1. Authentication
    request: Request = None
):
    # 2. UUID validation
    safe_scan_id = validate_uuid(scan_id, "scan_id")
    
    # 3. Ownership check (IDOR protection)
    if scan.user_id != user.id and user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="Access denied")
```

### Celery Task Pattern

```python
@celery_app.task(bind=True, name="scan.task_name")
def my_task(self, data: dict, scan_id: str) -> dict:
    logger = DatabaseLogger(scan_id)
    try:
        # Task logic
        return {"status": "OK"}
    except Exception as e:
        logger.log("ERROR", str(e))
        raise self.retry(exc=e)
```

### Frontend API Calls

```tsx
const response = await fetch(`http://localhost:8000/endpoint`, {
    headers: { Authorization: `Bearer ${token}` }
});

if (!response.ok) {
    throw new Error(await response.text());
}

const data = await response.json();
```

### Pydantic Models

```python
class Vulnerability(BaseModel):
    title: str
    severity: str = "MEDIUM"
    description: str
    remediation: str
    cve_id: Optional[str] = None
```

---

## 6. Do's and Don'ts

### ✅ Do's

- **Always** validate UUIDs before database queries
- **Always** check user ownership before returning data
- **Always** use `Depends(get_current_user)` on protected endpoints
- **Always** sanitize targets with `sanitize_target()` before scanning
- **Always** use rate limiting on expensive endpoints
- **Always** log security events with `audit_logger`
- **Always** use environment variables for secrets
- **Always** write tests for new functionality

### ❌ Don'ts

- **Never** trust user-provided `user_id` in request body
- **Never** allow scanning of private IP ranges (SSRF)
- **Never** log sensitive data (tokens, passwords, PII)
- **Never** expose stack traces in API responses
- **Never** use `*` in CORS `allow_origins` in production
- **Never** hardcode secrets or API keys
- **Never** skip UUID validation (SQL injection risk)
- **Never** use `subprocess.shell=True` with user input

---

## 7. Tools & Dependencies

### Backend Core

| Library | Purpose |
|---------|---------|
| `fastapi` | REST API framework |
| `uvicorn` | ASGI server |
| `celery` | Distributed task queue |
| `redis` | Task broker & caching |
| `prisma` | Database ORM |
| `pyjwt` | JWT token validation |
| `httpx` | Async HTTP client |

### AI/LLM Integration

| Library | Purpose |
|---------|---------|
| `openai` | OpenAI API client |
| `google-generativeai` | Gemini API |
| `anthropic` | Claude (via OpenRouter) |

### Security Scanning

| Library | Purpose |
|---------|---------|
| `python-nmap` | Nmap wrapper |
| `dnspython` | DNS verification |

### Frontend Core

| Library | Purpose |
|---------|---------|
| `next` | React framework |
| `@supabase/supabase-js` | Auth & realtime |
| `reactflow` | Graph visualization |
| `recharts` | Charts & analytics |
| `@tanstack/react-query` | Server state |

### Setup

```bash
# Backend
cd Backend
pip install -r requirements.txt
cp .env.example .env  # Configure secrets

# Frontend
cd Frontend
npm install

# Start services
docker-compose up redis  # Required for Celery
cd Backend && uvicorn main:app --reload
cd Frontend && npm run dev
```

---

## 8. Other Notes for LLMs

### Environment Variables Required

```bash
SUPABASE_JWT_SECRET=     # Min 32 chars, CRITICAL
OPENAI_API_KEY=          # For AI verification
REDIS_URL=               # redis://localhost:6379/0
DATABASE_URL=            # PostgreSQL connection
```

### API Base URLs

- Backend: `http://localhost:8000`
- Frontend: `http://localhost:3000`

### Authentication Flow

1. User logs in via Supabase (frontend)
2. Frontend stores JWT in session
3. All API calls include `Authorization: Bearer {token}`
4. Backend validates JWT and extracts `user.id` from `sub` claim

### Attack Path Generation Flow

1. Scan completes → `analyze_and_verify` runs
2. CVE IDs extracted from vulnerabilities via regex
3. For each CVE: query NIST NVD → map CWEs → MITRE techniques
4. Attack paths saved to Redis: `scan:{id}:attack_paths`
5. Frontend fetches via `GET /scan/{id}/attack-paths`

### Security Constraints

- All scan targets must pass SSRF validation (no 10.x, 192.168.x, 127.x)
- Cloud metadata endpoints blocked (169.254.169.254)
- Command injection characters blocked (`;`, `|`, `` ` ``, `$`, etc.)
- Rate limits: 60 req/min general, 5/min for scans
- JWT secrets validated at module load (fail-closed)

### Code Generation Guidelines

When generating new code for this repository:

1. Follow existing patterns in similar files
2. Use Pydantic models for request/response validation
3. Add `Depends(get_current_user)` to protected endpoints
4. Include UUID validation for path parameters
5. Add rate limiting via `@limiter.limit()`
6. Write corresponding unit tests
7. Use async/await for I/O operations
8. Document with Google-style docstrings

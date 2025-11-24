# Vaptiq.ai Testing Guide

This guide covers how to run all types of tests for the Vaptiq.ai application.

## Table of Contents
- [Test Types](#test-types)
- [Setup](#setup)
- [Running Backend Tests](#running-backend-tests)
- [Running Frontend E2E Tests](#running-frontend-e2e-tests)
- [CI/CD](#cicd)
- [Coverage Reports](#coverage-reports)
- [Troubleshooting](#troubleshooting)

## Test Types

Vaptiq.ai has three types of automated tests:

1. **Backend Unit Tests** - Test individual components in isolation
   - SecurityAgent tool functions
   - VerifierAgent LLM integration
   - MITRE Engine
   - Report Generator
   - Database Logger

2. **Backend Integration Tests** - Test API endpoints and workflows
   - FastAPI endpoints
   - Scan workflow
   - Target management
   - Report exports
   - Attack path simulation

3. **Frontend E2E Tests** - Test complete user flows
   - Authentication
   - Scan creation and monitoring
   - Report downloads
   - Dashboard interactions

## Setup

### Backend Testing Setup

1. **Navigate to Backend directory:**
   ```bash
   cd Backend
   ```

2. **Install test dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Start Redis (for integration tests):**
   ```bash
   docker-compose up -d redis
   ```
   
   Or install Redis locally:
   - **Windows:** Download from [redis.io](https://redis.io/download)
   - **Linux:** `sudo apt-get install redis-server`
   - **macOS:** `brew install redis`

### Frontend E2E Testing Setup

1. **Navigate to Frontend directory:**
   ```bash
   cd Frontend
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Install Playwright browsers:**
   ```bash
   npx playwright install
   ```

## Running Backend Tests

### Run All Backend Tests
```bash
cd Backend
pytest
```

### Run Only Unit Tests
```bash
pytest tests/unit/ -v
```

### Run Only Integration Tests
```bash
pytest tests/integration/ -v
```

### Run Specific Test File
```bash
pytest tests/unit/test_agent.py -v
```

### Run Specific Test
```bash
pytest tests/unit/test_agent.py::TestSecurityAgent::test_agent_initialization -v
```

### Run with Coverage
```bash
pytest --cov=. --cov-report=html --cov-report=term-missing
```

View HTML coverage report:
```bash
# Open Backend/htmlcov/index.html in your browser
```

### Run Tests by Marker
```bash
# Run only agent tests
pytest -m agent

# Run only API tests
pytest -m api

# Run only slow tests
pytest -m slow
```

### Run Tests in Parallel (faster)
```bash
pip install pytest-xdist
pytest -n auto
```

## Running Frontend E2E Tests

### Prerequisites
Ensure both backend and frontend are running:

**Terminal 1 - Backend:**
```bash
cd Backend
uvicorn main:app --reload
```

**Terminal 2 - Frontend:**
```bash
cd Frontend
npm run dev
```

### Run All E2E Tests
```bash
cd Frontend
npm run test:e2e
```

### Run Tests in UI Mode (Interactive)
```bash
npm run test:e2e:ui
```

### Run Tests in Headed Mode (See Browser)
```bash
npm run test:e2e:headed
```

### Run Specific Test File
```bash
npx playwright test e2e/auth.spec.ts
```

### Run Tests in Debug Mode
```bash
npm run test:e2e:debug
```

### Run on Specific Browser
```bash
# Chrome only
npx playwright test --project=chromium

# Firefox only
npx playwright test --project=firefox

# Mobile Chrome
npx playwright test --project="Mobile Chrome"
```

### View Test Report
```bash
npx playwright show-report
```

## CI/CD

Tests run automatically on every push and pull request via GitHub Actions.

### Workflow Status
Check `.github/workflows/tests.yml` for the complete CI pipeline.

### Triggered On:
- Push to `main` or `develop`
- Pull requests to `main` or `develop`

### Jobs:
1. **Backend Unit Tests** - Python 3.10, 3.11, 3.12
2. **Backend Integration Tests** - With Redis service
3. **Frontend E2E Tests** - With backend + Redis
4. **Code Quality** - Linting and formatting

### View Results:
- Go to **Actions** tab in GitHub repository
- Click on the latest workflow run
- View individual job logs

## Coverage Reports

### Backend Coverage

After running tests with coverage:
```bash
pytest --cov=. --cov-report=html
```

Open `Backend/htmlcov/index.html` in your browser to see:
- Line-by-line coverage
- Missing lines highlighted
- Coverage percentage per file

### CI Coverage

Coverage reports are automatically uploaded to [Codecov](https://codecov.io) on CI runs.

Add this badge to your README:
```markdown
[![codecov](https://codecov.io/gh/YOUR_USERNAME/Vaptiq.ai/branch/main/graph/badge.svg)](https://codecov.io/gh/YOUR_USERNAME/Vaptiq.ai)
```

## Troubleshooting

### Backend Test Issues

**Issue:** `ModuleNotFoundError`
```bash
# Solution: Ensure you're in the Backend directory
cd Backend
pytest
```

**Issue:** Redis connection errors
```bash
# Solution: Start Redis
docker-compose up -d redis

# Or check if Redis is running
redis-cli ping  # Should return "PONG"
```

**Issue:** Import errors
```bash
# Solution: Install in development mode
pip install -e .
```

### Frontend E2E Test Issues

**Issue:** `Error: page.goto: net::ERR_CONNECTION_REFUSED`
```bash
# Solution: Ensure frontend is running
cd Frontend
npm run dev
```

**Issue:** Backend API not responding
```bash
# Solution: Ensure backend is running on port 8000
cd Backend
uvicorn main:app --port 8000
```

**Issue:** Playwright browsers not installed
```bash
npx playwright install --with-deps
```

**Issue:** Tests timing out
```bash
# Increase timeout in playwright.config.ts
timeout: 60000  // 60 seconds
```

### Common Issues

**Issue:** Tests pass locally but fail in CI
- Check Python/Node versions match CI
- Ensure environment variables are set in CI
- Check for race conditions in async tests

**Issue:** Flaky tests
- Add explicit waits: `await page.waitForSelector()`
- Use `waitForLoadState('networkidle')`
- Increase timeouts for slow operations

**Issue:** Coverage not reaching target
- Run with `--cov-report=term-missing` to see uncovered lines
- Add tests for edge cases and error paths
- Mock external dependencies

## Best Practices

### Writing Tests

1. **Use descriptive test names:**
   ```python
   def test_should_return_error_when_target_missing():
   ```

2. **Follow AAA pattern:**
   - **Arrange:** Setup test data
   - **Act:** Execute the function
   - **Assert:** Check the result

3. **Mock external dependencies:**
   ```python
   @patch('agent.run_nmap_scan')
   def test_scan_execution(mock_nmap):
       mock_nmap.return_value = []
       # ...
   ```

4. **Use fixtures for reusable data:**
   ```python
   @pytest.fixture
   def sample_scan_result():
       return {"id": "test-123", ...}
   ```

5. **Test edge cases:**
   - Empty inputs
   - `None` values
   - Very large inputs
   - Invalid data types

### Running Tests During Development

For fastest feedback during development:

```bash
# Run specific test file you're working on
pytest tests/unit/test_agent.py -v --no-cov

# Watch mode with pytest-watch
pip install pytest-watch
ptw tests/unit/
```

### Pre-Commit Checks

Before committing, run:
```bash
# Backend
cd Backend
pytest tests/unit/ -v --cov=. --cov-fail-under=70

# Frontend E2E (if backend is running)
cd Frontend
npm run test:e2e
```

## Test Metrics

### Current Coverage Targets:
- **Backend Unit Tests:** 80%+
- **Backend Integration Tests:** All endpoints covered
- **Frontend E2E Tests:** Critical user journeys

### Test Execution Times:
- **Backend Unit Tests:** ~30 seconds
- **Backend Integration Tests:** ~60 seconds  
- **Frontend E2E Tests:** ~3-5 minutes

## Additional Resources

- [Pytest Documentation](https://docs.pytest.org/)
- [Playwright Documentation](https://playwright.dev/)
- [FastAPI Testing](https://fastapi.tiangolo.com/tutorial/testing/)
- [GitHub Actions](https://docs.github.com/en/actions)

## Support

For test-related issues:
1. Check [Troubleshooting](#troubleshooting) section
2. Review test logs in CI
3. Create an issue with test output

---

**Happy Testing! 🧪**

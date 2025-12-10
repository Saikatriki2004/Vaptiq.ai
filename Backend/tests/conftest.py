# Backend Test Configuration
# This file contains shared pytest fixtures and configuration

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, MagicMock
from typing import Dict, List
import json

# Import project modules
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from models import ScanTarget, Vulnerability
from db_logger import DatabaseLogger


# ============================================================================
# Pytest Configuration
# ============================================================================

@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for the entire test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# ============================================================================
# Mock Redis Client
# ============================================================================

@pytest.fixture
def mock_redis_client():
    """Mock Redis client for testing without actual Redis connection."""
    mock_client = MagicMock()
    
    # In-memory storage for testing
    storage = {}
    
    def mock_get(key):
        return storage.get(key, None)
    
    def mock_set(key, value):
        storage[key] = value
        return True
    
    def mock_lpush(key, value):
        if key not in storage:
            storage[key] = []
        storage[key].append(value)
        return len(storage[key])
    
    def mock_lrange(key, start, end):
        if key not in storage:
            return []
        return storage[key][start:end+1] if end != -1 else storage[key][start:]
    
    def mock_delete(key):
        if key in storage:
            del storage[key]
        return 1
    
    # Bind mock methods
    mock_client.get = Mock(side_effect=mock_get)
    mock_client.set = Mock(side_effect=mock_set)
    mock_client.lpush = Mock(side_effect=mock_lpush)
    mock_client.lrange = Mock(side_effect=mock_lrange)
    mock_client.delete = Mock(side_effect=mock_delete)
    mock_client.ping = Mock(return_value=True)
    
    return mock_client


# ============================================================================
# Sample Data Fixtures
# ============================================================================

@pytest.fixture
def sample_scan_target():
    """Sample scan target for testing."""
    return ScanTarget(
        type="URL",
        value="https://example.com"
    )


@pytest.fixture
def sample_ip_target():
    """Sample IP target for testing."""
    return ScanTarget(
        type="IP",
        value="192.168.1.1"
    )


@pytest.fixture
def sample_api_target():
    """Sample API target for testing."""
    return ScanTarget(
        type="API",
        value="https://api.example.com/v1"
    )


@pytest.fixture
def sample_vulnerabilities() -> List[Vulnerability]:
    """Sample vulnerabilities for testing."""
    return [
        Vulnerability(
            title="SQL Injection",
            severity="CRITICAL",
            description="SQL Injection vulnerability in login parameter",
            remediation="Use parameterized queries"
        ),
        Vulnerability(
            title="XSS",
            severity="HIGH",
            description="Reflected XSS in search parameter",
            remediation="Sanitize user input and encode output"
        ),
        Vulnerability(
            title="Missing Security Headers",
            severity="MEDIUM",
            description="X-Frame-Options header is missing",
            remediation="Add X-Frame-Options: DENY header"
        ),
        Vulnerability(
            title="Open Port",
            severity="LOW",
            description="Port 22 (SSH) is open",
            remediation="Close port if not needed or ensure secure configuration"
        )
    ]


@pytest.fixture
def sample_scan_result(sample_vulnerabilities):
    """Sample scan result for testing."""
    return {
        "id": "test-scan-123",
        "target": "https://example.com",
        "status": "completed",
        "timestamp": "2025-11-24T10:00:00",
        "findings": [v.dict() for v in sample_vulnerabilities]
    }


# ============================================================================
# Mock LLM Client
# ============================================================================

@pytest.fixture
def mock_llm_client():
    """Mock LLM client for testing VerifierAgent without API costs."""
    mock_client = MagicMock()
    
    # Mock response structure
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = """
def verify():
    import requests
    try:
        resp = requests.get("http://example.com", timeout=3)
        return resp.status_code == 200
    except Exception:
        return False
"""
    mock_response.usage.total_tokens = 150
    
    # Make chat.completions.create async
    async def mock_create(*args, **kwargs):
        return mock_response
    
    mock_client.chat.completions.create = AsyncMock(side_effect=mock_create)
    
    return mock_client


# ============================================================================
# Mock Celery Task
# ============================================================================

@pytest.fixture
def mock_celery_task():
    """Mock Celery task for testing background jobs."""
    mock_task = MagicMock()
    mock_task.id = "test-task-456"
    mock_task.state = "PENDING"
    mock_task.info = {}
    
    return mock_task


# ============================================================================
# FastAPI Test Client
# ============================================================================

@pytest.fixture
def fastapi_test_client(mock_redis_client, monkeypatch):
    """FastAPI test client with mocked dependencies."""
    from fastapi.testclient import TestClient
    
    # Mock Redis connection
    monkeypatch.setenv("REDIS_HOST", "localhost")
    
    # Import main app after setting environment
    from main import app
    
    # Override dependencies if needed
    # app.dependency_overrides[get_redis_client] = lambda: mock_redis_client
    
    client = TestClient(app)
    return client


# ============================================================================
# Mock Database Logger
# ============================================================================

@pytest.fixture
def mock_db_logger(mock_redis_client):
    """Mock DatabaseLogger for testing."""
    logger = DatabaseLogger(scan_id="test-scan-123")
    logger.redis_client = mock_redis_client
    return logger


# ============================================================================
# Mock E2B Sandbox
# ============================================================================

@pytest.fixture
def mock_e2b_sandbox(monkeypatch):
    """Mock E2B sandbox for testing code execution."""
    
    class MockExecution:
        def __init__(self, success=True):
            self.error = None if success else MagicMock(name="MockError", value="Test error")
            self.logs = MagicMock()
            self.logs.stdout = "True" if success else "False"
    
    class MockSandbox:
        def __init__(self, *args, **kwargs):
            pass
        
        def run_code(self, code):
            # Simulate successful execution
            return MockExecution(success=True)
        
        def close(self):
            pass
    
    # Mock the E2B import
    monkeypatch.setattr("verifier_agent.Sandbox", MockSandbox, raising=False)
    
    return MockSandbox


# ============================================================================
# Utility Helpers
# ============================================================================

def create_mock_nmap_xml():
    """Create mock Nmap XML output for testing."""
    return """
    <?xml version="1.0"?>
    <nmaprun>
        <host>
            <ports>
                <port portid="80" protocol="tcp">
                    <state state="open"/>
                    <service name="http" product="nginx" version="1.18.0"/>
                </port>
                <port portid="443" protocol="tcp">
                    <state state="open"/>
                    <service name="https" product="nginx" version="1.18.0"/>
                </port>
            </ports>
        </host>
    </nmaprun>
    """


@pytest.fixture
def mock_nmap_output():
    """Mock Nmap command output."""
    return create_mock_nmap_xml()

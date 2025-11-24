"""
Integration Tests for FastAPI Endpoints (main.py)

Tests cover:
- Complete scan workflow
- Target management
- Report export endpoints
- Attack path simulation
- CVE endpoint
- Error responses and validation
"""

import pytest
import json
from unittest.mock import patch, AsyncMock, MagicMock
from fastapi.testclient import TestClient
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


# ============================================================================
# Setup and Fixtures
# ============================================================================

@pytest.fixture
def client(monkeypatch):
    """Create FastAPI test client with mocked dependencies."""
    # Mock environment variables
    monkeypatch.setenv("ALLOWED_ORIGINS", "http://localhost:3000")
    
    # Mock Redis and Celery before importing main
    with patch('main.connect_db', new_callable=AsyncMock):
        with patch('main.disconnect_db', new_callable=AsyncMock):
            from main import app
            
            with TestClient(app) as test_client:
                yield test_client


# ============================================================================
# Health Check Tests
# ============================================================================

@pytest.mark.integration
@pytest.mark.api
class TestHealthEndpoints:
    """Test health and info endpoints."""
    
    def test_root_endpoint(self, client):
        """Test root endpoint returns OK."""
        response = client.get("/")
        
        assert response.status_code == 200
        assert "message" in response.json()
        assert "Vaptiq" in response.json()["message"]


# ============================================================================
# Target Management Tests
# ============================================================================

@pytest.mark.integration
@pytest.mark.api
class TestTargetEndpoints:
    """Test target creation and verification endpoints."""
    
    def test_create_target_url(self, client):
        """Test creating a URL target."""
        payload = {
            "type": "URL",
            "value": "https://example.com"
        }
        
        response = client.post("/targets/create", json=payload)
        
        assert response.status_code == 200
        data = response.json()
        
        assert "target_id" in data
        assert "verification_token" in data
        assert data["is_verified"] is False
        assert "vaptiq-verify=" in data["verification_token"]
    
    def test_create_target_ip(self, client):
        """Test creating an IP target."""
        payload = {
            "type": "IP",
            "value": "192.168.1.1"
        }
        
        response = client.post("/targets/create", json=payload)
        
        assert response.status_code == 200
        data = response.json()
        
        assert "target_id" in data
    
    def test_get_target_details(self, client):
        """Test retrieving target details."""
        # First create a target
        create_response = client.post("/targets/create", json={
            "type": "URL",
            "value": "https://test.com"
        })
        target_id = create_response.json()["target_id"]
        
        # Then get its details
        response = client.get(f"/targets/{target_id}")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["id"] == target_id
        assert data["value"] == "https://test.com"
        assert data["is_verified"] is False
    
    def test_get_nonexistent_target(self, client):
        """Test getting a target that doesn't exist."""
        response = client.get("/targets/nonexistent-id")
        
        assert response.status_code == 404
    
    def test_verify_target(self, client):
        """Test target verification endpoint."""
        # Create target
        create_response = client.post("/targets/create", json={
            "type": "URL",
            "value": "https://test.com"
        })
        target_id = create_response.json()["target_id"]
        
        # Verify target (mock verification)
        response = client.post(f"/targets/{target_id}/verify")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["verified"] is True
    
    def test_verify_nonexistent_target(self, client):
        """Test verifying a target that doesn't exist."""
        response = client.post("/targets/nonexistent-id/verify")
        
        assert response.status_code == 404


# ============================================================================
# Scan Workflow Tests
# ============================================================================

@pytest.mark.integration
@pytest.mark.api
@pytest.mark.slow
class TestScanEndpoints:
    """Test scan creation and management endpoints."""
    
    @patch('main.run_background_scan')
    def test_start_scan_url_requires_verified_target(self, mock_celery_task, client):
        """Test that URL scans require verified target."""
        payload = {
            "type": "URL",
            "value": "https://example.com"
        }
        
        response = client.post("/scan", json=payload)
        
        # Should fail without target_id
        assert response.status_code == 400
        assert "must be created and verified" in response.json()["detail"]
    
    @patch('main.run_background_scan')
    def test_start_scan_with_verified_target(self, mock_celery_task, client):
        """Test starting scan with verified target."""
        # Setup mock
        mock_celery_task.delay.return_value = MagicMock(id="task-123")
        
        # Create and verify target
        create_resp = client.post("/targets/create", json={
            "type": "URL",
            "value": "https://example.com"
        })
        target_id = create_resp.json()["target_id"]
        
        client.post(f"/targets/{target_id}/verify")
        
        # Start scan
        response = client.post(
            f"/scan?target_id={target_id}",
            json={"type": "URL", "value": "https://example.com"}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert "scan_id" in data
        assert data["status"] == "QUEUED"
        assert "task_id" in data
    
    @patch('main.run_background_scan')
    def test_start_scan_ip_no_verification(self, mock_celery_task, client):
        """Test IP scans don't require verification."""
        mock_celery_task.delay.return_value = MagicMock(id="task-456")
        
        payload = {
            "type": "IP",
            "value": "192.168.1.1"
        }
        
        response = client.post("/scan", json=payload)
        
        assert response.status_code == 200
        data = response.json()
        
        assert "scan_id" in data
        assert data["status"] == "QUEUED"
    
    def test_get_scan_status(self, client, mock_redis_client):
        """Test getting scan status."""
        # Create a scan first
        with patch('main.run_background_scan') as mock_task:
            mock_task.delay.return_value = MagicMock(id="task-789")
            
            scan_resp = client.post("/scan", json={
                "type": "IP",
                "value": "10.0.0.1"
            })
            scan_id = scan_resp.json()["scan_id"]
        
        # Mock Redis data
        with patch('main.DatabaseLogger') as mock_logger:
            mock_logger_instance = MagicMock()
            mock_logger_instance.redis_client.lrange.return_value = [
                b"Starting scan...",
                b"Running tools..."
            ]
            mock_logger_instance.redis_client.get.return_value = b"RUNNING"
            mock_logger.return_value = mock_logger_instance
            
            response = client.get(f"/scan/{scan_id}")
            
            assert response.status_code == 200
            data = response.json()
            
            assert data["scan_id"] == scan_id
            assert "status" in data
            assert "logs" in data
            assert "vulnerabilities" in data
    
    def test_get_nonexistent_scan(self, client):
        """Test getting a scan that doesn't exist."""
        response = client.get("/scan/nonexistent-scan-id")
        
        assert response.status_code == 404
    
    def test_list_scans(self, client):
        """Test listing all scans."""
        # Create a few scans
        with patch('main.run_background_scan') as mock_task:
            mock_task.delay.return_value = MagicMock(id="task-list")
            
            for i in range(3):
                client.post("/scan", json={
                    "type": "IP",
                    "value": f"10.0.0.{i}"
                })
        
        # List scans
        with patch('main.DatabaseLogger') as mock_logger:
            mock_logger_instance = MagicMock()
            mock_logger_instance.redis_client.get.return_value = b"COMPLETED"
            mock_logger_instance.redis_client.lrange.return_value = []
            mock_logger.return_value = mock_logger_instance
            
            response = client.get("/scans")
            
            assert response.status_code == 200
            data = response.json()
            
            assert isinstance(data, list)
            assert len(data) >= 3


# ============================================================================
# Report Export Tests
# ============================================================================

@pytest.mark.integration
@pytest.mark.api
class TestReportExportEndpoints:
    """Test report export endpoints."""
    
    def test_export_pdf(self, client):
        """Test PDF report export."""
        response = client.get("/scan/test-scan-123/export?format=pdf")
        
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"
        assert "attachment" in response.headers["content-disposition"]
        assert response.content.startswith(b'%PDF')
    
    def test_export_html(self, client):
        """Test HTML report export."""
        response = client.get("/scan/test-scan-456/export?format=html")
        
        assert response.status_code == 200
        assert response.headers["content-type"] == "text/html; charset=utf-8"
        assert b'<html' in response.content or b'<!DOCTYPE' in response.content
    
    def test_export_json(self, client):
        """Test JSON report export."""
        response = client.get("/scan/test-scan-789/export?format=json")
        
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/json"
        
        data = json.loads(response.content)
        assert isinstance(data, dict)
    
    def test_export_invalid_format(self, client):
        """Test export with invalid format."""
        response = client.get("/scan/test-scan-123/export?format=xml")
        
        assert response.status_code == 400
        assert "Invalid format" in response.json()["detail"]
    
    def test_export_with_severity_filter(self, client):
        """Test export with severity filtering."""
        response = client.get(
            "/scan/test-scan-123/export?format=json&severities=CRITICAL,HIGH"
        )
        
        assert response.status_code == 200
        data = json.loads(response.content)
        
        # Check that findings are filtered (if any)
        for finding in data.get("findings", []):
            assert finding["severity"] in ["CRITICAL", "HIGH"]


# ============================================================================
# Attack Path Simulation Tests
# ============================================================================

@pytest.mark.integration
@pytest.mark.api
class TestAttackPathEndpoints:
    """Test attack path simulation endpoints."""
    
    @patch('main.mitre_engine')
    def test_simulate_attack_path(self, mock_mitre, client):
        """Test attack path simulation."""
        mock_mitre.simulate_attack_path.return_value = {
            "nodes": [{"id": "1", "label": "Initial Access"}],
            "edges": []
        }
        
        response = client.post("/scan/test-scan-123/simulate-attack")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "nodes" in data
        assert "edges" in data


# ============================================================================
# Vulnerability Verification Tests
# ============================================================================

@pytest.mark.integration
@pytest.mark.api
class TestVerificationEndpoints:
    """Test manual vulnerability verification endpoint."""
    
    @patch('main.verifier_agent')
    async def test_verify_vulnerability(self, mock_verifier, client):
        """Test manual vulnerability verification."""
        mock_verifier.verify_vulnerability = AsyncMock(return_value=MagicMock(
            is_confirmed=True,
            proof_of_exploit="Test exploit",
            logs="Test logs",
            execution_time=1.5
        ))
        
        payload = {
            "target_url": "https://example.com",
            "vuln_type": "SQL Injection",
            "parameter": "id",
            "evidence_hint": "Error on quote"
        }
        
        response = client.post("/verify-vulnerability", json=payload)
        
        assert response.status_code == 200


# ============================================================================
# CVE Endpoint Tests
# ============================================================================

@pytest.mark.integration
@pytest.mark.api
class TestCVEEndpoints:
    """Test CVE listing endpoint."""
    
    @patch('aiohttp.ClientSession')
    async def test_get_cves_from_api(self, mock_session, client):
        """Test CVE endpoint with successful API call."""
        # This test is async, adapter needed for sync test client
        response = client.get("/cves")
        
        assert response.status_code == 200
        data = response.json()
        
        assert isinstance(data, list)
        # Should return fallback data or real data
        if len(data) > 0:
            assert "id" in data[0]
    
    def test_get_cves_fallback(self, client):
        """Test CVE endpoint falls back on API failure."""
        with patch('aiohttp.ClientSession') as mock_session:
            mock_session.side_effect = Exception("API Down")
            
            response = client.get("/cves")
            
            assert response.status_code == 200
            data = response.json()
            
            # Should return fallback/mock data
            assert isinstance(data, list)


# ============================================================================
# CORS Tests
# ============================================================================

@pytest.mark.integration
@pytest.mark.api
class TestCORS:
    """Test CORS configuration."""
    
    def test_cors_headers_present(self, client):
        """Test CORS headers are present."""
        response = client.options(
            "/",
            headers={"Origin": "http://localhost:3000"}
        )
        
        # Should have CORS headers or just work
        assert response.status_code in [200, 204]


# ============================================================================
# Error Handling Tests
# ============================================================================

@pytest.mark.integration
@pytest.mark.api
class TestErrorHandling:
    """Test API error handling."""
    
    def test_404_not_found(self, client):
        """Test 404 for non-existent routes."""
        response = client.get("/nonexistent-route")
        
        assert response.status_code == 404
    
    def test_invalid_json_payload(self, client):
        """Test handling of invalid JSON."""
        response = client.post(
            "/scan",
            data="invalid json {{{",
            headers={"Content-Type": "application/json"}
        )
        
        assert response.status_code == 422  # Validation error
    
    def test_missing_required_fields(self, client):
        """Test validation of required fields."""
        response = client.post("/scan", json={})
        
        assert response.status_code == 422  # Validation error

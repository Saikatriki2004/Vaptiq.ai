import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock, patch
from Backend.main import app, scans_db, mock_targets_db
from Backend.models import ScanTarget

client = TestClient(app)

# Helper to clear mock DBs
@pytest.fixture(autouse=True)
def clear_dbs():
    scans_db.clear()
    mock_targets_db.clear()
    yield

def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Vaptiq.ai Engine Running"}

def test_create_target():
    payload = {"type": "URL", "value": "http://example.com", "tags": []}
    response = client.post("/targets/create", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "target_id" in data
    assert "verification_token" in data
    assert data["is_verified"] is False

    # Check if added to mock_targets_db
    target_id = data["target_id"]
    assert target_id in mock_targets_db
    assert mock_targets_db[target_id]["value"] == "http://example.com"

def test_verify_target_success():
    # 1. Create Target
    target_id = "test-target-id"
    mock_targets_db[target_id] = {
        "id": target_id,
        "type": "URL",
        "value": "http://example.com",
        "verification_token": "token123",
        "is_verified": False
    }

    # 2. Verify
    # We need to mock verify_domain_ownership as it's an async function used inside the endpoint
    # However, in main.py it's a simple function that returns success mocked.
    # Let's inspect main.py verify_domain_ownership... it returns {"verified": True, ...}

    response = client.post(f"/targets/{target_id}/verify")
    assert response.status_code == 200
    assert response.json()["verified"] is True

    assert mock_targets_db[target_id]["is_verified"] is True

def test_verify_target_not_found():
    response = client.post("/targets/nonexistent/verify")
    assert response.status_code == 404

def test_start_scan_success(mocker):
    # Mock run_background_scan.delay
    mock_task = MagicMock()
    mock_task.id = "task-123"
    mocker.patch("Backend.main.run_background_scan.delay", return_value=mock_task)

    # 1. Create Verified Target
    target_id = "verified-target"
    mock_targets_db[target_id] = {
        "id": target_id,
        "type": "URL",
        "value": "http://example.com",
        "is_verified": True
    }

    payload = {"type": "URL", "value": "http://example.com", "tags": []}
    response = client.post(f"/scan?target_id={target_id}", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "QUEUED"
    assert data["task_id"] == "task-123"
    assert data["scan_id"] in scans_db

def test_start_scan_unverified_target():
    # 1. Create Unverified Target
    target_id = "unverified-target"
    mock_targets_db[target_id] = {
        "id": target_id,
        "type": "URL",
        "value": "http://example.com",
        "is_verified": False
    }

    payload = {"type": "URL", "value": "http://example.com", "tags": []}
    response = client.post(f"/scan?target_id={target_id}", json=payload)

    assert response.status_code == 403
    assert "Domain verification required" in response.json()["detail"]

def test_start_scan_missing_target_id_for_url():
    payload = {"type": "URL", "value": "http://example.com", "tags": []}
    response = client.post("/scan", json=payload)

    assert response.status_code == 400
    assert "URL targets must be created and verified" in response.json()["detail"]

def test_get_scan_status_found(mocker):
    scan_id = "scan-123"
    scans_db[scan_id] = {
        "scan_id": scan_id,
        "status": "QUEUED",
        "target": {"type": "IP", "value": "1.1.1.1"},
        "created_at": "2023-01-01T00:00:00"
    }

    # Mock Redis calls in DatabaseLogger
    # The endpoint uses DatabaseLogger(scan_id).redis_client...
    # We need to mock the redis_client inside DatabaseLogger or patch DatabaseLogger

    mock_redis = MagicMock()
    mock_redis.lrange.return_value = [b"Log 1", b"Log 2"]
    mock_redis.get.side_effect = lambda k: b"RUNNING" if "status" in k else None

    # Patch DatabaseLogger to return our mock
    with patch("Backend.main.DatabaseLogger") as MockLogger:
        MockLogger.return_value.redis_client = mock_redis

        response = client.get(f"/scan/{scan_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["scan_id"] == scan_id
        assert data["status"] == "RUNNING"
        assert data["logs"] == ["Log 1", "Log 2"]

def test_get_scan_status_not_found():
    response = client.get("/scan/nonexistent")
    assert response.status_code == 404

def test_export_scan_pdf(mocker):
    scan_id = "scan-export-pdf"

    # Mock ReportGenerator.generate_pdf
    # It returns a BytesIO
    mock_pdf = MagicMock()
    mocker.patch("Backend.main.ReportGenerator.generate_pdf", return_value=mock_pdf)

    response = client.get(f"/scan/{scan_id}/export?format=pdf")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"

def test_export_scan_invalid_format():
    response = client.get("/scan/123/export?format=exe")
    assert response.status_code == 400

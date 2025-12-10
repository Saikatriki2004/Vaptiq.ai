import pytest
from unittest.mock import MagicMock, AsyncMock
from Backend.tasks import run_background_scan
from Backend.models import ScanTarget

# Mock Redis
@pytest.fixture
def mock_redis(mocker):
    mock = MagicMock()
    mocker.patch("Backend.tasks.redis_client", mock)
    return mock

# Mock DatabaseLogger
@pytest.fixture
def mock_logger(mocker):
    mock = MagicMock()
    # Mock methods used in tasks.py
    mock.log = MagicMock()
    mock.update_status = MagicMock()
    mock.save_vulnerabilities = MagicMock()
    mock.update_phase = MagicMock()

    mocker.patch("Backend.tasks.DatabaseLogger", return_value=mock)
    return mock

# Mock SecurityAgent
@pytest.fixture
def mock_agent(mocker):
    mock = MagicMock()
    # Mock execute to be async
    mock.execute = AsyncMock(return_value={"vulnerabilities": [{"title": "Test Vuln"}]})
    mocker.patch("Backend.tasks.SecurityAgent", return_value=mock)
    return mock

def test_run_background_scan_success(mock_redis, mock_logger, mock_agent):
    scan_id = "test-scan-id"
    target_data = {"type": "URL", "value": "http://example.com", "tags": []}

    # We call run_background_scan.run(...) to bypass Celery machinery
    # but still execute the task logic

    mock_self = MagicMock()
    mock_self.request.id = "task-id-123"

    result = run_background_scan.run(target_data, scan_id)

    assert result["status"] == "OK"
    assert result["scan_id"] == scan_id

    # Check Logger calls
    mock_logger.update_status.assert_any_call("RUNNING")
    mock_logger.save_vulnerabilities.assert_called_once()
    mock_logger.update_status.assert_any_call("COMPLETED")

    # Check Agent calls
    mock_agent.execute.assert_called_once()

def test_run_background_scan_exception(mock_redis, mock_logger, mock_agent):
    scan_id = "test-scan-id"
    target_data = {"type": "URL", "value": "http://example.com", "tags": []}

    mock_self = MagicMock()
    mock_self.request.id = "task-id-123"

    # Make agent crash
    mock_agent.execute.side_effect = Exception("Crash")

    # In this test we expect the exception to bubble up or be handled by retry mechanism.
    # Since we are calling .run() directly and not mocking self (because run() does not accept self),
    # The `self.retry` call inside the task will likely fail because `self` is not bound properly
    # or it will raise the exception.
    # The code says `raise self.retry(exc=e)`.
    # Without binding, `self` inside `run` is likely the Task object itself?
    # Actually `bind=True` passes the task instance as first arg.
    # When calling `.run()`, does it pass the task instance?
    # If not, `self` might be missing or wrong.

    # However, for the purpose of testing the logic up to the crash:

    with pytest.raises(Exception, match="Crash"):
        run_background_scan.run(target_data, scan_id)

    mock_logger.log.assert_any_call("FATAL", "Worker Error: Crash")
    mock_logger.update_status.assert_called_with("FAILED")

import pytest
from unittest.mock import MagicMock, AsyncMock
from Backend.agent import SecurityAgent
from Backend.models import ScanTarget, ScanResult, Vulnerability

@pytest.fixture
def mock_target():
    return ScanTarget(type="URL", value="http://example.com", tags=["web"])

@pytest.fixture
def mock_logger(mocker):
    mock = MagicMock()
    mocker.patch("Backend.agent.DatabaseLogger", return_value=mock)
    return mock

@pytest.fixture
def mock_redis():
    mock = MagicMock()
    mock.get.return_value = None # Not cancelled
    return mock

@pytest.fixture
def mock_verifier(mocker):
    mock = MagicMock()
    # Mock verify_vulnerability
    mock.verify_vulnerability = AsyncMock()
    # Important: In SecurityAgent __init__, VerifierAgent() is called.
    # We patch the CLASS so it returns our mock instance.
    mocker.patch("Backend.agent.VerifierAgent", return_value=mock)
    return mock

@pytest.mark.asyncio
async def test_agent_execution_success(mock_target, mock_logger, mock_redis, mock_verifier, mocker):
    import Backend.agent
    from Backend.models import Vulnerability as ModelVuln # Use consistent import

    mock_nmap = AsyncMock(return_value=[
        ModelVuln(title="Open Port: 80", severity="LOW", description="Port 80 is open", remediation="Check")
    ])
    mocker.patch.object(Backend.agent, "run_nmap_scan", mock_nmap)
    mocker.patch.object(Backend.agent, "run_zap_spider", AsyncMock(return_value=[]))
    mocker.patch.object(Backend.agent, "check_ssl_cert", AsyncMock(return_value=[]))

    agent = SecurityAgent(mock_target, "test-scan-id", mock_redis)

    result = await agent.execute()

    # Check if tools returned errors (which are logged but don't fail the scan status)
    if len(result["vulnerabilities"]) == 0:
        error_logs = [call.args for call in mock_logger.log.call_args_list if call.args[0] == "ERROR"]
        if error_logs:
            pytest.fail(f"Logger reported errors: {error_logs}")

    assert result["status"] == "COMPLETED"
    assert len(result["vulnerabilities"]) == 1
    # Check Logger
    mock_logger.update_phase.assert_any_call("RUNNING")
    mock_logger.update_phase.assert_any_call("COMPLETED")

@pytest.mark.asyncio
async def test_agent_execution_cancelled(mock_target, mock_logger, mock_redis, mock_verifier):
    # Depending on how agent checks redis, it might check multiple times.
    # We want it to be cancelled.
    mock_redis.get.return_value = b"1" # Cancelled

    agent = SecurityAgent(mock_target, "test-scan-id", mock_redis)

    result = await agent.execute()

    assert result["status"] == "CANCELLED"
    # Logger should be called with CANCELLED phase
    mock_logger.update_phase.assert_any_call("CANCELLED")

@pytest.mark.asyncio
async def test_agent_execution_no_tools(mock_logger, mock_redis, mock_verifier):
    target = ScanTarget(type="UNKNOWN", value="foo", tags=[])
    agent = SecurityAgent(target, "test-scan-id", mock_redis)

    result = await agent.execute()

    assert result["status"] == "FAILED"
    assert "No tools defined" in result["error"]

@pytest.mark.asyncio
async def test_agent_verification_flow(mock_target, mock_logger, mock_redis, mock_verifier, mocker):
    import Backend.agent
    from Backend.models import Vulnerability as ModelVuln # Use consistent import

    # Mock finding a CRITICAL vulnerability
    critical_vuln = ModelVuln(title="SQLi", severity="CRITICAL", description="SQL injection", remediation="Fix")
    mocker.patch.object(Backend.agent, "run_nmap_scan", AsyncMock(return_value=[critical_vuln]))
    mocker.patch.object(Backend.agent, "run_zap_spider", AsyncMock(return_value=[]))
    mocker.patch.object(Backend.agent, "check_ssl_cert", AsyncMock(return_value=[]))

    # Mock Verification success
    mock_verification_result = MagicMock()
    mock_verification_result.is_confirmed = True
    mock_verification_result.proof_of_exploit = "PROOF"

    mock_verifier.verify_vulnerability.side_effect = AsyncMock(return_value=mock_verification_result)

    agent = SecurityAgent(mock_target, "test-scan-id", mock_redis)

    result = await agent.execute()

    assert result["status"] == "COMPLETED"
    findings = result["vulnerabilities"]
    assert len(findings) == 1
    assert findings[0]["status"] == "CONFIRMED"
    assert findings[0]["proof_of_exploit"] == "PROOF"

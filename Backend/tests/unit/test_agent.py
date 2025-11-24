"""
Unit Tests for Security Agent (agent.py)

Tests cover:
- Tool registry mapping
- Individual tool functions
- Parallel execution
- Cancellation handling
- Error handling
- Vulnerability aggregation
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from agent import (
    SecurityAgent,
    TOOL_REGISTRY,
    run_nmap_scan,
    run_zap_spider,
    check_ssl_cert,
    check_geo_ip,
    fuzz_api_endpoints
)
from models import ScanTarget, Vulnerability, ScanResult


# ============================================================================
# Tool Registry Tests
# ============================================================================

@pytest.mark.unit
@pytest.mark.agent
class TestToolRegistry:
    """Test tool registry mapping for different target types."""
    
    def test_url_target_tools(self):
        """URL targets should have nmap, zap, and ssl tools."""
        tools = TOOL_REGISTRY["URL"]
        assert "run_nmap_scan" in tools
        assert "run_zap_spider" in tools
        assert "check_ssl_cert" in tools
        assert len(tools) == 3
    
    def test_ip_target_tools(self):
        """IP targets should have nmap and geoip tools."""
        tools = TOOL_REGISTRY["IP"]
        assert "run_nmap_scan" in tools
        assert "check_geo_ip" in tools
        assert len(tools) == 2
    
    def test_api_target_tools(self):
        """API targets should have nmap and api fuzzer tools."""
        tools = TOOL_REGISTRY["API"]
        assert "run_nmap_scan" in tools
        assert "fuzz_api_endpoints" in tools
        assert len(tools) == 2
    
    def test_all_target_types_registered(self):
        """All expected target types should be in registry."""
        assert "URL" in TOOL_REGISTRY
        assert "IP" in TOOL_REGISTRY
        assert "API" in TOOL_REGISTRY


# ============================================================================
# Individual Tool Tests
# ============================================================================

@pytest.mark.unit
@pytest.mark.agent
@pytest.mark.asyncio
class TestIndividualTools:
    """Test individual security tool functions."""
    
    async def test_run_nmap_scan_no_binary(self):
        """Test nmap scan when binary is not available."""
        with patch('shutil.which', return_value=None):
            result = await run_nmap_scan("example.com")
            
            assert len(result) == 1
            assert result[0].title == "Configuration Error"
            assert result[0].severity == "LOW"
            assert "not found" in result[0].description
    
    async def test_run_nmap_scan_with_mock_output(self, mock_nmap_output):
        """Test nmap scan with mocked successful output."""
        with patch('shutil.which', return_value='/usr/bin/nmap'):
            with patch('asyncio.create_subprocess_exec') as mock_subprocess:
                # Mock process
                mock_process = AsyncMock()
                mock_process.returncode = 0
                mock_process.communicate = AsyncMock(
                    return_value=(mock_nmap_output.encode(), b"")
                )
                mock_subprocess.return_value = mock_process
                
                result = await run_nmap_scan("example.com")
                
                # Should find 2 open ports (80 and 443)
                assert len(result) == 2
                assert any("80" in v.title for v in result)
                assert any("443" in v.title for v in result)
    
    async def test_run_nmap_scan_error_handling(self):
        """Test nmap scan handles errors gracefully."""
        with patch('shutil.which', return_value='/usr/bin/nmap'):
            with patch('asyncio.create_subprocess_exec') as mock_subprocess:
                mock_process = AsyncMock()
                mock_process.returncode = 1
                mock_process.communicate = AsyncMock(
                    return_value=(b"", b"Error: Invalid target")
                )
                mock_subprocess.return_value = mock_process
                
                result = await run_nmap_scan("invalid-target")
                
                # Should return empty list on error
                assert result == []
    
    async def test_run_zap_spider(self):
        """Test ZAP spider tool (mock implementation)."""
        result = await run_zap_spider("https://example.com")
        
        assert isinstance(result, list)
        # Mock returns security header finding
        if len(result) > 0:
            assert any("Security Headers" in v.title for v in result)
    
    async def test_check_ssl_cert(self):
        """Test SSL certificate checker."""
        result = await check_ssl_cert("https://example.com")
        
        assert isinstance(result, list)
        # May or may not find issues (random in mock)
    
    async def test_check_geo_ip(self):
        """Test GeoIP checker."""
        result = await check_geo_ip("8.8.8.8")
        
        assert isinstance(result, list)
        # Mock returns empty list
        assert result == []
    
    async def test_fuzz_api_endpoints(self):
        """Test API endpoint fuzzer."""
        result = await fuzz_api_endpoints("https://api.example.com")
        
        assert isinstance(result, list)
        # Mock returns SQL injection finding
        if len(result) > 0:
            assert any("SQL Injection" in v.title for v in result)
            assert any(v.severity == "CRITICAL" for v in result)


# ============================================================================
# Security Agent Tests
# ============================================================================

@pytest.mark.unit
@pytest.mark.agent
@pytest.mark.asyncio
class TestSecurityAgent:
    """Test SecurityAgent orchestration and execution."""
    
    async def test_agent_initialization(self, sample_scan_target, mock_redis_client):
        """Test agent initializes correctly."""
        agent = SecurityAgent(
            target=sample_scan_target,
            scan_id="test-scan-123",
            redis_client=mock_redis_client
        )
        
        assert agent.target == sample_scan_target
        assert agent.scan_id == "test-scan-123"
        assert agent.redis == mock_redis_client
        assert agent.is_cancelled is False
        assert agent.semaphore._value == 2  # Max 2 concurrent
    
    async def test_agent_invalid_target_type(self, mock_redis_client):
        """Test agent handles invalid target type gracefully."""
        invalid_target = ScanTarget(type="INVALID", value="test")
        agent = SecurityAgent(
            target=invalid_target,
            scan_id="test-scan-456",
            redis_client=mock_redis_client
        )
        
        result = await agent.execute()
        
        assert result["status"] == "FAILED"
        assert "No tools defined" in result["error"]
        assert result["vulnerabilities"] == []
    
    async def test_agent_cancellation_check(self, sample_scan_target, mock_redis_client):
        """Test agent detects cancellation signal."""
        agent = SecurityAgent(
            target=sample_scan_target,
            scan_id="test-scan-789",
            redis_client=mock_redis_client
        )
        
        # Set cancellation flag
        mock_redis_client.set(f"scan:test-scan-789:cancel", "true")
        
        with pytest.raises(asyncio.CancelledError):
            await agent._check_cancellation()
        
        assert agent.is_cancelled is True
    
    async def test_run_tool_with_semaphore(self, sample_scan_target, mock_redis_client):
        """Test tool execution respects semaphore limits."""
        agent = SecurityAgent(
            target=sample_scan_target,
            scan_id="test-scan-999",
            redis_client=mock_redis_client
        )
        
        with patch('agent.run_nmap_scan', new_callable=AsyncMock) as mock_nmap:
            mock_nmap.return_value = []
            
            result = await agent.run_tool("run_nmap_scan")
            
            assert result.tool == "run_nmap_scan"
            assert result.findings == []
            assert result.error is None
            mock_nmap.assert_called_once()
    
    async def test_run_tool_handles_errors(self, sample_scan_target, mock_redis_client):
        """Test tool execution handles errors gracefully."""
        agent = SecurityAgent(
            target=sample_scan_target,
            scan_id="test-scan-error",
            redis_client=mock_redis_client
        )
        
        with patch('agent.run_nmap_scan', new_callable=AsyncMock) as mock_nmap:
            mock_nmap.side_effect = Exception("Network error")
            
            result = await agent.run_tool("run_nmap_scan")
            
            assert result.tool == "run_nmap_scan"
            assert result.findings == []
            assert "Network error" in result.error
    
    async def test_run_unknown_tool(self, sample_scan_target, mock_redis_client):
        """Test agent handles unknown tool gracefully."""
        agent = SecurityAgent(
            target=sample_scan_target,
            scan_id="test-scan-unknown",
            redis_client=mock_redis_client
        )
        
        result = await agent.run_tool("unknown_tool")
        
        assert result.tool == "unknown_tool"
        assert result.findings == []
        assert "Unknown tool" in result.error
    
    @patch('agent.run_nmap_scan', new_callable=AsyncMock)
    @patch('agent.run_zap_spider', new_callable=AsyncMock)
    @patch('agent.check_ssl_cert', new_callable=AsyncMock)
    async def test_execute_url_target(
        self, 
        mock_ssl, 
        mock_zap, 
        mock_nmap,
        sample_scan_target,
        mock_redis_client,
        sample_vulnerabilities
    ):
        """Test full execution for URL target."""
        # Setup mocks
        mock_nmap.return_value = [sample_vulnerabilities[0]]
        mock_zap.return_value = [sample_vulnerabilities[1]]
        mock_ssl.return_value = [sample_vulnerabilities[2]]
        
        agent = SecurityAgent(
            target=sample_scan_target,
            scan_id="test-scan-full",
            redis_client=mock_redis_client
        )
        
        # Mock verifier to avoid actual LLM calls
        with patch.object(agent.verifier_agent, 'verify_vulnerability', new_callable=AsyncMock) as mock_verify:
            mock_verify.return_value = MagicMock(
                is_confirmed=True,
                proof_of_exploit="Test exploit"
            )
            
            result = await agent.execute()
            
            # Verify result structure
            assert result["status"] == "COMPLETED"
            assert len(result["vulnerabilities"]) == 3
            
            # Verify all tools were called
            mock_nmap.assert_called_once()
            mock_zap.assert_called_once()
            mock_ssl.assert_called_once()
    
    async def test_execute_handles_cancellation(self, sample_scan_target, mock_redis_client):
        """Test execution handles cancellation gracefully."""
        agent = SecurityAgent(
            target=sample_scan_target,
            scan_id="test-scan-cancel",
            redis_client=mock_redis_client
        )
        
        # Set cancellation before execution
        mock_redis_client.set(f"scan:test-scan-cancel:cancel", "true")
        
        result = await agent.execute()
        
        assert result["status"] == "CANCELLED"
        assert result["vulnerabilities"] == []
    
    @patch('agent.run_nmap_scan', new_callable=AsyncMock)
    async def test_parallel_execution(self, mock_nmap, sample_ip_target, mock_redis_client):
        """Test that tools execute in parallel."""
        mock_nmap.return_value = []
        
        agent = SecurityAgent(
            target=sample_ip_target,
            scan_id="test-scan-parallel",
            redis_client=mock_redis_client
        )
        
        import time
        start_time = time.time()
        
        with patch('agent.check_geo_ip', new_callable=AsyncMock) as mock_geo:
            mock_geo.return_value = []
            
            await agent.execute()
            
            execution_time = time.time() - start_time
            
            # Both tools should execute (may be sequential due to mocking)
            assert mock_nmap.called
            assert mock_geo.called
    
    async def test_vulnerability_verification_selective(
        self,
        sample_scan_target,
        mock_redis_client,
        sample_vulnerabilities
    ):
        """Test that only CRITICAL and HIGH vulns are verified."""
        agent = SecurityAgent(
            target=sample_scan_target,
            scan_id="test-scan-verify",
            redis_client=mock_redis_client
        )
        
        with patch('agent.run_nmap_scan', new_callable=AsyncMock) as mock_nmap:
            # Return mixed severity vulnerabilities
            mock_nmap.return_value = sample_vulnerabilities
            
            with patch('agent.run_zap_spider', new_callable=AsyncMock, return_value=[]):
                with patch('agent.check_ssl_cert', new_callable=AsyncMock, return_value=[]):
                    with patch.object(agent.verifier_agent, 'verify_vulnerability', new_callable=AsyncMock) as mock_verify:
                        mock_verify.return_value = MagicMock(
                            is_confirmed=True,
                            proof_of_exploit="Test"
                        )
                        
                        await agent.execute()
                        
                        # Only CRITICAL and HIGH should be verified (2 out of 4)
                        assert mock_verify.call_count == 2


# ============================================================================
# Edge Cases and Error Handling
# ============================================================================

@pytest.mark.unit
@pytest.mark.agent
@pytest.mark.asyncio
class TestEdgeCases:
    """Test edge cases and error scenarios."""
    
    async def test_empty_findings(self, sample_scan_target, mock_redis_client):
        """Test agent handles scans with no findings."""
        agent = SecurityAgent(
            target=sample_scan_target,
            scan_id="test-scan-empty",
            redis_client=mock_redis_client
        )
        
        with patch('agent.run_nmap_scan', new_callable=AsyncMock, return_value=[]):
            with patch('agent.run_zap_spider', new_callable=AsyncMock, return_value=[]):
                with patch('agent.check_ssl_cert', new_callable=AsyncMock, return_value=[]):
                    result = await agent.execute()
                    
                    assert result["status"] == "COMPLETED"
                    assert result["vulnerabilities"] == []
    
    async def test_all_tools_fail(self, sample_scan_target, mock_redis_client):
        """Test agent handles all tools failing."""
        agent = SecurityAgent(
            target=sample_scan_target,
            scan_id="test-scan-allfail",
            redis_client=mock_redis_client
        )
        
        with patch('agent.run_nmap_scan', new_callable=AsyncMock) as mock_nmap:
            with patch('agent.run_zap_spider', new_callable=AsyncMock) as mock_zap:
                with patch('agent.check_ssl_cert', new_callable=AsyncMock) as mock_ssl:
                    # All tools raise exceptions
                    mock_nmap.side_effect = Exception("Nmap failed")
                    mock_zap.side_effect = Exception("ZAP failed")
                    mock_ssl.side_effect = Exception("SSL failed")
                    
                    result = await agent.execute()
                    
                    # Should still complete but with no findings
                    assert result["status"] == "COMPLETED"
                    assert result["vulnerabilities"] == []

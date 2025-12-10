"""
Unit Tests for Verifier Agent (verifier_agent.py)

Tests cover:
- LLM provider initialization
- Privacy mode enforcement
- Script generation
- Sandbox execution
- Verification workflow
- Retry logic and fallbacks
"""

import pytest
import os
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from verifier_agent import VerifierAgent, SuspectedVuln, VerificationResult


# ============================================================================
# LLM Provider Initialization Tests
# ============================================================================

@pytest.mark.unit
@pytest.mark.verifier
class TestLLMProviderInitialization:
    """Test LLM provider initialization logic."""
    
    def test_default_to_mock_mode(self, monkeypatch):
        """Test agent defaults to MOCK mode without API keys."""
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("MOONSHOT_API_KEY", raising=False)
        
        agent = VerifierAgent()
        
        assert agent.mode == "MOCK"
        assert agent.client is None
    
    def test_openrouter_initialization(self, monkeypatch):
        """Test OpenRouter provider initialization."""
        monkeypatch.setenv("LLM_PROVIDER", "OPENROUTER")
        monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
        monkeypatch.setenv("PRIVACY_MODE", "LOW")
        
        with patch('verifier_agent.AsyncOpenAI') as mock_openai:
            agent = VerifierAgent()
            
            assert agent.llm_provider == "OPENROUTER"
            assert agent.mode == "REAL"
            assert agent.model == "moonshotai/kimi-k2-thinking"
            
            mock_openai.assert_called_once()
            call_kwargs = mock_openai.call_args[1]
            assert call_kwargs["base_url"] == "https://openrouter.ai/api/v1"
            assert call_kwargs["api_key"] == "test-key"
    
    def test_gemini_initialization(self, monkeypatch):
        """Test Gemini provider initialization."""
        monkeypatch.setenv("LLM_PROVIDER", "GEMINI")
        monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key")
        
        with patch('verifier_agent.AsyncOpenAI') as mock_openai:
            agent = VerifierAgent()
            
            assert agent.llm_provider == "GEMINI"
            assert agent.mode == "REAL"
            assert agent.model == "gemini-2.0-flash-exp"
            
            call_kwargs = mock_openai.call_args[1]
            assert "generativelanguage.googleapis.com" in call_kwargs["base_url"]
    
    def test_kimi_initialization(self, monkeypatch):
        """Test Kimi (Moonshot) provider initialization."""
        monkeypatch.setenv("LLM_PROVIDER", "KIMI")
        monkeypatch.setenv("MOONSHOT_API_KEY", "test-kimi-key")
        
        with patch('verifier_agent.AsyncOpenAI') as mock_openai:
            agent = VerifierAgent()
            
            assert agent.llm_provider == "KIMI"
            assert agent.mode == "REAL"
            assert agent.model == "kimi-k2-thinking"
            
            call_kwargs = mock_openai.call_args[1]
            assert call_kwargs["base_url"] == "https://api.moonshot.ai/v1"
    
    def test_privacy_mode_high_forces_gemini(self, monkeypatch):
        """Test PRIVACY_MODE=HIGH forces direct Gemini API."""
        monkeypatch.setenv("PRIVACY_MODE", "HIGH")
        monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key")
        monkeypatch.setenv("LLM_PROVIDER", "OPENROUTER")  # This should be overridden
        
        with patch('verifier_agent.AsyncOpenAI'):
            agent = VerifierAgent()
            
            # Should use Gemini despite OPENROUTER being set
            assert agent.llm_provider == "GEMINI"
    
    def test_missing_openai_library(self, monkeypatch):
        """Test fallback to MOCK when openai library is missing."""
        monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
        
        with patch('builtins.__import__', side_effect=ImportError("No module named 'openai'")):
            agent = VerifierAgent()
            
            assert agent.mode == "MOCK"


# ============================================================================
# Prompt Construction Tests
# ============================================================================

@pytest.mark.unit
@pytest.mark.verifier
class TestPromptConstruction:
    """Test verification prompt construction."""
    
    def test_prompt_includes_vuln_details(self, monkeypatch):
        """Test prompt includes vulnerability details."""
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        
        agent = VerifierAgent()
        suspicion = SuspectedVuln(
            target_url="https://example.com/search",
            vuln_type="SQL Injection",
            parameter="q",
            evidence_hint="Error on single quote"
        )
        
        prompt = agent._construct_prompt(suspicion)
        
        assert "SQL Injection" in prompt
        assert "https://example.com/search" in prompt
        assert "q" in prompt
        assert "Error on single quote" in prompt
    
    def test_prompt_includes_safety_requirements(self, monkeypatch):
        """Test prompt includes safety requirements."""
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        
        agent = VerifierAgent()
        suspicion = SuspectedVuln(
            target_url="https://example.com",
            vuln_type="XSS",
            parameter="search",
            evidence_hint="Reflected in response"
        )
        
        prompt = agent._construct_prompt(suspicion)
        
        assert "Do NOT perform destructive actions" in prompt
        assert "DROP TABLE" in prompt or "DELETE" in prompt
        assert "timeout" in prompt.lower()


# ============================================================================
# Script Generation Tests (Mock Mode)
# ============================================================================

@pytest.mark.unit
@pytest.mark.verifier
@pytest.mark.asyncio
class TestScriptGenerationMock:
    """Test script generation in MOCK mode."""
    
    async def test_generate_sql_injection_script(self, monkeypatch):
        """Test SQL injection script generation."""
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        
        agent = VerifierAgent()
        suspicion = SuspectedVuln(
            target_url="https://example.com/user",
            vuln_type="SQL Injection",
            parameter="id",
            evidence_hint="Database error on quote"
        )
        
        script = await agent._generate_script_mock(suspicion)
        
        assert "def verify():" in script
        assert "import requests" in script
        assert "SQL" in script or "sqli" in script.lower()
        assert suspicion.target_url in script
        assert suspicion.parameter in script
    
    async def test_generate_xss_script(self, monkeypatch):
        """Test XSS script generation."""
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        
        agent = VerifierAgent()
        suspicion = SuspectedVuln(
            target_url="https://example.com/search",
            vuln_type="XSS",
            parameter="q",
            evidence_hint="Script tag reflected"
        )
        
        script = await agent._generate_script_mock(suspicion)
        
        assert "def verify():" in script
        assert "<script>" in script
        assert "XSS" in script or "xss" in script
        assert suspicion.target_url in script
    
    async def test_generate_generic_script(self, monkeypatch):
        """Test generic vulnerability script generation."""
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        
        agent = VerifierAgent()
        suspicion = SuspectedVuln(
            target_url="https://example.com/api",
            vuln_type="Command Injection",
            parameter="cmd",
            evidence_hint="Shell error message"
        )
        
        script = await agent._generate_script_mock(suspicion)
        
        assert "def verify():" in script
        assert "import requests" in script
        # Should have basic anomaly detection
        assert "try:" in script
        assert "except" in script


# ============================================================================
# Script Generation Tests (Real Mode)
# ============================================================================

@pytest.mark.unit
@pytest.mark.verifier
@pytest.mark.asyncio
class TestScriptGenerationReal:
    """Test script generation with real LLM."""
    
    async def test_generate_script_real_success(self, monkeypatch, mock_llm_client):
        """Test successful LLM script generation."""
        monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
        
        with patch('verifier_agent.AsyncOpenAI', return_value=mock_llm_client):
            agent = VerifierAgent()
            agent.mode = "REAL"
            agent.client = mock_llm_client
            
            suspicion = SuspectedVuln(
                target_url="https://example.com",
                vuln_type="SQL Injection",
                parameter="id",
                evidence_hint="Error"
            )
            
            script = await agent._generate_script_real(suspicion)
            
            assert "def verify():" in script
            assert mock_llm_client.chat.completions.create.called
    
    async def test_generate_script_real_retry_logic(self, monkeypatch):
        """Test retry logic on API failures."""
        monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
        
        mock_client = MagicMock()
        
        # Fail twice, then succeed
        call_count = 0
        async def mock_create(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise Exception("API Error")
            
            mock_response = MagicMock()
            mock_response.choices = [MagicMock()]
            mock_response.choices[0].message.content = "def verify():\n    return True"
            mock_response.usage.total_tokens = 100
            return mock_response
        
        mock_client.chat.completions.create = AsyncMock(side_effect=mock_create)
        
        with patch('verifier_agent.AsyncOpenAI', return_value=mock_client):
            agent = VerifierAgent()
            agent.mode = "REAL"
            agent.client = mock_client
            
            suspicion = SuspectedVuln(
                target_url="https://example.com",
                vuln_type="XSS",
                parameter="q",
                evidence_hint="Reflected"
            )
            
            script = await agent._generate_script_real(suspicion)
            
            # Should retry and eventually succeed
            assert "def verify():" in script
            assert call_count == 3
    
    async def test_generate_script_real_all_retries_fail(self, monkeypatch):
        """Test fallback to mock when all retries fail."""
        monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
        
        mock_client = MagicMock()
        mock_client.chat.completions.create = AsyncMock(side_effect=Exception("API Down"))
        
        with patch('verifier_agent.AsyncOpenAI', return_value=mock_client):
            agent = VerifierAgent()
            agent.mode = "REAL"
            agent.client = mock_client
            
            suspicion = SuspectedVuln(
                target_url="https://example.com",
                vuln_type="SQL Injection",
                parameter="id",
                evidence_hint="Error"
            )
            
            script = await agent._generate_script_real(suspicion)
            
            # Should fallback to mock
            assert "def verify():" in script
            assert "SQL" in script or "sqli" in script.lower()
    
    async def test_clean_markdown_from_llm_response(self, monkeypatch, mock_llm_client):
        """Test markdown cleanup from LLM response."""
        monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
        
        # Mock client returns code with markdown
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = """```python
def verify():
    return True
```"""
        mock_response.usage.total_tokens = 50
        
        mock_llm_client.chat.completions.create = AsyncMock(return_value=mock_response)
        
        with patch('verifier_agent.AsyncOpenAI', return_value=mock_llm_client):
            agent = VerifierAgent()
            agent.mode = "REAL"
            agent.client = mock_llm_client
            
            suspicion = SuspectedVuln(
                target_url="https://example.com",
                vuln_type="XSS",
                parameter="q",
                evidence_hint="Reflected"
            )
            
            script = await agent._generate_script_real(suspicion)
            
            # Should remove markdown
            assert "```" not in script
            assert "def verify():" in script


# ============================================================================
# Sandbox Execution Tests
# ============================================================================

@pytest.mark.unit
@pytest.mark.verifier
@pytest.mark.asyncio
class TestSandboxExecution:
    """Test sandbox code execution."""
    
    async def test_sandbox_not_configured(self, monkeypatch):
        """Test fallback when E2B is not configured."""
        monkeypatch.delenv("E2B_API_KEY", raising=False)
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        
        agent = VerifierAgent()
        
        result = await agent.execute_in_sandbox("def verify():\n    return True")
        
        # Should fallback to mock (returns True)
        assert result is True
    
    async def test_sandbox_success(self, monkeypatch, mock_e2b_sandbox):
        """Test successful sandbox execution."""
        monkeypatch.setenv("E2B_API_KEY", "test-e2b-key")
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        
        agent = VerifierAgent()
        
        code = "def verify():\n    return True"
        result = await agent.execute_in_sandbox(code)
        
        # Mock sandbox returns True
        assert result is True
    
    async def test_sandbox_execution_error(self, monkeypatch):
        """Test sandbox handles execution errors."""
        monkeypatch.setenv("E2B_API_KEY", "test-e2b-key")
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        
        # Mock sandbox that returns error
        class MockExecution:
            def __init__(self):
                self.error = MagicMock(name="RuntimeError", value="Division by zero")
                self.logs = MagicMock()
                self.logs.stdout = ""
        
        class MockSandbox:
            def __init__(self, *args, **kwargs):
                pass
            
            def run_code(self, code):
                return MockExecution()
            
            def close(self):
                pass
        
        with patch('verifier_agent.Sandbox', MockSandbox):
            agent = VerifierAgent()
            
            code = "def verify():\n    return 1/0"
            result = await agent.execute_in_sandbox(code)
            
            assert result is False


# ============================================================================
# Verification Workflow Tests
# ============================================================================

@pytest.mark.unit
@pytest.mark.verifier
@pytest.mark.asyncio
class TestVerificationWorkflow:
    """Test complete verification workflow."""
    
    async def test_verify_vulnerability_confirmed(self, monkeypatch):
        """Test verification workflow for confirmed vulnerability."""
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        monkeypatch.setenv("E2B_API_KEY", "test-key")
        
        agent = VerifierAgent()
        
        suspicion = SuspectedVuln(
            target_url="https://example.com",
            vuln_type="SQL Injection",
            parameter="id",
            evidence_hint="Error on quote"
        )
        
        # Mock sandbox to return True
        with patch.object(agent, 'execute_in_sandbox', new_callable=AsyncMock, return_value=True):
            result = await agent.verify_vulnerability(suspicion)
            
            assert isinstance(result, VerificationResult)
            assert result.is_confirmed is True
            assert len(result.proof_of_exploit) > 0
            assert result.execution_time > 0
            assert "MOCK" in result.logs or "REAL" in result.logs
    
    async def test_verify_vulnerability_not_confirmed(self, monkeypatch):
        """Test verification workflow for false positive."""
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        monkeypatch.setenv("E2B_API_KEY", "test-key")
        
        agent = VerifierAgent()
        
        suspicion = SuspectedVuln(
            target_url="https://example.com",
            vuln_type="XSS",
            parameter="q",
            evidence_hint="May be reflected"
        )
        
        # Mock sandbox to return False
        with patch.object(agent, 'execute_in_sandbox', new_callable=AsyncMock, return_value=False):
            result = await agent.verify_vulnerability(suspicion)
            
            assert isinstance(result, VerificationResult)
            assert result.is_confirmed is False
            assert result.proof_of_exploit == ""
            assert "False Positive" in result.logs or "NOT CONFIRMED" in result.logs
    
    async def test_verify_vulnerability_measures_time(self, monkeypatch):
        """Test that verification measures execution time."""
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        
        agent = VerifierAgent()
        
        suspicion = SuspectedVuln(
            target_url="https://example.com",
            vuln_type="SQL Injection",
            parameter="id",
            evidence_hint="Error"
        )
        
        import asyncio
        
        async def slow_sandbox(code):
            await asyncio.sleep(0.1)  # Simulate 100ms execution
            return True
        
        with patch.object(agent, 'execute_in_sandbox', new_callable=AsyncMock, side_effect=slow_sandbox):
            result = await agent.verify_vulnerability(suspicion)
            
            assert result.execution_time >= 0.1


# ============================================================================
# Edge Cases
# ============================================================================

@pytest.mark.unit
@pytest.mark.verifier
class TestVerifierEdgeCases:
    """Test edge cases and error scenarios."""
    
    def test_custom_model_override(self, monkeypatch):
        """Test custom model can be specified via env var."""
        monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
        monkeypatch.setenv("OPENROUTER_MODEL", "custom/model-name")
        
        with patch('verifier_agent.AsyncOpenAI'):
            agent = VerifierAgent()
            
            assert agent.model == "custom/model-name"
    
    def test_privacy_mode_case_insensitive(self, monkeypatch):
        """Test privacy mode is case insensitive."""
        monkeypatch.setenv("PRIVACY_MODE", "high")
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        
        with patch('verifier_agent.AsyncOpenAI'):
            agent = VerifierAgent()
            
            assert agent.privacy_mode == "HIGH"
            assert agent.llm_provider == "GEMINI"

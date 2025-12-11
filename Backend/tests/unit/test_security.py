"""
Unit tests for security.py

Tests cover:
- UUID validation
- Target sanitization and SSRF protection
- Command injection prevention
- Constant-time comparison
- Audit logging
"""

import pytest
from unittest.mock import MagicMock, patch, mock_open
import json
from security import (
    validate_uuid,
    sanitize_target,
    constant_time_compare,
    AuditLogger
)


class TestValidateUUID:
    """Tests for UUID validation function."""
    
    def test_valid_uuid_returns_same_value(self):
        """Should validate correct UUID format successfully."""
        valid_uuid = "123e4567-e89b-12d3-a456-426614174000"
        result = validate_uuid(valid_uuid)
        assert result == valid_uuid
    
    def test_valid_uuid_v4(self):
        """Should accept UUID v4 format."""
        uuid_v4 = "550e8400-e29b-41d4-a716-446655440000"
        result = validate_uuid(uuid_v4)
        assert result == uuid_v4
    
    def test_invalid_uuid_raises_valueerror(self):
        """Should reject invalid UUID with ValueError."""
        invalid_uuid = "not-a-valid-uuid"
        with pytest.raises(ValueError) as exc_info:
            validate_uuid(invalid_uuid)
        assert "Invalid" in str(exc_info.value)
        assert "UUID" in str(exc_info.value)
    
    def test_empty_string_raises_valueerror(self):
        """Should reject empty string."""
        with pytest.raises(ValueError):
            validate_uuid("")
    
    def test_sql_injection_attempt_blocked(self):
        """Should reject SQL injection attempts."""
        with pytest.raises(ValueError):
            validate_uuid("'; DROP TABLE users; --")
    
    def test_custom_field_name_in_error(self):
        """Should include custom field name in error message."""
        with pytest.raises(ValueError) as exc_info:
            validate_uuid("invalid", field_name="scan_id")
        assert "scan_id" in str(exc_info.value)
    
    def test_none_value_raises_valueerror(self):
        """Should reject None input."""
        with pytest.raises(ValueError):
            validate_uuid(None)


class TestSanitizeTarget:
    """Tests for target sanitization and SSRF protection."""
    
    def test_valid_url_returns_hostname(self):
        """Should sanitize URL and return hostname."""
        result = sanitize_target("https://example.com/api/v1", "URL")
        assert result == "example.com"
    
    def test_url_with_port_removes_port(self):
        """Should remove port from hostname."""
        result = sanitize_target("https://example.com:8080/path", "URL")
        assert result == "example.com"
    
    def test_url_without_protocol_still_works(self):
        """Should handle URL without protocol."""
        result = sanitize_target("example.com/path", "URL")
        assert result == "example.com"
    
    def test_command_injection_semicolon_blocked(self):
        """Should block command injection characters (semicolon)."""
        with pytest.raises(ValueError) as exc_info:
            sanitize_target("example.com; rm -rf /", "URL")
        assert "command injection" in str(exc_info.value).lower()
    
    def test_command_injection_pipe_blocked(self):
        """Should block pipe character."""
        with pytest.raises(ValueError):
            sanitize_target("example.com | cat /etc/passwd", "URL")
    
    def test_command_injection_backtick_blocked(self):
        """Should block backtick character."""
        with pytest.raises(ValueError):
            sanitize_target("example.com `whoami`", "URL")
    
    def test_private_ip_192_168_blocked(self):
        """Should block private IP addresses (192.168.x.x)."""
        with pytest.raises(ValueError) as exc_info:
            sanitize_target("192.168.1.1", "IP")
        assert "SSRF" in str(exc_info.value)
    
    def test_private_ip_10_x_blocked(self):
        """Should block private IP addresses (10.x.x.x)."""
        with pytest.raises(ValueError) as exc_info:
            sanitize_target("10.0.0.1", "IP")
        assert "SSRF" in str(exc_info.value)
    
    def test_private_ip_172_16_blocked(self):
        """Should block private IP addresses (172.16.x.x)."""
        with pytest.raises(ValueError) as exc_info:
            sanitize_target("172.16.0.1", "IP")
        assert "SSRF" in str(exc_info.value)
    
    def test_loopback_127_blocked(self):
        """Should block loopback addresses."""
        with pytest.raises(ValueError) as exc_info:
            sanitize_target("127.0.0.1", "IP")
        assert "loopback" in str(exc_info.value).lower()
    
    def test_localhost_url_blocked(self):
        """Should block localhost variations in URLs."""
        with pytest.raises(ValueError) as exc_info:
            sanitize_target("http://localhost/admin", "URL")
        assert "SSRF" in str(exc_info.value)
    
    def test_cloud_metadata_endpoint_blocked(self):
        """Should block AWS/GCP metadata endpoint."""
        with pytest.raises(ValueError) as exc_info:
            sanitize_target("169.254.169.254", "IP")
        assert "metadata" in str(exc_info.value).lower()
    
    def test_valid_public_ip(self):
        """Should allow valid public IP addresses."""
        result = sanitize_target("8.8.8.8", "IP")
        assert result == "8.8.8.8"
    
    def test_invalid_ip_format_rejected(self):
        """Should reject invalid IP format."""
        with pytest.raises(ValueError) as exc_info:
            sanitize_target("999.999.999.999", "IP")
        assert "Invalid" in str(exc_info.value)
    
    def test_api_type_uses_url_validation(self):
        """Should treat API type same as URL."""
        result = sanitize_target("https://api.example.com/v1", "API")
        assert result == "api.example.com"
    
    def test_unknown_target_type_rejected(self):
        """Should reject unknown target type."""
        with pytest.raises(ValueError) as exc_info:
            sanitize_target("example.com", "UNKNOWN")
        assert "Unknown target type" in str(exc_info.value)


class TestConstantTimeCompare:
    """Tests for timing-safe string comparison."""
    
    def test_equal_strings_return_true(self):
        """Should return True for equal strings."""
        assert constant_time_compare("secret123", "secret123") is True
    
    def test_different_strings_return_false(self):
        """Should return False for different strings."""
        assert constant_time_compare("secret123", "secret124") is False
    
    def test_different_length_strings_return_false(self):
        """Should return False for strings of different lengths."""
        assert constant_time_compare("short", "muchlonger") is False
    
    def test_empty_strings_return_true(self):
        """Should return True for two empty strings."""
        assert constant_time_compare("", "") is True
    
    def test_none_first_arg_returns_false(self):
        """Should return False when first argument is None."""
        assert constant_time_compare(None, "test") is False
    
    def test_none_second_arg_returns_false(self):
        """Should return False when second argument is None."""
        assert constant_time_compare("test", None) is False
    
    def test_both_none_returns_false(self):
        """Should return False when both arguments are None."""
        assert constant_time_compare(None, None) is False
    
    def test_unicode_strings(self):
        """Should handle Unicode strings correctly."""
        assert constant_time_compare("hello世界", "hello世界") is True
        assert constant_time_compare("hello世界", "hello世界x") is False


class TestAuditLogger:
    """Tests for audit logging functionality."""
    
    @pytest.fixture
    def audit_logger(self, tmp_path):
        """Create audit logger with temporary file."""
        log_file = tmp_path / "test_audit.log"
        return AuditLogger(log_file=str(log_file))
    
    def test_log_event_writes_json(self, audit_logger, tmp_path):
        """Should log audit events in JSON format."""
        log_file = tmp_path / "test_audit.log"
        logger = AuditLogger(log_file=str(log_file))
        
        logger.log_event(
            event_type="TEST_EVENT",
            user_id="user-123",
            action="TEST"
        )
        
        # Read log file and verify JSON
        with open(log_file, 'r') as f:
            content = f.read().strip()
            log_entry = json.loads(content)
        
        assert log_entry["event_type"] == "TEST_EVENT"
        assert log_entry["user_id"] == "user-123"
        assert log_entry["action"] == "TEST"
        assert "timestamp" in log_entry
    
    def test_log_auth_success(self, audit_logger, tmp_path):
        """Should log authentication success."""
        log_file = tmp_path / "auth_success.log"
        logger = AuditLogger(log_file=str(log_file))
        
        logger.log_auth_success(user_id="user-456", ip_address="192.168.1.1")
        
        with open(log_file, 'r') as f:
            log_entry = json.loads(f.read().strip())
        
        assert log_entry["event_type"] == "AUTH_SUCCESS"
        assert log_entry["status"] == "SUCCESS"
    
    def test_log_auth_failure(self, audit_logger, tmp_path):
        """Should log authentication failure."""
        log_file = tmp_path / "auth_failure.log"
        logger = AuditLogger(log_file=str(log_file))
        
        logger.log_auth_failure(reason="Invalid password", ip_address="10.0.0.1")
        
        with open(log_file, 'r') as f:
            log_entry = json.loads(f.read().strip())
        
        assert log_entry["event_type"] == "AUTH_FAILURE"
        assert log_entry["status"] == "FAILURE"
        assert "Invalid password" in log_entry["details"]["reason"]
    
    def test_log_access_denied(self, audit_logger, tmp_path):
        """Should log authorization denial."""
        log_file = tmp_path / "access_denied.log"
        logger = AuditLogger(log_file=str(log_file))
        
        logger.log_access_denied(
            user_id="user-789",
            resource="/admin/users",
            reason="Insufficient permissions"
        )
        
        with open(log_file, 'r') as f:
            log_entry = json.loads(f.read().strip())
        
        assert log_entry["event_type"] == "ACCESS_DENIED"
        assert log_entry["status"] == "DENIED"
        assert log_entry["resource"] == "/admin/users"
    
    def test_log_filters_none_values(self, tmp_path):
        """Should filter out None values from log entries."""
        log_file = tmp_path / "filtered.log"
        logger = AuditLogger(log_file=str(log_file))
        
        logger.log_event(
            event_type="TEST",
            user_id="user-123",
            ip_address=None,  # Should be filtered
            resource=None,    # Should be filtered
            action="TEST"
        )
        
        with open(log_file, 'r') as f:
            log_entry = json.loads(f.read().strip())
        
        assert "ip_address" not in log_entry
        assert "resource" not in log_entry

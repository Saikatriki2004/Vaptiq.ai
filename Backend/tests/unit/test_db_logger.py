import pytest
from unittest.mock import MagicMock, patch
import json
from db_logger import DatabaseLogger

class TestDatabaseLogger:
    
    @pytest.fixture
    def mock_redis(self):
        with patch('db_logger.redis.from_url') as mock:
            client = MagicMock()
            mock.return_value = client
            yield client

    @pytest.fixture
    def logger(self, mock_redis):
        return DatabaseLogger("test-scan-id")

    def test_initialization(self, mock_redis):
        logger = DatabaseLogger("test-scan-id")
        assert logger.scan_id == "test-scan-id"
        assert logger.redis_client == mock_redis

    def test_log(self, logger, mock_redis):
        logger.log("INFO", "Test message")
        
        # Check rpush called
        mock_redis.rpush.assert_called_once()
        args = mock_redis.rpush.call_args
        assert args[0][0] == "scan:test-scan-id:logs"
        assert "[INFO] Test message" in args[0][1]
        
        # Check expire called
        mock_redis.expire.assert_called_once_with("scan:test-scan-id:logs", 86400)

    def test_update_status(self, logger, mock_redis):
        logger.update_status("RUNNING")
        
        mock_redis.set.assert_called_once_with("scan:test-scan-id:status", "RUNNING")
        mock_redis.expire.assert_called_once_with("scan:test-scan-id:status", 86400)

    def test_save_vulnerabilities(self, logger, mock_redis):
        vulns = [{"title": "Vuln 1"}, {"title": "Vuln 2"}]
        logger.save_vulnerabilities(vulns)
        
        mock_redis.set.assert_called_once_with(
            "scan:test-scan-id:vulnerabilities", 
            json.dumps(vulns)
        )
        mock_redis.expire.assert_called_once_with("scan:test-scan-id:vulnerabilities", 86400)

    def test_update_phase(self, logger, mock_redis):
        logger.update_phase("VERIFYING")
        
        mock_redis.set.assert_called_once_with("scan:test-scan-id:phase", "VERIFYING")
        mock_redis.expire.assert_called_once_with("scan:test-scan-id:phase", 86400)
        
        # Should also log the phase change
        # We can't easily check internal calls to self.log without mocking it, 
        # but we can check if rpush was called for the log
        assert mock_redis.rpush.call_count >= 1

    def test_update_progress(self, logger, mock_redis):
        logger.update_progress(50)
        
        mock_redis.set.assert_called_once_with("scan:test-scan-id:progress", "50")
        mock_redis.expire.assert_called_once_with("scan:test-scan-id:progress", 86400)

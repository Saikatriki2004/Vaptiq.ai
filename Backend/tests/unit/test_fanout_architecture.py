"""
Unit tests for Fan-Out/Fan-In Architecture and Consensus Engine
"""
import pytest
from unittest.mock import Mock, MagicMock, patch
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from models import Vulnerability


class TestConsensusCheck:
    """Tests for the consensus_check function that validates findings."""
    
    def test_open_ports_always_confirmed(self):
        """Open port findings from Nmap should always be confirmed."""
        from agent import consensus_check
        
        vuln = Vulnerability(
            title="Open Port 80 (http)",
            severity="INFO",
            description="Port is exposed.",
            remediation="Close if unused."
        )
        
        result = consensus_check(vuln, [])
        assert result == "CONFIRMED"
    
    def test_dry_run_results_confirmed(self):
        """Dry run infrastructure check results should be confirmed."""
        from agent import consensus_check
        
        vuln = Vulnerability(
            title="Dry Run Successful",
            severity="INFO",
            description="Target is reachable.",
            remediation="System ready for full scan."
        )
        
        result = consensus_check(vuln, [])
        assert result == "CONFIRMED"
    
    def test_security_violation_confirmed(self):
        """Security violations (blocked scans) should be confirmed."""
        from agent import consensus_check
        
        vuln = Vulnerability(
            title="Security Violation: Invalid Target",
            severity="CRITICAL",
            description="Private IP blocked.",
            remediation="Use public IP."
        )
        
        result = consensus_check(vuln, [])
        assert result == "CONFIRMED"
    
    def test_sql_injection_pending_verification(self):
        """SQL Injection findings should go to AI verification."""
        from agent import consensus_check
        
        vuln = Vulnerability(
            title="SQL Injection in login parameter",
            severity="HIGH",
            description="SQLi vulnerability detected.",
            remediation="Use parameterized queries."
        )
        
        result = consensus_check(vuln, [])
        assert result == "PENDING_VERIFICATION"
    
    def test_critical_findings_pending_verification(self):
        """CRITICAL severity findings should go to AI verification."""
        from agent import consensus_check
        
        vuln = Vulnerability(
            title="Remote Code Execution",
            severity="CRITICAL",
            description="RCE vulnerability detected.",
            remediation="Patch immediately."
        )
        
        result = consensus_check(vuln, [])
        assert result == "PENDING_VERIFICATION"
    
    def test_cross_validation_confirms(self):
        """Multiple tools finding same issue type should result in CONFIRMED."""
        from agent import consensus_check
        
        vuln1 = Vulnerability(
            title="Missing Security Headers",
            severity="MEDIUM",
            description="X-Frame-Options missing.",
            remediation="Add header."
        )
        
        vuln2 = Vulnerability(
            title="Security Header X-Content-Type-Options missing",
            severity="MEDIUM",
            description="X-Content-Type-Options missing.",
            remediation="Add header."
        )
        
        # Both are "header" type vulns, should cross-validate
        result = consensus_check(vuln1, [vuln1, vuln2])
        assert result == "CONFIRMED"
    
    def test_medium_severity_suspected(self):
        """MEDIUM severity without cross-validation should be SUSPECTED."""
        from agent import consensus_check
        
        vuln = Vulnerability(
            title="Information Disclosure",
            severity="MEDIUM",
            description="Server version exposed.",
            remediation="Hide version."
        )
        
        result = consensus_check(vuln, [])
        assert result == "SUSPECTED"


class TestExtractVulnType:
    """Tests for the _extract_vuln_type helper function."""
    
    def test_sql_injection_normalized(self):
        """SQL Injection titles should normalize to sql_injection."""
        from agent import _extract_vuln_type
        
        assert _extract_vuln_type("SQL Injection in login") == "sql_injection"
        assert _extract_vuln_type("Blind SQLi detected") == "sql_injection"
    
    def test_xss_normalized(self):
        """XSS titles should normalize to xss."""
        from agent import _extract_vuln_type
        
        assert _extract_vuln_type("Reflected XSS in search") == "xss"
        assert _extract_vuln_type("Cross-Site Scripting (CVE-2023-1234)") == "xss"
    
    def test_open_port_normalized(self):
        """Open port titles should normalize to open_port."""
        from agent import _extract_vuln_type
        
        assert _extract_vuln_type("Open Port 443 (https)") == "open_port"
    
    def test_ssl_normalized(self):
        """SSL/TLS titles should normalize to ssl_tls."""
        from agent import _extract_vuln_type
        
        assert _extract_vuln_type("Weak SSL Configuration") == "ssl_tls"
        assert _extract_vuln_type("TLS 1.0 Enabled") == "ssl_tls"


class TestCeleryTaskRegistration:
    """Tests to verify Celery tasks are properly registered."""
    
    def test_nmap_task_exists(self):
        """run_nmap_task should be a valid Celery task."""
        from tasks import run_nmap_task
        assert hasattr(run_nmap_task, 'delay')
        assert hasattr(run_nmap_task, 'apply_async')
    
    def test_zap_task_exists(self):
        """run_zap_task should be a valid Celery task."""
        from tasks import run_zap_task
        assert hasattr(run_zap_task, 'delay')
    
    def test_ssl_check_task_exists(self):
        """run_ssl_check_task should be a valid Celery task."""
        from tasks import run_ssl_check_task
        assert hasattr(run_ssl_check_task, 'delay')
    
    def test_orchestrator_exists(self):
        """start_orchestrated_scan should be a valid Celery task."""
        from tasks import start_orchestrated_scan
        assert hasattr(start_orchestrated_scan, 'delay')
    
    def test_aggregator_exists(self):
        """analyze_and_verify should be a valid Celery task."""
        from tasks import analyze_and_verify
        assert hasattr(analyze_and_verify, 'delay')
    
    def test_legacy_task_exists(self):
        """Legacy run_background_scan should still exist for backwards compatibility."""
        from tasks import run_background_scan
        assert hasattr(run_background_scan, 'delay')


class TestSmartRetryConfig:
    """Tests for the smart retry configuration."""
    
    def test_task_annotations_configured(self):
        """Celery task_annotations should be configured for scanner tasks."""
        from celery_config import celery_app
        
        annotations = celery_app.conf.task_annotations
        assert annotations is not None
        assert 'scan.run_nmap_task' in annotations
        assert 'scan.run_zap_task' in annotations
        assert 'scan.run_ssl_check_task' in annotations
    
    def test_nmap_rate_limit(self):
        """Nmap task should have rate limiting configured."""
        from celery_config import celery_app
        
        nmap_config = celery_app.conf.task_annotations.get('scan.run_nmap_task', {})
        assert nmap_config.get('rate_limit') == '10/m'
        assert nmap_config.get('max_retries') == 5
    
    def test_retry_backoff_enabled(self):
        """Tasks should have retry backoff enabled."""
        from celery_config import celery_app
        
        nmap_config = celery_app.conf.task_annotations.get('scan.run_nmap_task', {})
        assert nmap_config.get('retry_backoff') is True

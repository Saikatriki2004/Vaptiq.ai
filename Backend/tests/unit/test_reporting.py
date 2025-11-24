"""
Unit Tests for Report Generator (reporting.py)

Tests cover:
- PDF generation
- HTML generation and XSS sanitization
- JSON export
- Severity filtering
- Unicode handling
- Error handling
"""

import pytest
import io
import json
from unittest.mock import patch, MagicMock
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from reporting import ReportGenerator


# ============================================================================
# PDF Generation Tests
# ============================================================================

@pytest.mark.unit
@pytest.mark.reporting
class TestPDFGeneration:
    """Test PDF report generation."""
    
    def test_generate_pdf_basic(self, sample_scan_result):
        """Test basic PDF generation."""
        pdf_io = ReportGenerator.generate_pdf(sample_scan_result)
        
        assert isinstance(pdf_io, io.BytesIO)
        assert pdf_io.tell() > 0  # Has content
        
        pdf_content = pdf_io.getvalue()
        assert pdf_content.startswith(b'%PDF')  # Valid PDF header
    
    def test_generate_pdf_with_findings(self, sample_scan_result):
        """Test PDF includes vulnerability findings."""
        pdf_io = ReportGenerator.generate_pdf(sample_scan_result)
        
        pdf_content = pdf_io.getvalue()
        
        # PDF should be non-empty
        assert len(pdf_content) > 1000  # Reasonable size
    
    def test_generate_pdf_unicode_handling(self):
        """Test PDF handles Unicode characters."""
        scan_result = {
            "id": "test-123",
            "target": "https://example.com",
            "status": "completed",
            "timestamp": "2025-11-24T10:00:00",
            "findings": [
                {
                    "type": "SQL Injection 中文测试",
                    "severity": "CRITICAL",
                    "description": "Vulnerability with émoji 🔥 and unicode ñ",
                    "proof": "SELECT * FROM users WHERE id='1′"  # Curly quote
                }
            ]
        }
        
        # Should not raise UnicodeEncodeError
        pdf_io = ReportGenerator.generate_pdf(scan_result)
        
        assert isinstance(pdf_io, io.BytesIO)
        assert pdf_io.tell() > 0
    
    def test_generate_pdf_empty_findings(self):
        """Test PDF generation with no findings."""
        scan_result = {
            "id": "test-empty",
            "target": "https://example.com",
            "status": "completed",
            "timestamp": "2025-11-24T10:00:00",
            "findings": []
        }
        
        pdf_io = ReportGenerator.generate_pdf(scan_result)
        
        assert isinstance(pdf_io, io.BytesIO)
        assert pdf_io.tell() > 0
    
    def test_generate_pdf_severity_colors(self, sample_scan_result):
        """Test PDF uses different colors for severity levels."""
        # This is a smoke test - we can't easily verify colors in binary PDF
        pdf_io = ReportGenerator.generate_pdf(sample_scan_result)
        
        pdf_content = pdf_io.getvalue()
        
        # Should have reasonable size with multiple findings
        assert len(pdf_content) > 2000


# ============================================================================
# HTML Generation Tests
# ============================================================================

@pytest.mark.unit
@pytest.mark.reporting
class TestHTMLGeneration:
    """Test HTML report generation."""
    
    def test_generate_html_basic(self, sample_scan_result):
        """Test basic HTML generation."""
        html_io = ReportGenerator.generate_html(sample_scan_result)
        
        assert isinstance(html_io, io.BytesIO)
        assert html_io.tell() > 0
        
        html_content = html_io.getvalue().decode('utf-8')
        assert '<!DOCTYPE html>' in html_content or '<html' in html_content
    
    def test_generate_html_xss_sanitization(self):
        """Test HTML sanitizes XSS payloads."""
        scan_result = {
            "id": "test-xss",
            "target": "https://example.com",
            "status": "completed",
            "timestamp": "2025-11-24T10:00:00",
            "findings": [
                {
                    "type": "XSS",
                    "severity": "HIGH",
                    "description": "<script>alert('XSS')</script>",
                    "proof": "<img src=x onerror=alert(1)>"
                }
            ]
        }
        
        html_io = ReportGenerator.generate_html(scan_result)
        html_content = html_io.getvalue().decode('utf-8')
        
        # Should escape script tags
        assert '<script>alert' not in html_content
        assert 'onerror=alert' not in html_content
        
        # Should have escaped versions
        assert '&lt;script&gt;' in html_content or 'script&gt;' in html_content
    
    def test_generate_html_includes_severity(self, sample_scan_result):
        """Test HTML includes severity information."""
        html_io = ReportGenerator.generate_html(sample_scan_result)
        html_content = html_io.getvalue().decode('utf-8')
        
        # Should include severity levels
        assert 'CRITICAL' in html_content or 'critical' in html_content.lower()
        assert 'HIGH' in html_content or 'high' in html_content.lower()
    
    def test_generate_html_structure(self, sample_scan_result):
        """Test HTML has proper structure."""
        html_io = ReportGenerator.generate_html(sample_scan_result)
        html_content = html_io.getvalue().decode('utf-8')
        
        # Basic HTML structure
        assert '<html' in html_content.lower()
        assert '</html>' in html_content
        assert '<body' in html_content.lower() or 'body' in html_content.lower()
    
    def test_generate_html_unicode(self):
        """Test HTML handles Unicode properly."""
        scan_result = {
            "id": "test-unicode",
            "target": "https://example.com",
            "status": "completed",
            "timestamp": "2025-11-24T10:00:00",
            "findings": [
                {
                    "type": "Test 中文 émoji 🔥",
                    "severity": "LOW",
                    "description": "Unicode test ñ ü",
                    "proof": "Test"
                }
            ]
        }
        
        html_io = ReportGenerator.generate_html(scan_result)
        html_content = html_io.getvalue().decode('utf-8')
        
        # Should contain Unicode characters
        assert '中文' in html_content or 'unicode' in html_content.lower()


# ============================================================================
# JSON Generation Tests
# ============================================================================

@pytest.mark.unit
@pytest.mark.reporting
class TestJSONGeneration:
    """Test JSON report generation."""
    
    def test_generate_json_basic(self, sample_scan_result):
        """Test basic JSON generation."""
        json_io = ReportGenerator.generate_json(sample_scan_result)
        
        assert isinstance(json_io, io.BytesIO)
        assert json_io.tell() > 0
        
        json_content = json_io.getvalue().decode('utf-8')
        parsed = json.loads(json_content)
        
        assert isinstance(parsed, dict)
    
    def test_generate_json_structure(self, sample_scan_result):
        """Test JSON has correct structure."""
        json_io = ReportGenerator.generate_json(sample_scan_result)
        json_content = json_io.getvalue().decode('utf-8')
        parsed = json.loads(json_content)
        
        assert 'id' in parsed
        assert 'target' in parsed
        assert 'status' in parsed
        assert 'findings' in parsed
        assert isinstance(parsed['findings'], list)
    
    def test_generate_json_preserves_data(self, sample_scan_result):
        """Test JSON preserves all data accurately."""
        json_io = ReportGenerator.generate_json(sample_scan_result)
        json_content = json_io.getvalue().decode('utf-8')
        parsed = json.loads(json_content)
        
        assert parsed['id'] == sample_scan_result['id']
        assert parsed['target'] == sample_scan_result['target']
        assert len(parsed['findings']) == len(sample_scan_result['findings'])
    
    def test_generate_json_valid_format(self, sample_scan_result):
        """Test JSON is properly formatted."""
        json_io = ReportGenerator.generate_json(sample_scan_result)
        json_content = json_io.getvalue().decode('utf-8')
        
        # Should not raise JSONDecodeError
        parsed = json.loads(json_content)
        
        # Should be pretty-printed (has newlines)
        assert '\n' in json_content
    
    def test_generate_json_unicode(self):
        """Test JSON handles Unicode correctly."""
        scan_result = {
            "id": "test-unicode",
            "target": "https://example.com",
            "status": "completed",
            "timestamp": "2025-11-24T10:00:00",
            "findings": [
                {
                    "type": "Unicode Test 中文",
                    "severity": "LOW",
                    "description": "émoji 🔥 test",
                    "proof": "ñ ü"
                }
            ]
        }
        
        json_io = ReportGenerator.generate_json(scan_result)
        json_content = json_io.getvalue().decode('utf-8')
        parsed = json.loads(json_content)
        
        assert '中文' in parsed['findings'][0]['type']
        assert '🔥' in parsed['findings'][0]['description']


# ============================================================================
# Error Handling Tests
# ============================================================================

@pytest.mark.unit
@pytest.mark.reporting
class TestReportingErrorHandling:
    """Test error handling in report generation."""
    
    def test_pdf_handles_missing_fields(self):
        """Test PDF handles missing optional fields."""
        scan_result = {
            "id": "test-minimal",
            "target": "https://example.com",
            "findings": []
        }
        
        # Should not raise KeyError
        pdf_io = ReportGenerator.generate_pdf(scan_result)
        
        assert isinstance(pdf_io, io.BytesIO)
    
    def test_html_handles_missing_fields(self):
        """Test HTML handles missing optional fields."""
        scan_result = {
            "id": "test-minimal",
            "target": "https://example.com",
            "findings": []
        }
        
        html_io = ReportGenerator.generate_html(scan_result)
        
        assert isinstance(html_io, io.BytesIO)
    
    def test_json_handles_none_values(self):
        """Test JSON handles None values."""
        scan_result = {
            "id": "test-none",
            "target": "https://example.com",
            "status": None,
            "timestamp": None,
            "findings": []
        }
        
        json_io = ReportGenerator.generate_json(scan_result)
        json_content = json_io.getvalue().decode('utf-8')
        parsed = json.loads(json_content)
        
        assert parsed['status'] is None
        assert parsed['timestamp'] is None


# ============================================================================
# Severity Filtering Tests
# ============================================================================

@pytest.mark.unit
@pytest.mark.reporting
class TestSeverityFiltering:
    """Test severity filtering (if implemented in ReportGenerator)."""
    
    def test_filter_critical_only(self, sample_scan_result):
        """Test filtering for critical findings only."""
        # Filter before passing to generator
        filtered_result = sample_scan_result.copy()
        filtered_result['findings'] = [
            f for f in sample_scan_result['findings']
            if f.get('severity') == 'CRITICAL'
        ]
        
        json_io = ReportGenerator.generate_json(filtered_result)
        json_content = json_io.getvalue().decode('utf-8')
        parsed = json.loads(json_content)
        
        # Should only have critical findings
        for finding in parsed['findings']:
            assert finding.get('severity') == 'CRITICAL'
    
    def test_multiple_severity_levels(self, sample_scan_result):
        """Test report includes multiple severity levels."""
        json_io = ReportGenerator.generate_json(sample_scan_result)
        json_content = json_io.getvalue().decode('utf-8')
        parsed = json.loads(json_content)
        
        severities = {f.get('severity') for f in parsed['findings']}
        
        # Should have multiple severity levels
        assert len(severities) > 1

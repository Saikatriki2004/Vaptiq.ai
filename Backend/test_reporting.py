import io
import pytest
from datetime import datetime
from reporting import ReportGenerator

def _sample_scan_result(overrides=None):
    base = {
        "target": "example.com",
        "findings": [
            {
                "severity": "HIGH",
                "type": "SQL Injection",
                "description": "Unsanitized input in login form.",
                "proof": "GET /login?user=' OR 1=1 --"
            },
            {
                "severity": "LOW",
                "type": "Server Banner Disclosure",
                "description": "Server discloses version banner.",
                "proof": None,
            },
        ],
    }
    if overrides:
        base.update(overrides)
    return base

def test_generate_pdf_returns_bytesio_and_non_empty():
    scan_result = _sample_scan_result()
    pdf_stream = ReportGenerator.generate_pdf(scan_result)
    
    assert isinstance(pdf_stream, io.BytesIO)
    data = pdf_stream.getvalue()
    assert isinstance(data, (bytes, bytearray))
    assert len(data) > 0
    # Basic PDF magic header check
    assert data.startswith(b"%PDF")

def test_generate_pdf_handles_missing_optional_fields():
    scan_result = {
        "target": "missing-fields.test",
        "findings": [
            {
                # no severity, type, description, or proof
            }
        ],
    }
    pdf_stream = ReportGenerator.generate_pdf(scan_result)
    data = pdf_stream.getvalue()
    assert data.startswith(b"%PDF")

def test_generate_pdf_sanitizes_unicode_text():
    scan_result = _sample_scan_result({
        "target": "unicod\u000123\u000124",
        "findings": [
            {
                "severity": "critical",
                "type": "Curly\u2018quote",
                "description": "Description with fancy quotes \u2018\u2019 and dash \u2013",
                "proof": "Proof with fancy \u2018\u2019 and dash \u2013",
            }
        ],
    })
    pdf_stream = ReportGenerator.generate_pdf(scan_result)
    data = pdf_stream.getvalue()
    assert data.startswith(b"%PDF")

def test_generate_html_returns_bytesio_and_contains_target_and_findings():
    scan_result = _sample_scan_result()
    html_stream = ReportGenerator.generate_html(scan_result)
    
    assert isinstance(html_stream, io.BytesIO)
    html = html_stream.getvalue().decode("utf-8")
    
    assert "Vaptiq.ai Report" in html
    assert "example.com" in html
    assert "SQL Injection" in html
    assert "Unsanitized input in login form." in html
    assert "PROOF OF EXPLOIT" in html

def test_generate_json_returns_pretty_printed_json_bytes():
    scan_result = _sample_scan_result()
    json_stream = ReportGenerator.generate_json(scan_result)
    
    assert isinstance(json_stream, io.BytesIO)
    payload = json_stream.getvalue().decode("utf-8")
    
    assert "\n  " in payload  # pretty printed with indentation
    assert '"target": "example.com"' in payload
    assert '"findings"' in payload

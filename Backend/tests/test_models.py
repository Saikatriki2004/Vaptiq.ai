from Backend.models import ScanTarget, Vulnerability, ScanResult

def test_scan_target_creation():
    target = ScanTarget(type="URL", value="http://example.com", tags=["web"])
    assert target.type == "URL"
    assert target.value == "http://example.com"
    assert target.tags == ["web"]

def test_vulnerability_creation():
    vuln = Vulnerability(
        title="Test Vuln",
        severity="HIGH",
        description="A test vulnerability",
        remediation="Fix it"
    )
    assert vuln.title == "Test Vuln"
    assert vuln.severity == "HIGH"
    assert vuln.status == "SUSPECTED"
    assert vuln.description == "A test vulnerability"
    assert vuln.remediation == "Fix it"
    assert vuln.proof_of_exploit is None

def test_scan_result_creation():
    vuln = Vulnerability(
        title="Test Vuln",
        severity="HIGH",
        description="A test vulnerability",
        remediation="Fix it"
    )
    result = ScanResult(tool="TestTool", findings=[vuln])
    assert result.tool == "TestTool"
    assert len(result.findings) == 1
    assert result.findings[0].title == "Test Vuln"
    assert result.error is None

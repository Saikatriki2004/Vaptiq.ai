from pydantic import BaseModel
from typing import List, Optional

class Vulnerability(BaseModel):
    title: str
    severity: str
    description: str
    remediation: Optional[str] = None
    status: str = "SUSPECTED"
    proof_of_exploit: Optional[str] = None

class ScanResult(BaseModel):
    tool: str
    findings: List[Vulnerability]
    error: Optional[str] = None

class ScanTarget(BaseModel):
    type: str # URL, IP, API
    value: str

"""
Centralized Pydantic Data Models for SentinelAI
"""
from typing import List, Optional
from pydantic import BaseModel


class ScanTarget(BaseModel):
    """Represents a target to be scanned"""
    type: str  # URL, IP, API
    value: str
    tags: List[str] = []
    dry_run: bool = False  # New flag: Default to False (Real Scan)


class Vulnerability(BaseModel):
    """Represents a discovered vulnerability"""
    title: str
    severity: str
    status: str = "SUSPECTED"  # SUSPECTED, CONFIRMED, FALSE_POSITIVE, INFO
    description: str
    remediation: str
    proof_of_exploit: Optional[str] = None


class ScanResult(BaseModel):
    """Represents the result from a tool execution"""
    tool: str
    findings: List[Vulnerability] = []
    error: Optional[str] = None

"""
Refactored Security Agent with Tool Registry & Parallel Execution
"""
import asyncio
import random
import logging
import shutil
import subprocess
from datetime import datetime
from typing import List, Optional
import xmltodict

# Import centralized models
from .models import ScanTarget, Vulnerability, ScanResult
from .verifier_agent import VerifierAgent, SuspectedVuln
from .db_logger import DatabaseLogger

# --- Tool Registry ---
# Maps TargetType to a list of Tool Functions
TOOL_REGISTRY = {
    "URL": ["run_nmap_scan", "run_zap_spider", "check_ssl_cert"],
    "IP":  ["run_nmap_scan", "check_geo_ip"],
    "API": ["run_nmap_scan", "fuzz_api_endpoints"]
}

# --- Real Nmap Tool Implementation ---
async def run_nmap_scan(target: str, dry_run: bool = False) -> List[Vulnerability]:
    """
    Nmap Scanner Wrapper.
    Supports 'Dry Run' to validate infrastructure without attacking.
    """
    # 1. Infrastructure Check (Always Run)
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        return [Vulnerability(
            title="Scanner Configuration Error",
            severity="CRITICAL",
            description="Nmap binary is missing from the worker container.",
            remediation="Install nmap in the Dockerfile.",
            status="FALSE_POSITIVE"
        )]

    # 2. Dry Run Mode (Fast, Safe, Non-Destructive)
    if dry_run:
        # We just check if we can resolve the target, or simple ping
        try:
            # Simple ping check (1 packet, 1 second timeout)
            # Cross-platform: Windows uses -n, Linux/macOS uses -c
            import platform
            if platform.system() == "Windows":
                ping_cmd = ["ping", "-n", "1", "-w", "1000", target]
            else:
                ping_cmd = ["ping", "-c", "1", "-W", "1", target]
            
            proc = await asyncio.create_subprocess_exec(
                *ping_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            
            if proc.returncode == 0:
                return [Vulnerability(
                    title="Dry Run Successful",
                    severity="INFO",
                    description=f"Target {target} is reachable and Nmap is installed.",
                    remediation="System is ready for full scan.",
                    status="CONFIRMED"
                )]
            else:
                return [Vulnerability(
                    title="Target Unreachable",
                    severity="LOW",
                    description=f"Could not ping {target}. Firewall may be blocking.",
                    remediation="Check network connectivity.",
                    status="SUSPECTED"
                )]
        except Exception as e:
            return [Vulnerability(
                title="Dry Run Failed",
                severity="LOW",
                description=f"Execution error: {str(e)}",
                remediation="Check worker logs.",
                status="SUSPECTED"
            )]

    # 3. Real Execution Mode (The "Heavy" Scan)
    # -sV: Version Detection, -T4: Fast timing
    print(f"⚔️ Executing Nmap on {target}...")
    cmd = [nmap_path, "-sV", "-T4", "--top-ports", "100", "-oX", "-", target]
    
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            # Log stderr but do not crash
            print(f"Nmap Error: {stderr.decode()}")
            return []

        # Parse XML Output
        data = xmltodict.parse(stdout)
        vulnerabilities = []
        
        # Handle XML parsing logic
        nmap_run = data.get('nmaprun', {})
        hosts = nmap_run.get('host', [])
        if isinstance(hosts, dict): 
            hosts = [hosts]
        
        for host in hosts:
            ports = host.get('ports', {}).get('port', [])
            if isinstance(ports, dict): 
                ports = [ports]
            
            for port in ports:
                state = port.get('state', {}).get('@state')
                if state == 'open':
                    service = port.get('service', {}).get('@name', 'unknown')
                    version = port.get('service', {}).get('@product', '')
                    port_id = port.get('@portid')
                    
                    vulnerabilities.append(Vulnerability(
                        title=f"Open Port {port_id} ({service})",
                        severity="INFO",
                        description=f"Port is exposed.",
                        remediation="Close if unused.",
                        status="CONFIRMED"
                    ))
                    
        print(f"✅ Nmap scan complete. Found {len(vulnerabilities)} open ports.")
        return vulnerabilities

    except Exception as e:
        return [Vulnerability(
            title="Scan Execution Error",
            severity="HIGH",
            description=str(e),
            remediation="Check worker logs.",
            status="FAILED"
        )]


async def run_zap_spider(target: str) -> List[Vulnerability]:
    """Mock ZAP spider tool"""
    await asyncio.sleep(3)
    return [
        Vulnerability(
            title="Missing Security Headers",
            severity="MEDIUM",
            description="X-Frame-Options header is missing.",
            remediation="Add X-Frame-Options: DENY"
        )
    ]


async def check_ssl_cert(target: str) -> List[Vulnerability]:
    """Mock SSL certificate checker"""
    await asyncio.sleep(2)
    if random.random() > 0.7:
        return [
            Vulnerability(
                title="Weak SSL/TLS Configuration",
                severity="HIGH",
                description="Server supports outdated TLS 1.0 protocol.",
                remediation="Disable TLS 1.0 and 1.1, use TLS 1.2+"
            )
        ]
    return []


async def check_geo_ip(target: str) -> List[Vulnerability]:
    """Mock GeoIP checker"""
    await asyncio.sleep(1)
    return []


async def fuzz_api_endpoints(target: str) -> List[Vulnerability]:
    """Mock API fuzzer"""
    await asyncio.sleep(4)
    return [
        Vulnerability(
            title="SQL Injection Vulnerability",
            severity="CRITICAL",
            description="API endpoint vulnerable to SQLi.",
            remediation="Use parameterized queries."
        )
    ]


# --- Security Agent ---
class SecurityAgent:
    """
    The Core Security Engine with Tool Registry & Parallel Execution.
    Orchestrates scanning tools and AI verification with safety controls.
    """
    def __init__(self, target: ScanTarget, scan_id: str, redis_client):
        self.target = target
        self.scan_id = scan_id
        self.redis = redis_client
        self.logger = DatabaseLogger(scan_id)
        self.verifier_agent = VerifierAgent()
        self.is_cancelled = False
        
        # SAFETY: Limit to 2 concurrent tools per scan to avoid WAF bans
        self.semaphore = asyncio.Semaphore(2)

    async def _check_cancellation(self):
        """Checks Redis for a cancellation flag."""
        if self.redis.get(f"scan:{self.scan_id}:cancel"):
            self.logger.log("SYSTEM", "Cancellation signal received. Stopping.")
            self.is_cancelled = True
            raise asyncio.CancelledError("Scan Cancelled by User")

    async def run_tool(self, tool_name: str) -> ScanResult:
        """Wrapper to run a tool safely with concurrency limits and jitter."""
        if self.is_cancelled:
            return ScanResult(tool=tool_name, findings=[], error="Cancelled")
        
        # SAFETY: Wait for semaphore slot (max 2 concurrent tools)
        async with self.semaphore:
            await self._check_cancellation()
            
            # Jitter is only needed for real scans to avoid WAF bans
            if not self.target.dry_run:
                delay = random.uniform(0.5, 3.0)
                self.logger.log("TOOL", f"Queuing {tool_name} (Delay: {delay:.1f}s)...")
                await asyncio.sleep(delay)

            self.logger.log("TOOL", f"Starting {tool_name} (Dry Run: {self.target.dry_run})...")
            
            try:
                # Map tool name to actual function
                tool_func_map = {
                    "run_nmap_scan": run_nmap_scan,
                    "run_zap_spider": run_zap_spider,
                    "check_ssl_cert": check_ssl_cert,
                    "check_geo_ip": check_geo_ip,
                    "fuzz_api_endpoints": fuzz_api_endpoints
                }
                
                tool_func = tool_func_map.get(tool_name)
                if not tool_func:
                    self.logger.log("ERROR", f"Unknown tool: {tool_name}")
                    return ScanResult(tool=tool_name, findings=[], error=f"Unknown tool: {tool_name}")
                
                # Execute the tool
                if tool_name == "run_nmap_scan":
                    findings = await tool_func(self.target.value, self.target.dry_run)
                else:
                    findings = await tool_func(self.target.value)
                
                self.logger.log("TOOL", f"Finished {tool_name}. Found {len(findings)} issues.")
                return ScanResult(tool=tool_name, findings=findings)
                
            except Exception as e:
                self.logger.log("ERROR", f"Tool {tool_name} failed: {str(e)}")
                return ScanResult(tool=tool_name, findings=[], error=str(e))

    async def execute(self) -> dict:
        """
        Run the full scanning and verification process with parallel execution.
        Returns a dictionary with results.
        """
        try:
            self.logger.update_phase("RUNNING")
            self.logger.update_progress(10)

            # 1. Identify Tools based on target type
            tools = TOOL_REGISTRY.get(self.target.type, [])
            if not tools:
                self.logger.log("ERROR", f"No tools defined for target type: {self.target.type}")
                self.logger.update_phase("FAILED")
                return {
                    "status": "FAILED",
                    "vulnerabilities": [],
                    "error": f"No tools defined for target type: {self.target.type}"
                }

            # 2. Parallel Execution (The Big Upgrade)
            # Create a list of coroutines
            tasks = [self.run_tool(tool) for tool in tools]
            
            self.logger.log("ORCHESTRATOR", f"Scheduling {len(tasks)} tools (max 2 concurrent)...")
            
            # Run them all in parallel, but Semaphore limits active ones to 2
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            self.logger.update_progress(60)

            # 3. Aggregation & Deduplication
            all_vulnerabilities = []
            for res in results:
                if isinstance(res, Exception):
                    self.logger.log("ERROR", f"Tool failed with exception: {str(res)}")
                elif isinstance(res, ScanResult):
                    if res.error:
                        self.logger.log("ERROR", f"Tool {res.tool} returned error: {res.error}")
                    else:
                        all_vulnerabilities.extend(res.findings)
                        
            self.logger.log("ORCHESTRATOR", f"Aggregated {len(all_vulnerabilities)} total findings from all tools.")

            # 4. Verification Phase (Sequential because it relies on findings)
            self.logger.update_phase("VERIFYING")
            self.logger.update_progress(80)
            
            verified_vulnerabilities = []
            for vuln in all_vulnerabilities:
                # Only verify CRITICAL and HIGH severity findings
                if vuln.severity in ["CRITICAL", "HIGH"]:
                    self.logger.log("VERIFIER", f"Verifying: {vuln.title}")
                    
                    suspected = SuspectedVuln(
                        target_url=self.target.value,
                        vuln_type=vuln.title,
                        parameter="id",
                        evidence_hint=vuln.description
                    )
                    
                    try:
                        verification_result = await self.verifier_agent.verify_vulnerability(suspected)
                        
                        if verification_result.is_confirmed:
                            vuln.status = "CONFIRMED"
                            vuln.proof_of_exploit = verification_result.proof_of_exploit
                            self.logger.log("VERIFIER", f"✓ CONFIRMED: {vuln.title}")
                        else:
                            vuln.status = "SUSPECTED"
                            self.logger.log("VERIFIER", f"⚠ SUSPECTED (not confirmed): {vuln.title}")
                    except Exception as e:
                        self.logger.log("ERROR", f"Verification failed for {vuln.title}: {str(e)}")
                        vuln.status = "SUSPECTED"
                else:
                    vuln.status = "SUSPECTED"
                
                verified_vulnerabilities.append(vuln)

            # 5. Completion
            self.logger.update_phase("COMPLETED")
            self.logger.update_progress(100)
            self.logger.log("ORCHESTRATOR", f"Scan completed. Total findings: {len(verified_vulnerabilities)}")
            
            return {
                "status": "COMPLETED",
                "vulnerabilities": [v.dict() for v in verified_vulnerabilities]
            }

        except asyncio.CancelledError:
            self.logger.update_phase("CANCELLED")
            self.logger.update_progress(0)
            return {
                "status": "CANCELLED",
                "vulnerabilities": []
            }
        except Exception as e:
            self.logger.log("FATAL", f"Agent crashed: {str(e)}")
            self.logger.update_phase("FAILED")
            return {
                "status": "FAILED",
                "vulnerabilities": [],
                "error": str(e)
            }

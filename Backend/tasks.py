"""
Fan-Out/Fan-In Celery Worker with Chord Orchestration

Architecture:
- Individual tool tasks (fan-out) run on separate workers for true parallelism
- Chord aggregates results (fan-in) for consensus checking
- Smart retries and credit refund for resilience
"""
import asyncio
import redis
import os
import shutil
from typing import List, Dict, Any
from celery import chain, chord, group
from celery.exceptions import SoftTimeLimitExceeded
from .celery_config import celery_app
from .agent import SecurityAgent, run_nmap_scan, run_zap_spider, check_ssl_cert, consensus_check
from .models import ScanTarget, Vulnerability
from .db_logger import DatabaseLogger
from .db import db
from .security import sanitize_target

# Initialize Redis for the worker to read flags
redis_client = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))


async def _refund_user(user_id: str, amount: int, scan_id: str, reason: str):
    """
    Atomically refund credits and log transaction.
    
    This function is critical for preventing user churn from system failures.
    Without refunds, users lose credits every time:
    - Celery worker crashes (OOM kill)
    - Network timeout occurs
    - LLM API is down
    - Target server is unreachable
    
    Args:
        user_id: User to refund
        amount: Number of credits to refund
        scan_id: Scan that failed
        reason: Explanation for refund
    """
    await db.user.update(
        where={"id": user_id},
        data={"credits": {"increment": amount}}
    )
    
    await db.credittransaction.create(data={
        "userId": user_id,
        "amount": amount,
        "type": "SCAN_REFUND_ERROR",
        "scanId": scan_id,
        "reason": reason
    })
    
    print(f"✅ Refunded {amount} credits to user {user_id[:8]}... (Reason: {reason})")


# =============================================================================
# INDIVIDUAL TOOL TASKS (Fan-Out)
# Each task runs on a SEPARATE worker for TRUE PARALLELISM
# =============================================================================

@celery_app.task(bind=True, name="scan.run_nmap_task")
def run_nmap_task(self, recon_data: dict) -> dict:
    """
    Execute ONLY Nmap scan. Runs on a separate worker for true parallelism.
    
    Args:
        recon_data: Contains target info and scan_id from recon task
        
    Returns:
        dict with tool name and findings list
    """
    target = recon_data.get("target", "")
    target_type = recon_data.get("target_type", "URL")
    dry_run = recon_data.get("dry_run", False)
    scan_id = recon_data.get("scan_id", "unknown")
    
    logger = DatabaseLogger(scan_id)
    logger.log("NMAP", f"Starting Nmap scan on {target}...")
    
    try:
        # Run the async nmap scanner
        findings = asyncio.run(run_nmap_scan(target, target_type, dry_run))
        
        logger.log("NMAP", f"Nmap completed. Found {len(findings)} findings.")
        
        return {
            "tool": "nmap",
            "findings": [f.dict() for f in findings],
            "target": target,
            "scan_id": scan_id
        }
    except Exception as e:
        logger.log("NMAP", f"Nmap failed: {str(e)}")
        return {
            "tool": "nmap",
            "findings": [],
            "error": str(e),
            "scan_id": scan_id
        }


@celery_app.task(bind=True, name="scan.run_zap_task")
def run_zap_task(self, recon_data: dict) -> dict:
    """
    Execute ONLY ZAP spider. Runs on a separate worker.
    
    Args:
        recon_data: Contains target info and scan_id from recon task
        
    Returns:
        dict with tool name and findings list
    """
    target = recon_data.get("target", "")
    scan_id = recon_data.get("scan_id", "unknown")
    dry_run = recon_data.get("dry_run", False)
    
    logger = DatabaseLogger(scan_id)
    
    # Skip ZAP in dry run mode
    if dry_run:
        logger.log("ZAP", "Skipping ZAP in dry run mode")
        return {
            "tool": "zap",
            "findings": [],
            "scan_id": scan_id,
            "skipped": True
        }
    
    logger.log("ZAP", f"Starting ZAP spider on {target}...")
    
    try:
        findings = asyncio.run(run_zap_spider(target))
        
        logger.log("ZAP", f"ZAP completed. Found {len(findings)} findings.")
        
        return {
            "tool": "zap",
            "findings": [f.dict() for f in findings],
            "target": target,
            "scan_id": scan_id
        }
    except Exception as e:
        logger.log("ZAP", f"ZAP failed: {str(e)}")
        return {
            "tool": "zap",
            "findings": [],
            "error": str(e),
            "scan_id": scan_id
        }


@celery_app.task(bind=True, name="scan.run_ssl_check_task")
def run_ssl_check_task(self, recon_data: dict) -> dict:
    """
    Execute ONLY SSL certificate check.
    
    Args:
        recon_data: Contains target info and scan_id from recon task
        
    Returns:
        dict with tool name and findings list
    """
    target = recon_data.get("target", "")
    scan_id = recon_data.get("scan_id", "unknown")
    dry_run = recon_data.get("dry_run", False)
    
    logger = DatabaseLogger(scan_id)
    
    if dry_run:
        logger.log("SSL", "Skipping SSL check in dry run mode")
        return {
            "tool": "ssl_check",
            "findings": [],
            "scan_id": scan_id,
            "skipped": True
        }
    
    logger.log("SSL", f"Checking SSL/TLS for {target}...")
    
    try:
        findings = asyncio.run(check_ssl_cert(target))
        
        logger.log("SSL", f"SSL check completed. Found {len(findings)} issues.")
        
        return {
            "tool": "ssl_check",
            "findings": [f.dict() for f in findings],
            "target": target,
            "scan_id": scan_id
        }
    except Exception as e:
        logger.log("SSL", f"SSL check failed: {str(e)}")
        return {
            "tool": "ssl_check",
            "findings": [],
            "error": str(e),
            "scan_id": scan_id
        }


@celery_app.task(bind=True, name="scan.run_nikto_task")
def run_nikto_task(self, recon_data: dict) -> dict:
    """
    Execute Nikto web scanner (placeholder for future implementation).
    
    Args:
        recon_data: Contains target info and scan_id from recon task
        
    Returns:
        dict with tool name and findings list
    """
    scan_id = recon_data.get("scan_id", "unknown")
    dry_run = recon_data.get("dry_run", False)
    
    logger = DatabaseLogger(scan_id)
    
    if dry_run:
        logger.log("NIKTO", "Skipping Nikto in dry run mode")
        return {
            "tool": "nikto",
            "findings": [],
            "scan_id": scan_id,
            "skipped": True
        }
    
    # TODO: Implement real Nikto integration
    logger.log("NIKTO", "Nikto scanner not yet implemented")
    return {
        "tool": "nikto",
        "findings": [],
        "scan_id": scan_id,
        "not_implemented": True
    }


# =============================================================================
# RECON TASK (Sequential - runs first)
# =============================================================================

@celery_app.task(bind=True, name="scan.run_recon_task")
def run_recon_task(self, target_data: dict, scan_id: str) -> dict:
    """
    Initial reconnaissance - validates target and prepares scan context.
    This runs BEFORE the parallel fan-out tasks.
    
    Args:
        target_data: Original target dict from API
        scan_id: Unique scan identifier
        
    Returns:
        dict with sanitized target info for downstream tasks
    """
    logger = DatabaseLogger(scan_id)
    logger.update_phase("RECON")
    logger.update_progress(5)
    
    target_value = target_data.get("value", "")
    target_type = target_data.get("type", "URL")
    dry_run = target_data.get("dry_run", False)
    
    logger.log("RECON", f"Starting reconnaissance on {target_value}...")
    
    try:
        # Sanitize and validate target (SSRF protection)
        safe_target = sanitize_target(target_value, target_type)
        logger.log("RECON", f"Target validated: {safe_target}")
        
        # Return recon data for downstream tasks
        return {
            "target": safe_target,
            "original_target": target_value,
            "target_type": target_type,
            "dry_run": dry_run,
            "scan_id": scan_id,
            "recon_status": "SUCCESS"
        }
    except ValueError as e:
        logger.log("RECON", f"Target validation failed: {str(e)}")
        return {
            "target": target_value,
            "target_type": target_type,
            "dry_run": dry_run,
            "scan_id": scan_id,
            "recon_status": "BLOCKED",
            "error": str(e)
        }


# =============================================================================
# ORCHESTRATOR (Manager Task)
# =============================================================================

@celery_app.task(name="scan.start_orchestrated_scan")
def start_orchestrated_scan(target_data: dict, scan_id: str, user_id: str):
    """
    True parallel scanning with Celery chord.
    
    Workflow:
    1. Recon (Sequential) - Validate target, DNS lookup
    2. Parallel Scans (Fan-out) - Nmap, ZAP, SSL run simultaneously on DIFFERENT workers
    3. Aggregation (Fan-in) - Merge findings, consensus check, AI verify
    
    Why this is efficient:
    If you have 50 workers, run_nmap_task and run_zap_task happen at the 
    exact same millisecond on different machines.
    
    Args:
        target_data: Target information from API
        scan_id: Unique scan identifier
        user_id: User ID for refund purposes
    """
    logger = DatabaseLogger(scan_id)
    logger.log("ORCHESTRATOR", "Starting orchestrated scan workflow...")
    logger.update_status("RUNNING")
    
    # Build the workflow: Recon -> Parallel Scans -> Aggregation
    workflow = chain(
        run_recon_task.s(target_data, scan_id),
        chord(
            [
                run_nmap_task.s(),
                run_zap_task.s(),
                run_ssl_check_task.s()
            ],
            analyze_and_verify.s(scan_id, user_id)
        )
    )
    
    # Fire and forget - the workflow runs asynchronously
    workflow.apply_async()
    
    logger.log("ORCHESTRATOR", "Workflow dispatched. Tools running in parallel...")


# =============================================================================
# AGGREGATOR (Fan-In - The Brain)
# =============================================================================

@celery_app.task(bind=True, name="scan.analyze_and_verify")
def analyze_and_verify(self, results: list, scan_id: str, user_id: str) -> dict:
    """
    Aggregate results from parallel scans and apply consensus checking.
    
    'results' is a list of outputs from [Nmap, ZAP, SSL] tasks.
    
    Args:
        results: List of dicts from parallel tool tasks
        scan_id: Unique scan identifier
        user_id: User ID for refund purposes
        
    Returns:
        Final scan result dict
    """
    logger = DatabaseLogger(scan_id)
    logger.update_phase("AGGREGATING")
    logger.update_progress(70)
    logger.log("AGGREGATOR", f"Received results from {len(results)} tools")
    
    # Collect all findings from all tools
    all_findings: List[Vulnerability] = []
    errors = []
    
    for tool_result in results:
        if isinstance(tool_result, dict):
            tool_name = tool_result.get("tool", "unknown")
            
            if tool_result.get("error"):
                errors.append(f"{tool_name}: {tool_result['error']}")
                logger.log("AGGREGATOR", f"Tool {tool_name} had error: {tool_result['error']}")
            else:
                findings_data = tool_result.get("findings", [])
                for f in findings_data:
                    vuln = Vulnerability(**f)
                    all_findings.append(vuln)
                logger.log("AGGREGATOR", f"Collected {len(findings_data)} findings from {tool_name}")
    
    logger.log("AGGREGATOR", f"Total raw findings: {len(all_findings)}")
    
    # Apply consensus checking
    logger.update_phase("CONSENSUS")
    verified_findings: List[Vulnerability] = []
    
    for vuln in all_findings:
        status = consensus_check(vuln, all_findings)
        vuln.status = status
        
        if status == "DISCARDED":
            logger.log("CONSENSUS", f"Discarded: {vuln.title} (low confidence)")
        elif status == "PENDING_VERIFICATION":
            # Queue for AI verification
            verify_vulnerability.delay(vuln.dict(), scan_id)
            verified_findings.append(vuln)
            logger.log("CONSENSUS", f"Queued for AI verification: {vuln.title}")
        else:
            verified_findings.append(vuln)
            logger.log("CONSENSUS", f"{status}: {vuln.title}")
    
    # Save results
    logger.update_phase("COMPLETED")
    logger.update_progress(100)
    logger.save_vulnerabilities([v.dict() for v in verified_findings])
    logger.update_status("COMPLETED")
    
    logger.log("AGGREGATOR", f"Scan completed. {len(verified_findings)} findings after consensus.")
    
    return {
        "status": "COMPLETED",
        "scan_id": scan_id,
        "total_findings": len(verified_findings),
        "errors": errors if errors else None
    }


# =============================================================================
# AI VERIFICATION TASK
# =============================================================================

@celery_app.task(bind=True, name="scan.verify_vulnerability")
def verify_vulnerability(self, vuln_data: dict, scan_id: str) -> dict:
    """
    AI-powered vulnerability verification for high-severity findings.
    
    This runs asynchronously after aggregation for CRITICAL/HIGH findings.
    
    Args:
        vuln_data: Vulnerability dict to verify
        scan_id: Scan identifier for logging
        
    Returns:
        Verification result
    """
    from .verifier_agent import VerifierAgent, SuspectedVuln
    
    logger = DatabaseLogger(scan_id)
    vuln = Vulnerability(**vuln_data)
    
    logger.log("VERIFIER", f"AI verifying: {vuln.title}")
    
    try:
        verifier = VerifierAgent()
        
        suspected = SuspectedVuln(
            target_url=vuln_data.get("target", "unknown"),
            vuln_type=vuln.title,
            parameter="id",
            evidence_hint=vuln.description
        )
        
        result = asyncio.run(verifier.verify_vulnerability(suspected))
        
        if result.is_confirmed:
            logger.log("VERIFIER", f"✓ CONFIRMED by AI: {vuln.title}")
            # Update the vulnerability in Redis
            # TODO: Implement atomic update to saved vulnerabilities
            return {"verified": True, "vuln": vuln.title}
        else:
            logger.log("VERIFIER", f"✗ Not confirmed by AI: {vuln.title}")
            return {"verified": False, "vuln": vuln.title}
            
    except Exception as e:
        logger.log("VERIFIER", f"AI verification failed: {str(e)}")
        return {"verified": False, "error": str(e), "vuln": vuln.title}


# =============================================================================
# LEGACY TASK (Kept for backwards compatibility)
# =============================================================================

@celery_app.task(
    bind=True,
    name="scan.run_agentic_scan",
    acks_late=True,          # Don't acknowledge until done (resilience)
    retry_backoff=True,      # Exponential backoff if Redis fails
    max_retries=3
)
def run_background_scan(self, target_data: dict, scan_id: str, user_id: str):
    """
    [LEGACY] Background Task: Instantiates the Agent and runs the full VAPT loop.
    
    NOTE: This is kept for backwards compatibility. New scans should use
    start_orchestrated_scan() for true parallel execution.
    
    Args:
        target_data: Dictionary containing target information
        scan_id: Unique identifier for the scan
        user_id: User ID for refund purposes (CRITICAL for bankruptcy prevention)
        
    Returns:
        Dictionary with scan results
    """
    logger = DatabaseLogger(scan_id)
    cost = 0 if target_data.get("dry_run") else 10
    
    try:
        logger.log("SYSTEM", f"Job picked up by worker {self.request.id}")
        logger.update_status("RUNNING")
        
        # Reconstruct the Target object
        target = ScanTarget(**target_data)
        
        # Initialize Agent with Context (including Redis client for cancellation)
        agent = SecurityAgent(target, scan_id, redis_client)
        
        # Run the Async Logic properly using asyncio.run()
        result = asyncio.run(agent.execute())
        
        # Save results to Redis
        logger.save_vulnerabilities(result.get("vulnerabilities", []))
        
        # Log completion
        logger.log("SYSTEM", "Scan completed successfully.")
        logger.update_status("COMPLETED")
        
        return {"status": "OK", "scan_id": scan_id}
        
    except SoftTimeLimitExceeded:
        # Graceful shutdown if scan takes too long
        logger.log("SYSTEM", "Time limit exceeded. Refunding user...")
        logger.update_phase("TIMEOUT")
        logger.update_status("TIMEOUT")
        
        # REFUND LOGIC (Timeout)
        if cost > 0:
            asyncio.run(_refund_user(user_id, cost, scan_id, "TIMEOUT - Scan exceeded 30-minute limit"))
        
        return {"status": "TIMEOUT", "scan_id": scan_id}
        
    except Exception as e:
        # Handle crashes with refund and retry mechanism
        logger.log("FATAL", f"Worker Error: {str(e)}")
        logger.update_phase("FAILED")
        logger.update_status("FAILED")
        
        # REFUND LOGIC (Error)
        if cost > 0:
            error_msg = str(e)[:100]  # Truncate long errors
            asyncio.run(_refund_user(user_id, cost, scan_id, f"ERROR: {error_msg}"))
        
        # Retry the task
        raise self.retry(exc=e)

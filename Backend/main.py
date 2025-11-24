# --- Imports ---
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from typing import Optional, List
from datetime import datetime
import uuid
import aiohttp
import logging
import sys
import json
import os
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from verifier_agent import VerifierAgent, SuspectedVuln
from mitre_engine import MitreEngine
from reporting import ReportGenerator
from tasks import run_background_scan
from agent import ScanTarget as ScanTargetPydantic
from db_logger import DatabaseLogger
from store import engine, Base, get_db
from models_orm import Target, Scan, Vulnerability
from verifier import verify_domain_ownership

# --- Logging Configuration ---
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)
logger = logging.getLogger("vaptiq.backend")

# --- Helper Functions ---
def safe_decode(value):
    """Safely decode Redis bytes to string."""
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "ignore")
    return value

# --- FastAPI App Initialization ---
app = FastAPI()

# --- Database Initialization ---
@app.on_event("startup")
async def startup():
    # Create tables if they don't exist
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

# --- CORS Configuration ---
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:3001")
allowed_origins_list = [origin.strip() for origin in ALLOWED_ORIGINS.split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

# --- Initialize Engines ---
mitre_engine = MitreEngine()
verifier_agent = VerifierAgent()

# --- Endpoints ---

@app.get("/scan/{scan_id}/export")
async def export_scan(scan_id: str, format: str = "pdf", severities: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    """Export scan report in PDF, HTML, or JSON format."""
    allowed_formats = {"pdf", "html", "json"}
    if format not in allowed_formats:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid format '{format}'. Allowed: {', '.join(allowed_formats)}"
        )
    
    # Fetch scan from DB
    result = await db.execute(
        select(Scan).options(selectinload(Scan.vulnerabilities), selectinload(Scan.target)).where(Scan.id == scan_id)
    )
    scan = result.scalars().first()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Construct scan_result dict for ReportGenerator
    findings = []
    for vuln in scan.vulnerabilities:
        findings.append({
            "type": vuln.title,
            "severity": vuln.severity,
            "description": vuln.description,
            "proof": vuln.proof
        })
    
    # Filter findings
    if severities:
        severity_list = [s.upper() for s in severities.split(",")]
        findings = [f for f in findings if f.get("severity", "LOW").upper() in severity_list]

    scan_result = {
        "id": scan.id,
        "target": scan.target.value if scan.target else "Unknown",
        "status": scan.status,
        "timestamp": scan.createdAt.isoformat() if scan.createdAt else datetime.now().isoformat(),
        "findings": findings
    }
    
    try:
        if format == "pdf":
            pdf_io = ReportGenerator.generate_pdf(scan_result)
            return StreamingResponse(
                pdf_io,
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=vaptiq_report_{scan_id}.pdf"}
            )
        elif format == "html":
            html_io = ReportGenerator.generate_html(scan_result)
            return StreamingResponse(
                html_io,
                media_type="text/html",
                headers={"Content-Disposition": f"attachment; filename=vaptiq_report_{scan_id}.html"}
            )
        else:  # json
            json_io = ReportGenerator.generate_json(scan_result)
            return StreamingResponse(
                json_io,
                media_type="application/json",
                headers={"Content-Disposition": f"attachment; filename=vaptiq_report_{scan_id}.json"}
            )
    except Exception as e:
        logger.exception(f"Report generation failed for scan {scan_id}")
        raise HTTPException(status_code=500, detail="Failed to generate report")


@app.post("/scan/{scan_id}/simulate-attack")
async def simulate_attack(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).options(selectinload(Scan.vulnerabilities)).where(Scan.id == scan_id))
    scan = result.scalars().first()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = [
        {
            "type": v.title,
            "severity": v.severity,
            "description": v.description,
            "proof": v.proof
        } for v in scan.vulnerabilities
    ]
        
    graph = mitre_engine.simulate_attack_path(findings)
    return graph


@app.post("/scan")
async def start_scan(target_input: ScanTargetPydantic, target_id: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    """
    Start a vulnerability scan on a target.
    """
    user_id = "mock-user-123"

    # 1. Rate Limiting (Feature C)
    # Count active scans (QUEUED or RUNNING) for this user
    # Assuming targets belong to user_id. We check active scans linked to targets owned by user_id.
    active_scans_result = await db.execute(
        select(func.count(Scan.id))
        .join(Target)
        .where(Target.userId == user_id)
        .where(Scan.status.in_(["QUEUED", "RUNNING"]))
    )
    active_count = active_scans_result.scalar()

    if active_count >= 2:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Maximum 2 active scans allowed per user."
        )

    # 2. Check Target & Verification
    if target_input.type == "URL":
        if not target_id:
            raise HTTPException(
                status_code=400,
                detail="URL targets must be created and verified before scanning. Please create a target first."
            )
        
        # Fetch target from DB
        target_result = await db.execute(select(Target).where(Target.id == target_id))
        db_target = target_result.scalars().first()

        if not db_target:
            raise HTTPException(status_code=404, detail="Target not found")

        if not db_target.isVerified:
            raise HTTPException(
                status_code=403,
                detail=f"Domain verification required. Please verify ownership of {db_target.value} before scanning."
            )
    else:
        # For non-URL targets, we might create a transient target or assume it exists.
        # For consistency, let's create one if target_id not provided, but simple path:
        if target_id:
             target_result = await db.execute(select(Target).where(Target.id == target_id))
             db_target = target_result.scalars().first()
        else:
             # Create a target record for this scan
             db_target = Target(
                 type=target_input.type,
                 value=target_input.value,
                 userId=user_id,
                 isVerified=True # IP/API might not need DNS verification
             )
             db.add(db_target)
             await db.flush() # Get ID
             target_id = db_target.id

    # 3. Create Scan Entry
    new_scan = Scan(
        targetId=db_target.id,
        status="QUEUED"
    )
    db.add(new_scan)
    await db.commit()
    await db.refresh(new_scan)
    
    # 4. Dispatch to Redis/Celery
    target_data = target_input.model_dump(mode='json') if hasattr(target_input, 'model_dump') else target_input.dict()
    task = run_background_scan.delay(target_data, new_scan.id)
    
    return {
        "scan_id": new_scan.id,
        "status": "QUEUED",
        "task_id": task.id,
        "message": "Scan queued in background."
    }

@app.get("/scans")
async def list_scans(db: AsyncSession = Depends(get_db)):
    """
    List all scans sorted by creation date (newest first).
    """
    # Fetch all scans with target info
    result = await db.execute(
        select(Scan).options(selectinload(Scan.target), selectinload(Scan.vulnerabilities)).order_by(Scan.createdAt.desc())
    )
    scans = result.scalars().all()
    
    scan_list = []
    for scan in scans:
        # Get real-time status from Redis if running
        redis_status = None
        if scan.status in ["QUEUED", "RUNNING"]:
            db_logger = DatabaseLogger(scan.id)
            redis_status_raw = db_logger.redis_client.get(f"scan:{scan.id}:status")
            redis_status = safe_decode(redis_status_raw)

        status = redis_status or scan.status
        
        # Calculate severity summary
        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        # If running, findings might be in Redis. If completed, in DB.
        # For simplicity, use DB findings.
        for v in scan.vulnerabilities:
            sev = v.severity.upper()
            if sev in summary:
                summary[sev] += 1

        # Also check Redis for real-time findings if running?
        # Maybe skip for now to keep it simple, or merge.

        target_val = scan.target.value if scan.target else "Unknown"
        # Convert scan.target (SQLAlchemy) to dict or use value
        target_dict = {"value": target_val, "type": scan.target.type if scan.target else "Unknown"}

        scan_list.append({
            "scan_id": scan.id,
            "status": status,
            "target": target_dict,
            "created_at": scan.createdAt,
            "summary": summary
        })

    return scan_list

@app.get("/scan/{scan_id}")
async def get_scan_status(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get real-time status, logs, and vulnerabilities for a scan."""
    result = await db.execute(
        select(Scan).options(selectinload(Scan.target), selectinload(Scan.vulnerabilities)).where(Scan.id == scan_id)
    )
    scan = result.scalars().first()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    # Get real-time status/logs from Redis
    db_logger = DatabaseLogger(scan_id)
    
    logs_raw = db_logger.redis_client.lrange(f"scan:{scan_id}:logs", 0, -1)
    logs = [safe_decode(log) for log in logs_raw] if logs_raw else []
    
    status_raw = db_logger.redis_client.get(f"scan:{scan_id}:status")
    status = safe_decode(status_raw) or scan.status
    
    # Vulnerabilities
    vulnerabilities = []
    # If completed, prefer DB. If running, prefer Redis or DB?
    # Let's use DB findings which should be populated on completion.
    for v in scan.vulnerabilities:
         vulnerabilities.append({
             "type": v.title,
             "severity": v.severity,
             "description": v.description,
             "proof": v.proof,
             "status": v.status
         })

    return {
        "scan_id": scan.id,
        "status": status,
        "target": {"value": scan.target.value, "type": scan.target.type} if scan.target else None,
        "logs": logs,
        "vulnerabilities": vulnerabilities
    }

@app.post("/targets/{target_id}/verify")
async def verify_target(target_id: str):
    """
    Verify domain ownership via DNS TXT record.
    """
    # Call the verifier module (which now uses DB)
    result = await verify_domain_ownership(target_id)
    return result.dict()

@app.post("/targets/create")
async def create_target(target_input: ScanTargetPydantic, user_id: str = "mock-user-123", db: AsyncSession = Depends(get_db)):
    """
    Create a new target.
    """
    new_target = Target(
        type=target_input.type,
        value=target_input.value,
        userId=user_id
    )
    db.add(new_target)
    await db.commit()
    await db.refresh(new_target)
    
    return {
        "target_id": new_target.id,
        "verification_token": new_target.verificationToken,
        "is_verified": new_target.isVerified,
        "message": "Target created. Please verify domain ownership before scanning."
    }

@app.get("/targets/{target_id}")
async def get_target(target_id: str, db: AsyncSession = Depends(get_db)):
    """
    Get target details.
    """
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalars().first()

    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    return {
        "id": target.id,
        "type": target.type,
        "value": target.value,
        "user_id": target.userId,
        "verification_token": target.verificationToken,
        "is_verified": target.isVerified,
        "verified_at": target.verifiedAt,
        "created_at": target.createdAt
    }

@app.post("/verify-vulnerability")
async def verify_vulnerability_endpoint(suspected_vuln: SuspectedVuln):
    """
    Manually verify a suspected vulnerability.
    """
    result = await verifier_agent.verify_vulnerability(suspected_vuln)
    return result

@app.get("/")
async def root():
    return {"message": "Vaptiq.ai Engine Running"}

# In-memory cache for CVEs (Keep as is)
cve_cache = {
    "data": [],
    "last_updated": None
}

@app.get("/cves")
async def get_latest_cves():
    """
    Fetch latest CVEs from CIRCL.lu or fallback to LLM generation.
    """
    global cve_cache
    
    # Check cache (15 min TTL)
    if cve_cache["data"] and cve_cache["last_updated"]:
        cache_age = (datetime.now() - cve_cache["last_updated"]).total_seconds()
        if cache_age < 900:  # 15 minutes
            return cve_cache["data"]

    try:
        # 1. Try fetching from CIRCL.lu
        timeout = aiohttp.ClientTimeout(total=6, connect=3, sock_read=5)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get("https://cve.circl.lu/api/last") as response:
                if response.status == 200:
                    try:
                        data = await response.json()
                        formatted_cves = []
                        for item in data[:10]:
                            formatted_cves.append({
                                "id": item.get("id"),
                                "title": item.get("summary", "No description available")[:100] + "...",
                                "severity": "HIGH",
                                "date": item.get("Published", datetime.now().isoformat()),
                                "link": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={item.get('id')}"
                            })
                        
                        cve_cache["data"] = formatted_cves
                        cve_cache["last_updated"] = datetime.now()
                        return formatted_cves
                    except (aiohttp.ContentTypeError, json.JSONDecodeError) as e:
                        logger.warning(f"CVE API returned non-JSON response: {e}")
    except aiohttp.ClientError as e:
        logger.warning(f"CVE API request failed: {e}")
    except Exception as e:
        logger.exception(f"Unexpected error fetching CVEs: {e}")
        
    # 2. Fallback to Mock data
    logger.info("Falling back to mock CVE data...")
    return [
        {
            "id": "CVE-2025-1001 (AI-Est)",
            "title": "Simulated: Critical RCE in Cloud Infrastructure",
            "severity": "CRITICAL",
            "date": datetime.now().strftime("%Y-%m-%d"),
            "link": "#"
        },
        {
            "id": "CVE-2025-1002 (AI-Est)",
            "title": "Simulated: SQL Injection in Banking API",
            "severity": "HIGH",
            "date": datetime.now().strftime("%Y-%m-%d"),
            "link": "#"
        }
    ]

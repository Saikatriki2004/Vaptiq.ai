import dns.resolver
import logging
from pydantic import BaseModel
from datetime import datetime
from typing import Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from store import AsyncSessionLocal
from models_orm import Target

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VerificationRequest(BaseModel):
    target_id: str

class VerificationResult(BaseModel):
    success: bool
    message: str
    is_verified: bool
    verified_at: Optional[datetime] = None

async def verify_domain_ownership(target_id: str) -> VerificationResult:
    """
    Verifies domain ownership by checking for a DNS TXT record.
    
    Args:
        target_id: The unique identifier of the target to verify
        
    Returns:
        VerificationResult with success status and descriptive message
    """
    async with AsyncSessionLocal() as db:
        # 1. Fetch target from database
        result = await db.execute(select(Target).where(Target.id == target_id))
        target = result.scalars().first()

        if not target:
            logger.warning(f"Target not found: {target_id}")
            return VerificationResult(
                success=False,
                message="Target not found in database",
                is_verified=False
            )
        
        # 2. Extract domain from target value
        domain = extract_domain(target.value)
        required_token = target.verificationToken
        
        # Log truncated token for security (avoid full token exposure in logs)
        token_preview = f"{required_token[:8]}..." if len(required_token) > 8 else "***"
        logger.info(f"Verifying domain: {domain} with token: {token_preview}")
        
        try:
            # 3. Query DNS for TXT records
            logger.info(f"Querying DNS TXT records for {domain}...")
            # Run blocking DNS call in executor if needed, but for now blocking is okay in this scope or use aioDNS
            # dnspython is blocking. Ideally should be run_in_executor.
            # Assuming simple blocking is acceptable for this task or verifier agent runs in worker.
            # But this is called from main.py (async). So better use executor.
            import asyncio
            loop = asyncio.get_running_loop()
            answers = await loop.run_in_executor(None, query_dns_txt, domain)
            
            # 4. Check if our token exists in any TXT record
            found = False
            found_records = []

            for txt_record in answers:
                found_records.append(txt_record)

                if required_token in txt_record:
                    found = True
                    logger.info(f"✓ Verification token found in TXT record")
                    break

            if found:
                # 5. Update database - mark as verified
                verification_time = datetime.utcnow()
                target.isVerified = True
                target.verifiedAt = verification_time
                await db.commit()
                await db.refresh(target)

                logger.info(f"✓ Domain {domain} successfully verified!")
                return VerificationResult(
                    success=True,
                    message=f"Domain verified successfully! Scanning unlocked for {domain}.",
                    is_verified=True,
                    verified_at=verification_time
                )
            else:
                # Log count instead of full records to reduce log verbosity
                records_count = len(found_records)
                logger.warning(f"✗ Token not found. Found {records_count} TXT records")
                return VerificationResult(
                    success=False,
                    message=f"Verification token not found. Found {records_count} TXT records. Please wait 1-5 minutes for DNS propagation and try again.",
                    is_verified=False
                )

        except Exception as e:
            logger.error(f"DNS verification error: {str(e)}")
            return VerificationResult(
                success=False,
                message=f"DNS lookup failed: {str(e)}",
                is_verified=False
            )

def query_dns_txt(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        results = []
        for rdata in answers:
            results.append(rdata.to_text().strip('"'))
        return results
    except Exception as e:
        raise e

def extract_domain(url: str) -> str:
    """
    Extracts the domain from a URL or returns the input if already a domain.
    """
    # Remove protocol
    domain = url.replace("https://", "").replace("http://", "")
    
    # Remove path and query parameters
    domain = domain.split("/")[0].split("?")[0]
    
    # Remove port if present
    domain = domain.split(":")[0]
    
    return domain

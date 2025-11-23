import dns.resolver
import logging
from pydantic import BaseModel
from datetime import datetime
from typing import Optional
from store import mock_targets_db

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
    # 1. Fetch target from database
    target = mock_targets_db.get(target_id)
    if not target:
        logger.warning(f"Target not found: {target_id}")
        return VerificationResult(
            success=False,
            message="Target not found in database",
            is_verified=False
        )
    
    # 2. Extract domain from target value
    domain = extract_domain(target["value"])
    required_token = target["verification_token"]
    
    # Log truncated token for security (avoid full token exposure in logs)
    token_preview = f"{required_token[:8]}..." if len(required_token) > 8 else "***"
    logger.info(f"Verifying domain: {domain} with token: {token_preview}")
    
    try:
        # 3. Query DNS for TXT records
        logger.info(f"Querying DNS TXT records for {domain}...")
        answers = dns.resolver.resolve(domain, 'TXT')
        
        # 4. Check if our token exists in any TXT record
        found = False
        found_records = []
        
        for rdata in answers:
            # DNS TXT records are returned as quoted strings, decode them
            txt_record = rdata.to_text().strip('"')
            found_records.append(txt_record)
            
            if required_token in txt_record:
                found = True
                logger.info(f"✓ Verification token found in TXT record")
                break
        
        if found:
            # 5. Update database - mark as verified
            verification_time = datetime.now()
            target["is_verified"] = True
            target["verified_at"] = verification_time
            
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
    
    except dns.resolver.NXDOMAIN:
        logger.error(f"Domain does not exist: {domain}")
        return VerificationResult(
            success=False,
            message=f"Domain '{domain}' does not exist or cannot be resolved.",
            is_verified=False
        )
    
    except dns.resolver.NoAnswer:
        logger.warning(f"No TXT records found for {domain}")
        return VerificationResult(
            success=False,
            message=f"No TXT records found for '{domain}'. Please add the verification token as a TXT record.",
            is_verified=False
        )
    
    except dns.resolver.Timeout:
        logger.error(f"DNS query timeout for {domain}")
        return VerificationResult(
            success=False,
            message="DNS query timed out. Please try again in a moment.",
            is_verified=False
        )
    
    except Exception as e:
        logger.error(f"DNS verification error: {str(e)}")
        return VerificationResult(
            success=False,
            message=f"DNS lookup failed: {str(e)}",
            is_verified=False
        )

def extract_domain(url: str) -> str:
    """
    Extracts the domain from a URL or returns the input if already a domain.
    
    Examples:
        https://example.com/path -> example.com
        http://api.example.com -> api.example.com
        example.com -> example.com
    """
    # Remove protocol
    domain = url.replace("https://", "").replace("http://", "")
    
    # Remove path and query parameters
    domain = domain.split("/")[0].split("?")[0]
    
    # Remove port if present
    domain = domain.split(":")[0]
    
    return domain

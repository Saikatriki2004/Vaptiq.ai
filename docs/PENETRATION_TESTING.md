# Penetration Testing Guide for Vaptiq.ai

## Overview

This guide provides a comprehensive framework for conducting penetration testing on the Vaptiq.ai platform to validate security controls and identify vulnerabilities before production deployment.

## Pre-Testing Checklist

- [ ] Obtain written authorization from stakeholders
- [ ] Define testing scope and boundaries
- [ ] Set up isolated testing environment
- [ ] Configure monitoring and logging
- [ ] Notify relevant teams (DevOps, Security)
- [ ] Create rollback plan

## Testing Scope

### In-Scope
- Backend API (`/api/*`)
- Frontend application (`/dashboard/*`)
- Authentication system
- Scanning functionality
- Report generation
- API rate limiting

### Out-of-Scope
- Third-party services (Supabase, E2B)
- Infrastructure (AWS, hosting provider)
- DoS/DDoS attacks
- Social engineering
- Physical security

## Testing Methodology

### Phase 1: Reconnaissance (1-2 days)

**Information Gathering:**
```bash
# DNS enumeration
dig vaptiq.ai ANY
nslookup vaptiq.ai

# Subdomain enumeration
sublist3r -d vaptiq.ai

# Technology fingerprinting
whatweb https://vaptiq.ai
wappalyzer

# Port scanning (authorized only)
nmap -sV -p- vaptiq.ai
```

**Expected Findings:**
- Open ports: 443 (HTTPS), 80 (HTTP redirect)
- Technologies: Next.js, FastAPI, PostgreSQL, Redis
- Security headers present

### Phase 2: Authentication Testing (2-3 days)

**Test Cases:**

1. **JWT Token Security**
```bash
# Test 1: Missing token
curl -X GET https://api.vaptiq.ai/scans
# Expected: 401 Unauthorized

# Test 2: Invalid token
curl -X GET https://api.vaptiq.ai/scans \
  -H "Authorization: Bearer invalid-token"
# Expected: 401 Unauthorized

# Test 3: Expired token
# Generate expired JWT and test
# Expected: 401 Token expired

# Test 4: Token tampering
# Modify JWT payload and test
# Expected: 401 Invalid signature
```

2. **Session Management**
- Test session timeout
- Test concurrent sessions
- Test session fixation
- Test logout functionality

**OWASP Reference:** A07:2021 - Identification and Authentication Failures

### Phase 3: Authorization Testing (2-3 days)

**IDOR (Insecure Direct Object Reference) Testing:**

```bash
# Test 1: Access other user's scan
# Login as User A
USER_A_TOKEN="<token>"
USER_A_SCAN_ID="<scan-id>"

# Login as User B  
USER_B_TOKEN="<token>"

# Try to access User A's scan as User B
curl -X GET "https://api.vaptiq.ai/scan/$USER_A_SCAN_ID" \
  -H "Authorization: Bearer $USER_B_TOKEN"
# Expected: 403 Forbidden

# Test 2: Modify other user's target
curl -X  DELETE "https://api.vaptiq.ai/targets/$USER_A_TARGET_ID" \
  -H "Authorization: Bearer $USER_B_TOKEN"
# Expected: 403 Forbidden
```

**Privilege Escalation Testing:**
```bash
# Test role elevation
# Regular user trying admin endpoints
curl -X GET "https://api.vaptiq.ai/admin/users" \
  -H "Authorization: Bearer $USER_TOKEN"
# Expected: 403 Insufficient permissions
```

**OWASP Reference:** A01:2021 - Broken Access Control

### Phase 4: Input Validation & Injection (3-4 days)

**SQL Injection Testing:**
```bash
# Backend uses Prisma ORM (should be protected)
# Test edge cases
curl -X POST "https://api.vaptiq.ai/scan" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"type":"URL","value":"'; DROP TABLE scans; --"}'
# Expected: 400 Bad Request (input validation)
```

**Command Injection Testing:**
```bash
# Test 1: Shell metacharacters
curl -X POST "https://api.vaptiq.ai/scan" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"type":"URL","value":"example.com; rm -rf /"}'
# Expected: 400 Invalid character

# Test 2: Command substitution
curl -X POST "https://api.vaptiq.ai/scan" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"type":"URL","value":"$(whoami)"}'
# Expected: 400 Invalid character
```

**SSRF Testing:**
```bash
# Test 1: Private IP ranges
curl -X POST "https://api.vaptiq.ai/scan" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"type":"IP","value":"192.168.1.1"}'
# Expected: 400 SSRF protection

# Test 2: Cloud metadata
curl -X POST "https://api.vaptiq.ai/scan" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"type":"IP","value":"169.254.169.254"}'
# Expected: 400 SSRF protection

# Test 3: Localhost variations
for host in localhost 127.0.0.1 0.0.0.0 [::1]; do
  curl -X POST "https://api.vaptiq.ai/scan" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{\"type\":\"URL\",\"value\":\"$host\"}"
done
# Expected: All blocked
```

**XSS Testing:**
```bash
# Test HTML report generation
curl -X POST "https://api.vaptiq.ai/verify-vulnerability" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"vuln_type":"<script>alert(1)</script>","evidence":"test"}'

# Download HTML report and check for XSS
curl "https://api.vaptiq.ai/scan/$SCAN_ID/export?format=html"
# Expected: Script tags escaped
```

**OWASP Reference:** A03:2021 - Injection

### Phase 5: Business Logic Testing (2-3 days)

**Rate Limiting:**
```bash
# Automated rate limit testing
for i in {1..100}; do
  curl -X POST "https://api.vaptiq.ai/scan" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"type":"URL","value":"example.com"}' &
done
wait
# Expected: 429 Too Many Requests after 10 requests
```

**Credit System:**
```bash
# Test negative credits
# Test credit overflow
# Test concurrent scan deduction
# Test refund mechanism
```

**Domain Verification Bypass:**
```bash
# Test scanning without verification
# Test DNS TXT record spoofing
# Test subdomain takeover scenarios
```

### Phase 6: API Security Testing (2-3 days)

**Mass Assignment:**
```bash
# Try to set admin role
curl -X POST "https://api.vaptiq.ai/targets/create" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"type":"URL","value":"example.com","role":"ADMIN"}'
# Expected: Role field ignored or rejected
```

**Endpoint Enumeration:**
```bash
# Fuzz for hidden endpoints
ffuf -w wordlist.txt \
  -u "https://api.vaptiq.ai/FUZZ" \
  -H "Authorization: Bearer $TOKEN"
```

**CORS Misconfiguration:**
```bash
# Test CORS with different origins
curl -H "Origin: https://evil.com" \
  -H "Authorization: Bearer $TOKEN" \
  https://api.vaptiq.ai/scans
# Check Access-Control-Allow-Origin header
```

### Phase 7: Cryptography Testing (1-2 days)

**TLS/SSL Testing:**
```bash
# Test SSL configuration
sslscan vaptiq.ai
testssl.sh vaptiq.ai

# Check cipher suites
nmap --script ssl-enum-ciphers -p 443 vaptiq.ai
```

**Expected Configuration:**
- TLS 1.2+  only
- Strong cipher suites
- HSTS enabled
- Valid certificate

### Phase 8: Security Headers Testing (1 day)

```bash
# Automated header testing
curl -I https://vaptiq.ai

# Expected headers:
# - X-Content-Type-Options: nosniff
# - X-Frame-Options: DENY
# - X-XSS-Protection: 1; mode=block
# - Strict-Transport-Security: max-age=31536000
# - Content-Security-Policy: default-src 'self'
```

## Automated Testing Tools

### Recommended Tools

1. **OWASP ZAP**
```bash
# Automated scan
zap-cli quick-scan -s all https://vaptiq.ai

# Active scan (be careful with rate limits)
zap-cli active-scan https://vaptiq.ai
```

2. **Burp Suite Professional**
- Configure as proxy
- Run automated scanner
- Review findings manually

3. **Nuclei**
```bash
# Run community templates
nuclei -u https://vaptiq.ai -t ~/nuclei-templates/
```

## Reporting

### Report Structure

1. **Executive Summary**
   - Testing scope and dates
   - High-level findings
   - Risk rating
   - Recommendations

2. **Detailed Findings**
   For each vulnerability:
   - Title
   - Severity (Critical/High/Medium/Low)
   - CVSS Score
   - Affected endpoints
   - Steps to reproduce
   - Proof of concept
   - Remediation
   - OWASP mapping

3. **Test Coverage Matrix**
   - Tests performed
   - Pass/Fail status
   - Evidence

4. **Appendices**
   - Testing methodology
   - Tools used
   - Raw scan outputs

### Severity Ratings

- **Critical**: Can directly lead to system compromise
- **High**: Can lead to data breach or unauthorized access
- **Medium**: Security weaknesses requiring attention
- **Low**: Best practice violations

## Remediation Validation

After fixes are deployed:

1. Retest all identified vulnerabilities
2. Verify fixes don't introduce new issues
3. Update findings status
4. Issue clearance letter if all critical/high resolved

## Compliance Validation

Verify compliance with:
- OWASP Top 10 (2021)
- PCI DSS (if applicable)
- GDPR (for EU users)
- SOC 2 Type II

## Continuous Testing

**Recommendations:**
- Monthly automated scans
- Quarterly manual penetration tests
- Annual comprehensive security audit
- Bug bounty program consideration

## Emergency Contacts

- Security Team: security@vaptiq.ai
- Incident Response: incident@vaptiq.ai
- On-Call Engineer: [Phone number]

## Legal & Compliance

⚠️ **IMPORTANT**: Only perform testing with explicit written authorization. Unauthorized testing may violate:
- Computer Fraud and Abuse Act (CFAA)
- Computer Misuse Act
- Local cybersecurity laws

Always operate within the defined scope and rules of engagement.

---

**Document Version:** 1.0  
**Last Updated:** 2025-11-29  
**Next Review:** 2026-02-29

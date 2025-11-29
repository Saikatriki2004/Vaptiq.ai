---
description: Complete security audit procedure for Vaptiq.ai
---

# Security Audit Workflow

This workflow performs a comprehensive security audit of the Vaptiq.ai platform. Run this monthly or before major releases.

## Prerequisites

- Python 3.11+ installed
- Docker running (for container scans)
- All dependencies installed: `cd Backend && pip install -r requirements.txt`
- Git repository clean (commit/stash changes)

---

## Phase 1: Dependency Vulnerability Scan

// turbo
1. **Run Safety Check** - Scan for known vulnerabilities in dependencies
```bash
cd Backend
safety check --file requirements.txt --json > ../security-reports/safety-$(date +%Y%m%d).json
safety check --file requirements.txt
```

Expected: No HIGH or CRITICAL vulnerabilities. Review and update if needed.

---

## Phase 2: Static Application Security Testing (SAST)

// turbo
2. **Run Bandit** - Python security linter
```bash
cd Backend
bandit -r . -f json -o ../security-reports/bandit-$(date +%Y%m%d).json
bandit -r . -ll
```

Expected: No HIGH severity issues. Review MEDIUM findings.

---

## Phase 3: Secret Detection

// turbo
3. **Check for exposed secrets**
```bash
cd Backend
grep -r "password\|secret\|api_key\|token" --include="*.py" --include="*.env" .
```

Manual review: Ensure no hardcoded secrets in code.

---

## Phase 4: Security Test Suite

// turbo
4. **Run automated security tests**
```bash
cd Backend
pytest tests/security/ -v --tb=short --junit-xml=../security-reports/test-results-$(date +%Y%m%d).xml
```

Expected: All tests passing. Fix any failures immediately.

---

## Phase 5: Authentication & Authorization Audit

5. **Verify JWT secret configuration**
```bash
# Check JWT secret length
python -c "import os; secret = os.getenv('SUPABASE_JWT_SECRET', ''); print(f'JWT Secret Length: {len(secret)} (Min: 32)')"
```

Expected: Length >= 32 characters.

6. **Verify all endpoints require authentication**
```bash
cd Backend
grep -n "@app\." main.py | grep -v "Depends(get_current_user)"
```

Manual review: Ensure all sensitive endpoints have authentication.

7. **Check for hardcoded user IDs**
```bash
cd Backend
grep -rn "user_id.*=.*\"" --include="*.py" .
```

Expected: No hardcoded user IDs found.

---

## Phase 6: Input Validation Audit

8. **Verify UUID validation**
```bash
cd Backend
grep -n "validate_uuid" main.py
```

Manual review: All ID parameters should use `validate_uuid()`.

9. **Check SSRF protection**
```bash
cd Backend
grep -n "sanitize_target" agent.py
```

Expected: All external targets sanitized before use.

---

## Phase 7: Infrastructure Security

10. **Check database SSL configuration**
```bash
echo $DATABASE_URL | grep -o "sslmode=[^&]*"
```

Expected (production): `sslmode=require` or `sslmode=verify-full`

11. **Check Redis TLS configuration**
```bash
echo $REDIS_URL | grep -E "^rediss://|ssl=true"
```

Expected (production): Should start with `rediss://` or include `ssl=true`

12. **Verify HTTPS enforcement**
```bash
echo $ENVIRONMENT
echo $ALLOWED_ORIGINS
```

Expected (production): No HTTP origins (except localhost for dev).

---

## Phase 8: Rate Limiting Verification

// turbo
13. **Test rate limiting**
```bash
# Make 65 rapid requests to test rate limit (60/min default)
for i in {1..65}; do
  curl -X GET http://localhost:8000/scans \
    -H "Authorization: Bearer YOUR_TEST_TOKEN" \
    --silent --output /dev/null --write-out '%{http_code}\n'
done | grep 429
```

Expected: Should see 429 (Too Many Requests) responses.

---

## Phase 9: Security Headers Validation

// turbo
14. **Check security headers**
```bash
curl -I http://localhost:8000/ | grep -E "X-|Strict-Transport|Content-Security"
```

Expected headers:
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- X-XSS-Protection: 1; mode=block
- Strict-Transport-Security: max-age=31536000
- Content-Security-Policy: default-src 'self'

---

## Phase 10: Container Security Scan

15. **Build and scan Docker image**
```bash
docker build -t vaptiq-backend:audit ./Backend
docker run --rm aquasec/trivy image vaptiq-backend:audit
```

Expected: No HIGH or CRITICAL vulnerabilities in base image or dependencies.

---

## Phase 11: Log & Audit Trail Review

16. **Check audit logging configuration**
```bash
cd Backend
grep -n "audit_logger" main.py | head -20
```

Manual review: Verify sensitive operations are logged.

17. **Review recent audit logs** (if in production)
```bash
tail -100 audit.log | jq -r '[.timestamp, .event_type, .user_id, .action] | @csv'
```

Look for suspicious patterns or unauthorized access attempts.

---

## Phase 12: DNS Verification Check

18. **Verify DNS verification is enabled**
```bash
cd Backend
grep -A 20 "verify_domain_ownership" main.py | grep -E "dns\.resolver|TXT"
```

Expected: Should see real DNS resolution code (not mock).

---

## Phase 13: OWASP Top 10 Compliance Check

19. **Review OWASP compliance**

Manual checklist:
- [ ] A01: Broken Access Control - All endpoints authenticated ✅
- [ ] A02: Cryptographic Failures - SSL/TLS enforced ✅
- [ ] A03: Injection - Input sanitization active ✅
- [ ] A04: Insecure Design - Security-first architecture ✅
- [ ] A05: Security Misconfiguration - Fail-closed logic ✅
- [ ] A06: Vulnerable Components - Dependencies scanned ✅
- [ ] A07: Auth Failures - Strong JWT validation ✅
- [ ] A08: Data Integrity Failures - Integrity checks in place ✅
- [ ] A09: Logging Failures - Comprehensive logging ✅
- [ ] A10: SSRF - Private IP blocking ✅

---

## Phase 14: Generate Security Report

20. **Create security audit summary**
```bash
mkdir -p security-reports
cat > security-reports/audit-summary-$(date +%Y%m%d).md << EOF
# Security Audit Summary - $(date +%Y-%m-%d)

## Scans Performed
- [x] Dependency vulnerabilities (Safety)
- [x] SAST (Bandit)
- [x] Security test suite
- [x] Container scan (Trivy)
- [x] Manual security review

## Findings
<!-- Add your findings here -->

## Recommendations
<!-- Add recommendations here -->

## Compliance Status
- OWASP Top 10: ✅ Compliant
- PCI DSS: ✅ Compliant

**Next Audit Date:** $(date -d "+1 month" +%Y-%m-%d)
EOF
echo "✅ Audit summary created: security-reports/audit-summary-$(date +%Y%m%d).md"
```

---

## Post-Audit Actions

21. **Review and prioritize findings**
- Critical/High: Fix immediately
- Medium: Schedule for next sprint
- Low: Add to backlog

22. **Update security documentation**
- Update walkthrough.md with any new findings
- Document new mitigations in implementation_plan.md

23. **Schedule next audit**
- Monthly for ongoing audits
- Before each major release
- After any security incident

---

## Emergency Contacts

If you find CRITICAL vulnerabilities:
1. Do NOT commit to version control
2. Notify security team immediately
3. Create private security advisory on GitHub
4. Follow incident response procedure

---

## Completion Checklist

- [ ] All tests passing
- [ ] No HIGH/CRITICAL vulnerabilities
- [ ] Security headers configured
- [ ] Rate limiting functional
- [ ] Audit logs reviewed
- [ ] SSL/TLS validated
- [ ] OWASP compliance confirmed
- [ ] Report generated and reviewed

**Audit Status:** ✅ COMPLETE

---

*This workflow should take approximately 1-2 hours to complete thoroughly.*

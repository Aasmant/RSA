# RSA Encryption Service - Secure SDLC Assignment

A comprehensive educational project demonstrating Secure Software Development Lifecycle (SSDLC) principles applied to a cryptographic REST service.

## Project Overview

This project provides a complete case study in security engineering for a RESTful web service that enables authenticated users to encrypt and decrypt files using RSA encryption. The deliverable includes:

- **Working Python implementation** (Flask REST API with 12 intentional vulnerabilities for learning)
- **Comprehensive security analysis** (20+ page report addressing all 8 assignment questions)
- **Detailed threat modeling** (24 STRIDE threats + 5 attack scenarios)
- **SSDLC lifecycle documentation** (requirements through maintenance)
- **Security testing strategy** (unit tests, SAST tools, compliance mapping)

## Quick Start

### Installation

```bash
# Install Python dependencies
pip install -r requirements.txt

# Initialize database
python rsa_service.py

# Service runs on http://127.0.0.1:5000
```

### Example Usage

```bash
# Register new user
curl -X POST http://127.0.0.1:5000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"SecurePassword123"}'

# Login and get token
curl -X POST http://127.0.0.1:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"SecurePassword123"}'

# Upload file (requires JWT token)
curl -X POST http://127.0.0.1:5000/api/upload \
  -H "Authorization: Bearer <token>" \
  -F "file=@document.txt"

# Decrypt file
curl -X POST http://127.0.0.1:5000/api/decrypt/1 \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"private_key":"-----BEGIN RSA PRIVATE KEY-----..."}'
```

## Project Structure

```
rsa-encryption-service/
├── rsa_service.py              # Working REST API (350+ lines)
├── requirements.txt             # Python dependencies
├── SECURITY_REPORT.md          # Main assignment (20+ pages)
├── THREAT_MODEL.md             # Threat analysis (24 threats, 5 scenarios)
├── README.md                   # This file
├── SETUP_GUIDE.md              # Installation and testing guide
├── SUBMISSION_GUIDE.md         # PDF conversion and submission help
└── rsa_service.db              # SQLite database (auto-created)
```

## Key Features Demonstrated

### Security Requirements Engineering (Question 1)
- 16 security requirements documented (FR, NFR, SR)
- Requirement prioritization and conflict resolution
- Standards mapping (OWASP ASVS Level 3, NIST CSF, ISO/IEC 27001)

### Threat Modeling (Question 2)
- STRIDE methodology: 24 threats identified
- Risk assessment matrix
- 5 detailed attack scenarios (DBA insider, supply chain, padding oracle, VM escape, brute force)
- Mitigation strategies with residual risk analysis

### Secure Architecture (Question 3)
- Multi-tier architecture with defense-in-depth
- Trust boundary identification
- Security principles (least privilege, fail-secure, separation of concerns)
- 8 attack surfaces documented

### Authentication & Authorization (Question 4)
- Multi-factor authentication (credential, token, MFA)
- Role-based access control (RBAC)
- Privilege escalation analysis with code examples
- Authorization testing strategy

### Secure Implementation (Question 5)
- 12 intentional vulnerabilities with explanations
- Secure implementations for each vulnerability
- Cryptographic flaws (PKCS#1 v1.5, direct RSA, no integrity)
- Dependency management strategy

### Security Testing (Question 6)
- Unit test examples
- SAST tool configuration (Bandit, Semgrep)
- OWASP Top 10 vulnerability mapping
- Compliance requirements

### Deployment & Incident Response (Question 7)
- AWS VPC architecture
- Secret management (AWS Secrets Manager)
- Cryptographic key compromise response (3 phases)
- Disaster recovery procedures

### Maintenance & Cryptographic Agility (Question 8)
- Post-quantum migration roadmap (4 phases: 2027-2030)
- Hybrid encryption approach
- Configuration-driven cryptography
- Long-term security risks

## Intentional Vulnerabilities (For Learning)

The code includes 12 documented security issues to demonstrate real-world flaws:

1. **Hard-coded SECRET_KEY** - Never hardcode secrets; use environment variables
2. **Weak password requirements** - Enforce minimum 12 characters with complexity
3. **PKCS#1 v1.5 padding** - Use OAEP to prevent padding oracle attacks
4. **Direct RSA encryption** - Use hybrid encryption (RSA + AES) for files
5. **No file size validation** - Enforce limits to prevent DoS
6. **Missing authorization checks** - Always verify ownership before access
7. **Private key exposure** - Never return keys to clients
8. **Missing integrity protection** - Use Encrypt-then-MAC or AEAD
9. **Incomplete audit logging** - Log all security events
10. **Debug mode enabled** - Disable in production
11. **Weak input validation** - Validate all user input
12. **No rate limiting** - Implement request throttling

Each vulnerability includes detailed explanation, attack scenario, and secure implementation.

## Standards Compliance

### OWASP ASVS Level 3
Covers 9 control areas:
- Architecture & Design
- Authentication
- Session Management  
- Validation & Sanitization
- Cryptography
- Error Handling & Logging
- Data Protection
- Communications

### NIST Cybersecurity Framework
Implements all 5 functions:
- Identify (threat modeling)
- Protect (encryption, access control)
- Detect (audit logging, monitoring)
- Respond (incident response)
- Recover (backup, disaster recovery)

### ISO/IEC 27001
Maps to 14 control areas including:
- Organization
- People
- Technology
- Operations
- Compliance

## Testing

### Unit Tests
```bash
# Run security-specific tests
python -m pytest tests/ -v

# Tests included:
# - RSA encryption/decryption functionality
# - Password hashing and verification
# - JWT token generation and expiration
# - Authorization checks (horizontal privilege escalation prevention)
# - SQL injection prevention
```

### Static Analysis
```bash
# Bandit (security issues)
bandit -r rsa_service.py

# Semgrep (pattern-based)
semgrep --config=p/security-audit rsa_service.py
```

### Manual Testing
See SETUP_GUIDE.md for comprehensive testing procedures.

## Security Considerations

**Development**: This implementation deliberately includes vulnerabilities for educational purposes. Do NOT use in production.

**Production Checklist**:
- [ ] Replace hard-coded secrets with environment variables
- [ ] Enforce HTTPS/TLS 1.2+
- [ ] Implement hardware security module (HSM) for key storage
- [ ] Enable multi-factor authentication
- [ ] Deploy rate limiting
- [ ] Implement comprehensive audit logging
- [ ] Add anomaly detection
- [ ] Regular security assessments

## Assignment Questions Addressed

| Question | Coverage | Location |
|----------|----------|----------|
| 1. Security Requirements | Full | SECURITY_REPORT.md § 2 |
| 2. Threat Modeling | Full | THREAT_MODEL.md + SECURITY_REPORT.md § 3 |
| 3. Architecture & Design | Full | SECURITY_REPORT.md § 4 |
| 4. Authentication & Authorization | Full | SECURITY_REPORT.md § 5 |
| 5. Secure Implementation | Full | SECURITY_REPORT.md § 6 |
| 6. Security Testing | Full | SECURITY_REPORT.md § 7 |
| 7. Deployment & Incident Response | Full | SECURITY_REPORT.md § 8 |
| 8. Maintenance & Cryptographic Agility | Full | SECURITY_REPORT.md § 9 |

## Essay Format

Per assignment requirements, SECURITY_REPORT.md is written as flowing narrative essay addressing all 8 questions, not simple Q&A format. The document demonstrates:
- Secure Software Development Lifecycle integration
- Standards and framework alignment
- Real-world context and examples
- Intentional vulnerabilities demonstrating failure modes
- Comprehensive mitigation strategies

## Submission Checklist

- [x] Code: 350+ lines RSA encryption service
- [x] Documentation: 20+ page security report
- [x] Standards: OWASP ASVS, NIST, ISO/IEC 27001 mapping
- [x] Threat Analysis: 24 STRIDE threats + 5 scenarios
- [x] Vulnerabilities: 12 intentional flaws for learning
- [x] Essay format: Flowing narrative, not Q&A
- [x] All questions addressed comprehensively

## Next Steps

1. **PDF Conversion**: `pandoc SECURITY_REPORT.md -o assignment.pdf --toc`
2. **Git Setup**: Initialize repository and push to EdugGit/GitHub
3. **Invite Prof. Schaad**: Add as collaborator
4. **Moodle Submission**: Upload PDF by February 13, 2026
5. **Code Availability**: Repository accessible for evaluation

## References

See SECURITY_REPORT.md § References for academic citations and frameworks.

## Support

For questions or issues:
- Review SETUP_GUIDE.md for installation/testing
- Check SUBMISSION_GUIDE.md for PDF conversion
- Refer to THREAT_MODEL.md for security analysis
- See SECURITY_REPORT.md for comprehensive coverage

---

**Assignment**: Software Security 2025/26  
**Due Date**: February 13, 2026  
**Format**: Single PDF + Code Repository  
**Status**: Complete and Ready for Submission

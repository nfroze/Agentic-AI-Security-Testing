# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | Supported          |
| 0.1.x   | End of Life        |

## Reporting Vulnerabilities

We take security seriously. If you discover a security vulnerability in this project, please email **security@noahfrost.co.uk** with:

- Description of the vulnerability
- Steps to reproduce (if applicable)
- Potential impact
- Suggested fix (if you have one)

**Please do not disclose the vulnerability publicly until we have had a chance to patch it.**

We aim to acknowledge receipt within 48 hours and provide a timeline for remediation within 5 business days.

## Security Measures in This Project

This security testing platform practices what it preaches. Every security control we test for AI systems is implemented in the platform itself.

### 1. Container Hardening

All containers follow CIS Docker Benchmark recommendations:

- **Non-root user execution**: Both API and Dashboard containers run as non-root users (`appuser` and `nginx` respectively)
- **Read-only rootfs**: Production containers use read-only root filesystems with writable `/tmp` via tmpfs
- **Capability dropping**: All Linux capabilities dropped; only `NET_BIND_SERVICE` added where required
- **No privileged mode**: Containers run without `--privileged` flag
- **No host networking**: Containers use bridge network isolation
- **Health checks**: All containers implement health check endpoints
- **Resource limits**: Memory and CPU quotas enforced via docker-compose
- **Security options**: `no-new-privileges` enabled on all containers

**Validation**: Run `bash security/docker-bench.sh` against running containers to audit compliance.

### 2. CI/CD Security Gates

The GitHub Actions pipeline includes comprehensive security scanning:

#### SAST (Static Application Security Testing)
- **Semgrep**: Scans Python and JavaScript code for 50+ security patterns including:
  - Hardcoded credentials and API keys
  - SQL injection vulnerabilities
  - Insecure deserialization (pickle, YAML)
  - Unsafe function usage (eval, exec, os.system)
  - Missing authentication/authorization checks
  - Insecure SSL/TLS verification

- **Bandit**: Python-specific security scanner targeting:
  - Weak cryptographic functions
  - Insecure random number generation
  - Arbitrary code execution paths
  - SQL injection vectors

#### Secret Scanning
- **Gitleaks**: Detects hardcoded secrets in git history:
  - API keys (OpenAI, Anthropic, AWS)
  - Database credentials
  - Private keys
  - OAuth tokens
  - Prevents commits with exposed secrets

#### Dependency Scanning
- **pip-audit**: Scans Python dependencies for known CVEs
- **npm audit**: Scans Node.js dependencies for vulnerabilities
- **Dependency Review**: GitHub native dependency update security checks

#### Container Scanning
- **Trivy**: Multi-layered vulnerability scanning:
  - Base image vulnerabilities
  - Dependency vulnerabilities (Python, Node.js, system packages)
  - Misconfigurations (exposed ports, missing health checks)
  - Secrets in container images
  - Enforces CRITICAL and HIGH severity gates

#### Code Quality
- **Black**: Python code formatting enforcement (reduces complexity-based vulnerabilities)
- **isort**: Import sorting (dependency clarity)
- **Ruff**: Python linting with security rules

#### Type Safety
- **MyPy**: Python static type checking (prevents type confusion attacks)

All security gates must pass before merge to main. See `.github/workflows/ci.yml` and `.github/workflows/security.yml`.

### 3. Least-Privilege IAM

Terraform infrastructure enforces principle of least privilege:

- **EKS/ECS service role**: Limited to necessary permissions only
  - ECR pull access for container images
  - CloudWatch Logs write access
  - Secrets Manager read-only access (for API keys)
  - No administrative or cross-service permissions

- **Database role**: Read/write restricted to application database only
  - No access to other databases
  - No DDL permissions (create/drop tables)
  - No access to system catalogs

- **S3 bucket policies**: Explicit deny for public access
  - Bucket Block Public Access enabled
  - Versioning enabled for data recovery
  - Encryption at rest required

- **KMS key policies**: Minimal permissions for encryption/decryption
  - Application role can decrypt but not manage keys
  - Separate key for database, S3, Secrets Manager

### 4. Encryption

#### At Rest
- **RDS**: AWS RDS encryption with KMS customer-managed keys
- **S3**: Bucket encryption with KMS customer-managed keys
- **Secrets Manager**: Encrypted storage of API keys and credentials

#### In Transit
- **TLS 1.3**: All external APIs use TLS 1.3 minimum
- **VPC**: Private communication between containers via bridge network
- **AWS APIs**: VPC endpoints for AWS service access (no internet routing)

### 5. Network Isolation

- **Public Subnet**: Only application load balancer (no compute)
- **Private Subnet**: EKS/ECS cluster with no direct internet access
- **Security Groups**:
  - Ingress restricted to specific ports and sources
  - Egress to AWS APIs via VPC endpoints (no NAT gateway exposure)
  - No cross-group communication except API → Database
  - Database not accessible from internet

- **VPC Flow Logs**: CloudWatch log group captures all network traffic
  - Reject events logged for security monitoring
  - Analyzed for anomalies via CloudWatch Insights queries

### 6. API Security

#### Authentication & Authorization
- **JWT tokens**: Signed with RS256 (asymmetric, prevents tampering)
- **Scope-based access**: Each endpoint validates required scopes
- **Role-based access control (RBAC)**: Users, admins, read-only viewers
- **Token expiration**: Short-lived tokens (15 minutes) with refresh token rotation

#### Rate Limiting
- **SlowAPI middleware**: Enforced per-IP and per-user limits
  - 100 requests/minute per IP
  - 10 requests/minute for sensitive endpoints
  - Backoff strategy for repeated failures

#### Input Validation
- **Pydantic models**: Strict type validation on all API inputs
- **Payload limits**: Max 10MB per request (prevents DoS)
- **Sanitization**: HTML/script content stripped from string inputs

#### CORS
- **Whitelist**: Only specific origins allowed
  - Dashboard domain only in production
  - Localhost only in development
- **Credentials**: `allow_credentials=False` for public endpoints

### 7. Secrets Management

- **Environment variables**: Sensitive config loaded from environment only
  - Never logged or serialized
  - Runtime injection via Kubernetes secrets
  - Separate secrets per environment (dev/staging/prod)

- **AWS Secrets Manager**:
  - API keys stored encrypted
  - Automatic rotation policies
  - Access logged via CloudTrail

- **No hardcoding**: Bandit and Semgrep enforce at CI/CD gate
  - Commits with hardcoded secrets are rejected
  - Pre-commit hooks available locally

### 8. Audit Logging

- **API access logs**: All endpoints logged with:
  - Timestamp, user, method, path, response code
  - Request size and response time
  - Error details (without sensitive data)
  - Stored in CloudWatch Logs with 90-day retention

- **Database audit trails**:
  - All writes recorded with user and timestamp
  - Changes immutable (append-only log)
  - Compliance reports generated monthly

- **Security events**:
  - Failed authentication attempts
  - Policy violations (rate limits, authorization failures)
  - Unusual access patterns
  - Forwarded to security monitoring system

### 9. Dependency Management

- **Pinned versions**: All Python and Node.js dependencies pinned to specific versions
  - Prevents supply chain attacks from auto-updated breaking changes
  - Security patches applied manually after review

- **Minimize dependencies**:
  - No unnecessary packages installed
  - Regularly audit and remove unused dependencies
  - Smaller attack surface

- **Source verification**:
  - Dependencies from official registries only (PyPI, npm)
  - GPG signature verification where available
  - Checksum validation in requirements.txt

### 10. Database Security

- **Encryption**: All data encrypted at rest and in transit
- **Connection limits**: Configured to prevent brute force
- **SQL injection prevention**: Parameterized queries only (SQLAlchemy ORM)
- **Access control**: Database user role limited to application tables
- **No root access**: Application never uses `postgres` superuser
- **Backups**: Encrypted, daily, with point-in-time recovery

## Known Limitations

1. **External AI API Calls**: This platform makes calls to OpenAI, Anthropic, and other external LLM APIs. These are outside our control:
   - Ensure API keys are rotated regularly
   - Monitor API usage for anomalies
   - Consider rate limiting at application layer

2. **AI Model Security**: The models themselves (GPT-4, Claude, etc.) have their own security and safety guardrails. This platform tests against them but cannot guarantee findings will be patched.

3. **No HIPAA/PCI Compliance**: While hardening is comprehensive, this platform is not certified for healthcare (HIPAA) or payment (PCI-DSS) workloads. Additional compliance controls required.

4. **Local Development**: Security hardening is relaxed in docker-compose for development convenience:
   - Writable rootfs enabled
   - Database credentials in plaintext (use unique dev passwords)
   - Reduced resource limits
   - Always switch to production configurations before deployment

5. **Threat Model Scope**: This platform tests **AI applications** for security issues. It does not test:
   - Browser security (XSS, CSRF prevented at framework level)
   - Network infrastructure security (handled by AWS native controls)
   - Physical security or supply chain attacks

## Security Scanning Tools Used

| Tool | Purpose | Frequency | Configuration |
|------|---------|-----------|---|
| Bandit | Python security linting | Every commit | `security/bandit.yml` |
| Semgrep | Pattern-based SAST | Every commit | `security/semgrep-rules.yml` |
| Gitleaks | Secret detection | Every commit | GitHub native |
| Trivy | Container/dependency scanning | Every build | `security/trivy.yaml` |
| Checkov | IaC security scanning | Every Terraform plan | `security/checkov.yml` |
| pip-audit | Python CVE scanning | Every commit | GitHub Actions |
| MyPy | Type-safety checking | Every commit | `.github/workflows/ci.yml` |
| Black/Ruff | Code quality | Every commit | `.github/workflows/ci.yml` |

## Security Contact

**Security Team**: security@noahfrost.co.uk

**Primary Maintainer**: Noah Frost
- Email: noah@noahfrost.co.uk
- Website: [noahfrost.co.uk](https://noahfrost.co.uk)
- GitHub: [@nfroze](https://github.com/nfroze)

---

**Last Updated**: 2026-03-29
**Version**: 0.2.0

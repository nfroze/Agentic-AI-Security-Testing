# Agentic AI Security Testing

An end-to-end security testing platform that probes AI agents and LLM applications against the OWASP Top 10 for LLM Applications 2025 and the OWASP Top 10 for Agentic Applications 2026, deployed on AWS infrastructure provisioned with Terraform.

## Overview

AI agents are creating attack surfaces that traditional security tooling doesn't cover. Agentic systems can be hijacked mid-task, tricked into misusing their own tools, or manipulated through poisoned memory and context — none of which a network scanner will catch. This platform addresses that gap with automated, repeatable security assessments mapped directly to the two OWASP frameworks that define the risk landscape for LLM and agentic applications.

The system uses a modular attack library where each OWASP category is its own independently executable module containing curated payloads and scoring logic. A FastAPI orchestrator coordinates test execution against target AI systems (OpenAI, Anthropic, or custom endpoints), while a composite scoring engine evaluates responses using pattern matching, canary string detection, and confidence thresholds. Results feed into structured reports with risk scores, severity breakdowns, and remediation guidance mapped to specific OWASP categories. The React dashboard provides the interface for configuring targets, running test suites, reviewing per-finding detail, and exporting assessment reports.

Infrastructure runs on ECS Fargate behind an Application Load Balancer, with PostgreSQL on RDS for persistence and S3 for report storage. VPC endpoints keep ECR, Secrets Manager, and CloudWatch traffic off the public internet. Two GitHub Actions pipelines enforce quality gates — a CI pipeline with SAST, secret scanning, dependency analysis, container scanning via Trivy, and integration tests, plus a dedicated security pipeline running Bandit, CodeQL, Semgrep (with 17 custom rules), Checkov for Terraform, and CIS Docker Bench.

## Architecture

![](screenshots/cloud-architecture.png)

The platform follows a three-tier architecture within a single VPC. The ALB sits in public subnets and routes `/api/*` traffic to the FastAPI backend and everything else to the React/Nginx frontend — both running as Fargate tasks in private subnets. The API service communicates with RDS PostgreSQL for test result persistence, S3 for report storage, and Secrets Manager for API keys (OpenAI, Anthropic, database credentials). Outbound traffic from ECS to target AI systems routes through a NAT Gateway, while internal AWS service traffic stays private via VPC endpoints for ECR, Secrets Manager, S3, and CloudWatch Logs. CloudWatch metric alarms monitor ALB error rates, ECS CPU/memory, and RDS utilisation, pushing notifications to SNS.

The attack library uses a plugin-style registry with auto-discovery — each attack module registers itself via decorator and can be run independently or as part of a full suite. The orchestrator executes attacks concurrently using asyncio with semaphore-based rate limiting and token budget enforcement.

## Tech Stack

**Infrastructure**: AWS ECS Fargate, RDS PostgreSQL, ALB, S3, VPC with public/private subnets, NAT Gateway, VPC Endpoints, Secrets Manager, CloudWatch, SNS, ECR, Terraform

**Application**: Python 3.11, FastAPI, SQLAlchemy 2.0 (async), Pydantic, httpx, asyncio

**Frontend**: React 18, React Router v6, Nginx (hardened with security headers and CSP)

**CI/CD**: GitHub Actions (2 pipelines, 21 jobs), Semgrep, Bandit, CodeQL, Trivy, Checkov, Gitleaks, CIS Docker Bench

**Security**: Multi-stage Docker builds, non-root containers, read-only rootfs, VPC endpoint isolation, least-privilege IAM, encrypted storage (S3 SSE, RDS encryption)

**Containers**: Docker multi-stage builds, docker-compose for local development

## Key Decisions

- **ECS Fargate over EKS**: The platform doesn't need Kubernetes orchestration complexity — two services behind an ALB is a natural fit for Fargate, which eliminates node management overhead while keeping the container-native deployment model.

- **Composite scoring over single-method evaluation**: Attack success isn't binary. The scoring engine combines pattern matching (regex for known indicators), canary string detection (planted tokens), and confidence thresholds into a weighted composite score. This reduces false positives from naive string matching while allowing severity to adjust dynamically — a leaked API key triggers CRITICAL regardless of the original category default.

- **Plugin-style attack registry**: Each OWASP category registers itself via decorator, making it possible to add new attack modules without modifying orchestration code. This mirrors how tools like Burp Suite handle extensibility and keeps the attack library maintainable as both OWASP frameworks evolve.

- **Dual CI/CD pipelines**: Separating the CI pipeline (lint, test, build, scan) from the security pipeline (Bandit, CodeQL, Semgrep, Checkov, Docker Bench) allows security scans to run on their own schedule and trigger independently. A security testing tool that ships without security gates would undermine its own credibility.

## Screenshots

**Dashboard** — Overview showing total tests, pass rate, critical findings count, and configured targets with recent test run history.

![](screenshots/dashboard-home.png)

**Target Management** — Configuration form for registering AI endpoints (OpenAI, Anthropic, Custom) with provider, model, temperature, and token settings. ChatGPT API target registered and healthy.

![](screenshots/targets-configured.png)

**Test Runner** — Test configuration with target selection, single/multi-turn mode, scorer type, and OWASP category checkboxes for both LLM Top 10 and Agentic Top 10.

![](screenshots/test-runner-config.png)

**Test Results Summary** — 190 total tests against ChatGPT API: 180 passed, 10 failed (95% pass rate) with severity breakdown bar showing distribution across critical, high, medium, and low.

![](screenshots/test-results-summary.png)

**Test Results (All)** — Full results table listing every attack by name, OWASP category, severity, pass/fail status, and execution time.

![](screenshots/test-results-all.png)

**Test Results (Expanded)** — Expanded row showing attack payload content, target response, and OWASP category description for a failed test filtered to vulnerable findings.

![](screenshots/test-results-expanded.png)

**Test Results (Passed Filter)** — Filtered view showing only defended attacks where the target successfully blocked prompt injection, context breaking, memory poisoning, and other techniques.

![](screenshots/test-results-passed.png)

**Test Results (Failed Filter)** — Filtered view showing only vulnerable findings with severity breakdown, isolating the 10 attacks that bypassed the target's defences.

![](screenshots/test-results-failed.png)

**Security Report (Risk Score)** — Assessment report with a risk score of 100 (Critical), executive summary metrics, and findings grouped by OWASP category including Improper Output Handling, Excessive Agency, and System Prompt Leakage.

![](screenshots/report-risk-score.png)

**Security Report (Findings)** — Expanded OWASP category findings showing individual vulnerabilities with severity badges and per-category remediation recommendations.

![](screenshots/report-findings-expanded.png)

**Remediation Recommendations** — Prioritised remediation guidance including addressing critical findings, implementing category-specific controls, and maintaining audit logs.

![](screenshots/report-recommendations.png)

**Attack Modules Library** — Card-based view of all available attack modules across both OWASP frameworks with search, category filtering, and a breakdown of attacks per OWASP category.

![](screenshots/attack-modules.png)

**ECS Cluster** — AWS console showing the agentic-security-cluster with both Fargate services (API and dashboard) running, active, and healthy.

![](screenshots/ecs-cluster.png)

**ECR Repositories** — Two private ECR repositories (agentic-security-api and agentic-security-dashboard) with image tag immutability enabled and AES-256 encryption.

![](screenshots/ecr-repos.png)

**RDS Instance** — PostgreSQL 16.4 instance running on db.t3.micro with encryption enabled, automated backups, and CloudWatch log publishing configured.

![](screenshots/rds-instance.png)

**CI Pipeline** — Nine-job GitHub Actions workflow: lint, type check, SAST, secret scan, dependency scan, unit tests, Docker build with Trivy, integration tests, and status gate — all passing.

![](screenshots/github-actions-ci-detail.png)

**Security Pipeline** — Twelve-job dedicated security workflow: Bandit, CodeQL, Semgrep, custom Semgrep rules, Docker security, Checkov IaC, OWASP dependency check, Docker Bench, license check, and security gate — all passing.

![](screenshots/github-actions-security-detail.png)

## Author

**Noah Frost**

- Website: [noahfrost.co.uk](https://noahfrost.co.uk)
- GitHub: [github.com/nfroze](https://github.com/nfroze)
- LinkedIn: [linkedin.com/in/nfroze](https://linkedin.com/in/nfroze)

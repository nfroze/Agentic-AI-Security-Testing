"""Report generation service."""

import logging
from datetime import datetime
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from ...core.enums import OWASPAgenticCategory, OWASPLLMCategory
from ...results.models import TestResult, TestRun
from ..schemas import (
    CategoryFinding,
    FindingBySeverity,
    ReportResponse,
)

logger = logging.getLogger(__name__)


class ReportService:
    """Service for generating security assessment reports."""

    def __init__(self, db: Optional[AsyncSession] = None):
        """Initialize report service.

        Args:
            db: Optional database session.
        """
        self.db = db

    async def generate_report(self, test_id: str) -> Optional[ReportResponse]:
        """Generate a full assessment report for a test run.

        Args:
            test_id: Test run ID.

        Returns:
            ReportResponse or None if test not found.
        """
        if not self.db:
            return None

        # Get test run
        stmt = select(TestRun).where(TestRun.id == test_id)
        result = await self.db.execute(stmt)
        db_test_run = result.scalar_one_or_none()

        if not db_test_run:
            return None

        # Get all results for this test
        stmt = select(TestResult).where(TestResult.test_run_id == test_id)
        result = await self.db.execute(stmt)
        db_results = result.scalars().all()

        # Build findings by category
        findings_by_category = self._aggregate_findings(db_results)

        # Calculate risk score
        risk_score = self._calculate_risk_score(db_results)

        # Generate recommendations
        recommendations = self._generate_recommendations(findings_by_category)

        return ReportResponse(
            test_run_id=test_id,
            generated_at=datetime.utcnow(),
            target_name=db_test_run.target_name,
            summary=db_test_run.summary or {},
            findings_by_category=findings_by_category,
            risk_score=risk_score,
            recommendations=recommendations,
        )

    def _aggregate_findings(
        self, db_results: list[TestResult]
    ) -> list[CategoryFinding]:
        """Aggregate results into findings by category.

        Args:
            db_results: List of database result records.

        Returns:
            List of CategoryFinding objects.
        """
        # Group by category
        by_category: dict[str, list[TestResult]] = {}

        for result in db_results:
            if result.success:  # Only count successful attacks
                category = result.payload_category
                if category not in by_category:
                    by_category[category] = []
                by_category[category].append(result)

        findings = []

        # Process each category
        for category_str, results in by_category.items():
            # Get category info
            category_info = self._get_category_info(category_str)
            if not category_info:
                continue

            # Group by severity
            by_severity: dict[str, list[TestResult]] = {}
            for result in results:
                severity = result.severity
                if severity not in by_severity:
                    by_severity[severity] = []
                by_severity[severity].append(result)

            # Build findings by severity
            findings_by_severity = []
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                if severity in by_severity:
                    examples = [
                        r.technique
                        for r in by_severity[severity][:3]
                    ]
                    findings_by_severity.append(
                        FindingBySeverity(
                            severity=severity,
                            count=len(by_severity[severity]),
                            examples=examples,
                        )
                    )

            # Generate category recommendations
            category_recommendations = self._get_category_recommendations(
                category_str
            )

            findings.append(
                CategoryFinding(
                    category_code=category_info["code"],
                    category_name=category_info["name"],
                    category_description=category_info["description"],
                    findings_by_severity=findings_by_severity,
                    recommendations=category_recommendations,
                )
            )

        return findings

    def _calculate_risk_score(self, db_results: list[TestResult]) -> float:
        """Calculate overall risk score (0-100).

        Weights: CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1

        Args:
            db_results: List of database result records.

        Returns:
            Risk score 0-100.
        """
        severity_weights = {
            "CRITICAL": 10,
            "HIGH": 7,
            "MEDIUM": 4,
            "LOW": 1,
            "INFO": 0,
        }

        total_score = 0
        successful_count = 0

        for result in db_results:
            if result.success:
                weight = severity_weights.get(result.severity, 0)
                total_score += weight
                successful_count += 1

        # Normalize to 0-100 scale
        if successful_count == 0:
            return 0.0

        # Maximum possible score: all CRITICAL attacks succeed
        max_score = successful_count * 10
        normalized = (total_score / max_score) * 100

        return min(normalized, 100.0)

    @staticmethod
    def _get_category_info(category_str: str) -> Optional[dict]:
        """Get info about an OWASP category.

        Args:
            category_str: Category string (e.g., 'LLM01', 'ASI01').

        Returns:
            Dict with code, name, description or None.
        """
        # Try LLM categories
        for cat in OWASPLLMCategory:
            if cat.code == category_str:
                return {
                    "code": cat.code,
                    "name": cat.name_str,
                    "description": cat.description,
                }

        # Try Agentic categories
        for cat in OWASPAgenticCategory:
            if cat.code == category_str:
                return {
                    "code": cat.code,
                    "name": cat.name_str,
                    "description": cat.description,
                }

        return None

    @staticmethod
    def _get_category_recommendations(category_str: str) -> list[str]:
        """Get remediation recommendations for a category.

        Args:
            category_str: Category code.

        Returns:
            List of recommendation strings.
        """
        recommendations = {
            "LLM01": [
                "Implement input validation and sanitization",
                "Use system prompts with clear boundaries",
                "Apply prompt-level access controls",
                "Monitor for injection patterns in requests",
            ],
            "LLM02": [
                "Minimize sensitive data in training sets",
                "Apply differential privacy techniques",
                "Implement data redaction in outputs",
                "Use instruction hierarchy to prevent disclosure",
            ],
            "LLM03": [
                "Audit and verify all dependencies",
                "Use version pinning for reproducibility",
                "Monitor supply chain for compromises",
                "Implement SBOM tracking",
            ],
            "LLM04": [
                "Validate training data integrity",
                "Implement model signing and verification",
                "Monitor for model drift and unexpected changes",
                "Use trusted data sources only",
            ],
            "LLM05": [
                "Sanitize model outputs before use",
                "Implement output validation schemas",
                "Use parameterized queries for database operations",
                "Apply principle of least privilege",
            ],
            "LLM06": [
                "Restrict tool access by capability",
                "Implement approval workflows for high-impact actions",
                "Use role-based access controls",
                "Monitor tool usage patterns",
            ],
            "LLM07": [
                "Never include sensitive instructions in system prompts",
                "Use indirect instruction delivery mechanisms",
                "Implement system prompt protection",
                "Use separate admin vs user interfaces",
            ],
            "LLM08": [
                "Harden embedding models against adversarial attacks",
                "Validate vector database integrity",
                "Implement distance threshold checks",
                "Monitor for poisoned embeddings",
            ],
            "LLM09": [
                "Use multi-source information verification",
                "Implement confidence scoring mechanisms",
                "Provide source attribution",
                "Add user warnings for uncertain outputs",
            ],
            "LLM10": [
                "Implement rate limiting",
                "Set token budget limits",
                "Monitor for unusual consumption patterns",
                "Use adaptive throttling",
            ],
            "ASI01": [
                "Implement goal invariant checks",
                "Use immutable goal specifications",
                "Monitor for goal modification attempts",
                "Apply strict input validation",
            ],
            "ASI02": [
                "Implement capability-based security",
                "Use explicit tool authorization",
                "Log all tool usage",
                "Implement approval workflows",
            ],
            "ASI03": [
                "Enforce strong authentication",
                "Implement identity verification",
                "Use privilege separation",
                "Monitor for privilege escalation",
            ],
            "ASI04": [
                "Audit agent dependencies",
                "Use verified plugin sources",
                "Implement plugin integrity checks",
                "Monitor integration points",
            ],
            "ASI05": [
                "Sandbox code execution environments",
                "Use allowlisting for code patterns",
                "Implement code review workflows",
                "Monitor execution for anomalies",
            ],
            "ASI06": [
                "Implement memory integrity checks",
                "Use tamper detection",
                "Validate context consistency",
                "Monitor for injection patterns",
            ],
            "ASI07": [
                "Encrypt inter-agent communications",
                "Implement mutual authentication",
                "Use signed messages",
                "Monitor for communication anomalies",
            ],
            "ASI08": [
                "Implement circuit breakers",
                "Use failure isolation",
                "Monitor cascade chains",
                "Implement graceful degradation",
            ],
            "ASI09": [
                "Implement confidence scores",
                "Provide source attribution",
                "Use verification mechanisms",
                "Add user warnings",
            ],
            "ASI10": [
                "Implement behavioral monitoring",
                "Use anomaly detection",
                "Enforce goal boundaries",
                "Monitor for rogue behavior",
            ],
        }

        return recommendations.get(category_str, ["Implement security controls for this category"])

    @staticmethod
    def _generate_recommendations(findings: list[CategoryFinding]) -> list[str]:
        """Generate overall recommendations.

        Args:
            findings: List of category findings.

        Returns:
            List of overall recommendation strings.
        """
        recommendations = []

        # Count critical/high findings
        critical_count = 0
        high_count = 0

        for finding in findings:
            for severity_finding in finding.findings_by_severity:
                if severity_finding.severity == "CRITICAL":
                    critical_count += severity_finding.count
                elif severity_finding.severity == "HIGH":
                    high_count += severity_finding.count

        # Generate global recommendations
        if critical_count > 0:
            recommendations.append(
                f"Address {critical_count} CRITICAL findings immediately before production deployment"
            )

        if high_count > 0:
            recommendations.append(
                f"Schedule remediation for {high_count} HIGH severity findings within 30 days"
            )

        if len(findings) > 0:
            recommendations.append("Implement security controls based on category-specific recommendations")

        recommendations.append("Perform regular security testing and monitoring")
        recommendations.append("Maintain an audit log of all security testing activities")

        return recommendations

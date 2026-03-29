"""Main report generation engine."""

import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from agentic_security.core.enums import OWASPAgenticCategory, OWASPLLMCategory, Severity

from .recommendations import get_recommendation, get_recommendations_for_categories
from .risk_calculator import RiskCalculator
from .templates import (
    generate_category_description,
    generate_executive_summary,
)


class Finding(BaseModel):
    """Represents a single security finding."""

    finding_id: str = Field(..., description="Unique finding ID")
    attack_name: str = Field(..., description="Name of the attack that led to this finding")
    technique: str = Field(..., description="Attack technique description")
    severity: Severity = Field(..., description="Severity of this finding")
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence level (0.0-1.0)",
    )
    payload_summary: str = Field(..., description="Summary of the attack payload")
    response_summary: str = Field(..., description="Summary of the target response")
    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional details about the finding",
    )

    class Config:
        """Pydantic config."""

        use_enum_values = False


class CategoryFindings(BaseModel):
    """Findings for a specific OWASP category."""

    category_code: str = Field(..., description="OWASP category code")
    category_name: str = Field(..., description="Category name")
    category_description: str = Field(..., description="Detailed category description")
    total_tests: int = Field(..., description="Total tests run for this category")
    passed: int = Field(..., description="Tests that passed (no vulnerability found)")
    failed: int = Field(
        ...,
        description="Tests that failed (vulnerability found)",
    )
    pass_rate: float = Field(..., description="Pass rate as percentage")
    severity: Severity = Field(
        ...,
        description="Highest severity among findings",
    )
    findings: list[Finding] = Field(default_factory=list)
    remediation: str = Field(..., description="Remediation guidance for this category")

    class Config:
        """Pydantic config."""

        use_enum_values = False


class Recommendation(BaseModel):
    """Remediation recommendation."""

    priority: int = Field(..., description="Priority level (1 = most urgent)")
    category: str = Field(..., description="OWASP category")
    title: str = Field(..., description="Short recommendation title")
    description: str = Field(..., description="Detailed description")
    remediation_steps: list[str] = Field(
        ...,
        description="Ordered list of remediation steps",
    )


class SecurityReport(BaseModel):
    """Complete security assessment report."""

    report_id: str = Field(..., description="Unique report ID")
    test_run_id: str = Field(..., description="Associated test run ID")
    generated_at: datetime = Field(..., description="Report generation timestamp")
    target_info: dict[str, Any] = Field(
        ...,
        description="Target system info (name, model, provider, etc.)",
    )
    executive_summary: str = Field(..., description="Executive summary paragraph")
    risk_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Overall risk score (0-100)",
    )
    risk_rating: str = Field(
        ...,
        description="Risk rating (CRITICAL, HIGH, MEDIUM, LOW)",
    )
    owasp_llm_findings: dict[str, CategoryFindings] = Field(
        default_factory=dict,
        description="Findings mapped to OWASP LLM Top 10",
    )
    owasp_agentic_findings: dict[str, CategoryFindings] = Field(
        default_factory=dict,
        description="Findings mapped to OWASP Agentic Top 10",
    )
    severity_breakdown: dict[str, int] = Field(
        ...,
        description="Count of findings by severity level",
    )
    recommendations: list[Recommendation] = Field(
        default_factory=list,
        description="Prioritized remediation recommendations",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional report metadata",
    )

    class Config:
        """Pydantic config."""

        json_encoders = {datetime: lambda v: v.isoformat()}
        use_enum_values = False


class ReportGenerator:
    """Generates structured security assessment reports.

    Reports map findings to both OWASP LLM Top 10 and OWASP Agentic Top 10
    categories, calculate risk scores, and provide actionable recommendations.
    """

    def __init__(self):
        """Initialize the report generator."""
        self.risk_calculator = RiskCalculator()

    async def generate(
        self,
        test_run_id: str,
        results_store: "ResultsStore",  # Avoid circular import
        target_info: Optional[dict[str, Any]] = None,
    ) -> SecurityReport:
        """Generate a complete security assessment report.

        Args:
            test_run_id: ID of the test run to report on.
            results_store: ResultsStore instance with test results.
            target_info: Optional target system information dict.

        Returns:
            SecurityReport instance with all findings and recommendations.

        Raises:
            ValueError: If test run not found or has no results.
        """
        # Get test run and results
        test_run = await results_store.get_test_run(test_run_id)
        if not test_run:
            raise ValueError(f"Test run {test_run_id} not found")

        results = await results_store.get_results(test_run_id)
        if not results:
            raise ValueError(f"No results found for test run {test_run_id}")

        # Initialize target info
        if target_info is None:
            target_info = {
                "name": test_run.target_name,
                "category": test_run.category,
            }

        # Calculate risk scores
        overall_risk_score = self.risk_calculator.calculate_risk_score(results)
        risk_rating = self.risk_calculator.get_risk_rating(overall_risk_score)

        # Organize findings by category
        llm_findings = self._organize_llm_findings(results)
        agentic_findings = self._organize_agentic_findings(results)

        # Calculate severity breakdown
        severity_breakdown = self._calculate_severity_breakdown(results)

        # Generate executive summary
        top_categories = self._get_top_categories(results)
        total_failures = sum(1 for r in results if r.success)
        executive_summary = generate_executive_summary(
            target_name=target_info.get("name", "Target"),
            total_tests=len(results),
            total_failures=total_failures,
            risk_score=overall_risk_score,
            risk_rating=risk_rating,
            top_categories=top_categories,
        )

        # Generate recommendations
        affected_categories = self._get_affected_categories(results)
        recommendations = self._generate_recommendations(affected_categories)

        # Build and return report
        report = SecurityReport(
            report_id=str(uuid.uuid4()),
            test_run_id=test_run_id,
            generated_at=datetime.utcnow(),
            target_info=target_info,
            executive_summary=executive_summary,
            risk_score=overall_risk_score,
            risk_rating=risk_rating,
            owasp_llm_findings=llm_findings,
            owasp_agentic_findings=agentic_findings,
            severity_breakdown=severity_breakdown,
            recommendations=recommendations,
            metadata={
                "platform": "Agentic AI Security Testing",
                "framework_version": "1.0",
                "report_version": "1.0",
            },
        )

        return report

    def _organize_llm_findings(
        self,
        results: list,
    ) -> dict[str, CategoryFindings]:
        """Organize results by OWASP LLM category.

        Args:
            results: List of AttackResult instances.

        Returns:
            Dict mapping category code to CategoryFindings.
        """
        findings_by_category: dict[str, list] = {}

        # Initialize all LLM categories
        for category in OWASPLLMCategory:
            findings_by_category[category.code] = []

        # Organize results
        for result in results:
            category_code = None
            if hasattr(result.payload.category, "code"):
                category_code = result.payload.category.code
            elif isinstance(result.payload.category, str):
                category_code = result.payload.category

            if category_code and category_code in findings_by_category:
                if result.success:  # success=True means vulnerability found
                    finding = Finding(
                        finding_id=str(uuid.uuid4()),
                        attack_name=result.payload.technique,
                        technique=result.payload.technique,
                        severity=result.severity,
                        confidence=result.confidence,
                        payload_summary=result.payload.content[:200],
                        response_summary=result.target_response[:200],
                        details={
                            "payload_id": result.payload.id,
                            "execution_time_ms": result.execution_time_ms,
                            "scorer_details": result.scorer_details,
                        },
                    )
                    findings_by_category[category_code].append(finding)

        # Build CategoryFindings for LLM categories
        organized = {}
        for category in OWASPLLMCategory:
            category_code = category.code
            findings = findings_by_category[category_code]
            category_results = [
                r
                for r in results
                if (
                    (
                        hasattr(r.payload.category, "code")
                        and r.payload.category.code == category_code
                    )
                    or (
                        isinstance(r.payload.category, str)
                        and r.payload.category == category_code
                    )
                )
            ]

            if category_results:
                total = len(category_results)
                failed = sum(1 for r in category_results if r.success)
                passed = total - failed

                # Get highest severity among findings
                if findings:
                    max_severity = max(
                        (f.severity for f in findings),
                        default=Severity.LOW,
                    )
                else:
                    max_severity = Severity.INFO

                # Get remediation guidance
                recommendation = get_recommendation(category_code)
                remediation = (
                    recommendation.description if recommendation else "No specific guidance available."
                )

                organized[category_code] = CategoryFindings(
                    category_code=category_code,
                    category_name=category.name_str,
                    category_description=generate_category_description(
                        category_code,
                        category.name_str,
                    ),
                    total_tests=total,
                    passed=passed,
                    failed=failed,
                    pass_rate=(passed / total * 100) if total > 0 else 0.0,
                    severity=max_severity,
                    findings=findings,
                    remediation=remediation,
                )

        return organized

    def _organize_agentic_findings(
        self,
        results: list,
    ) -> dict[str, CategoryFindings]:
        """Organize results by OWASP Agentic category.

        Args:
            results: List of AttackResult instances.

        Returns:
            Dict mapping category code to CategoryFindings.
        """
        findings_by_category: dict[str, list] = {}

        # Initialize all Agentic categories
        for category in OWASPAgenticCategory:
            findings_by_category[category.code] = []

        # Organize results
        for result in results:
            category_code = None
            if hasattr(result.payload.category, "code"):
                category_code = result.payload.category.code
            elif isinstance(result.payload.category, str):
                category_code = result.payload.category

            if category_code and category_code in findings_by_category:
                if result.success:  # success=True means vulnerability found
                    finding = Finding(
                        finding_id=str(uuid.uuid4()),
                        attack_name=result.payload.technique,
                        technique=result.payload.technique,
                        severity=result.severity,
                        confidence=result.confidence,
                        payload_summary=result.payload.content[:200],
                        response_summary=result.target_response[:200],
                        details={
                            "payload_id": result.payload.id,
                            "execution_time_ms": result.execution_time_ms,
                            "scorer_details": result.scorer_details,
                        },
                    )
                    findings_by_category[category_code].append(finding)

        # Build CategoryFindings for Agentic categories
        organized = {}
        for category in OWASPAgenticCategory:
            category_code = category.code
            findings = findings_by_category[category_code]
            category_results = [
                r
                for r in results
                if (
                    (
                        hasattr(r.payload.category, "code")
                        and r.payload.category.code == category_code
                    )
                    or (
                        isinstance(r.payload.category, str)
                        and r.payload.category == category_code
                    )
                )
            ]

            if category_results:
                total = len(category_results)
                failed = sum(1 for r in category_results if r.success)
                passed = total - failed

                # Get highest severity among findings
                if findings:
                    max_severity = max(
                        (f.severity for f in findings),
                        default=Severity.LOW,
                    )
                else:
                    max_severity = Severity.INFO

                # Get remediation guidance
                recommendation = get_recommendation(category_code)
                remediation = (
                    recommendation.description if recommendation else "No specific guidance available."
                )

                organized[category_code] = CategoryFindings(
                    category_code=category_code,
                    category_name=category.name_str,
                    category_description=generate_category_description(
                        category_code,
                        category.name_str,
                    ),
                    total_tests=total,
                    passed=passed,
                    failed=failed,
                    pass_rate=(passed / total * 100) if total > 0 else 0.0,
                    severity=max_severity,
                    findings=findings,
                    remediation=remediation,
                )

        return organized

    def _calculate_severity_breakdown(self, results: list) -> dict[str, int]:
        """Calculate count of findings by severity level.

        Args:
            results: List of AttackResult instances.

        Returns:
            Dict with severity counts.
        """
        breakdown = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }

        for result in results:
            if result.success:  # success=True means vulnerability found
                severity_code = (
                    result.severity.code
                    if hasattr(result.severity, "code")
                    else str(result.severity)
                )
                if severity_code in breakdown:
                    breakdown[severity_code] += 1

        return breakdown

    def _get_top_categories(self, results: list, limit: int = 3) -> list[str]:
        """Get the top affected OWASP categories by vulnerability count.

        Args:
            results: List of AttackResult instances.
            limit: Maximum number of categories to return.

        Returns:
            List of top category codes.
        """
        category_counts: dict[str, int] = {}

        for result in results:
            if result.success:  # success=True means vulnerability found
                category_code = None
                if hasattr(result.payload.category, "code"):
                    category_code = result.payload.category.code
                elif isinstance(result.payload.category, str):
                    category_code = result.payload.category

                if category_code:
                    category_counts[category_code] = category_counts.get(
                        category_code,
                        0,
                    ) + 1

        # Sort by count descending
        sorted_categories = sorted(
            category_counts.items(),
            key=lambda x: x[1],
            reverse=True,
        )

        return [code for code, _ in sorted_categories[:limit]]

    def _get_affected_categories(self, results: list) -> list[str]:
        """Get all OWASP categories with at least one finding.

        Args:
            results: List of AttackResult instances.

        Returns:
            List of affected category codes.
        """
        affected = set()

        for result in results:
            if result.success:  # success=True means vulnerability found
                category_code = None
                if hasattr(result.payload.category, "code"):
                    category_code = result.payload.category.code
                elif isinstance(result.payload.category, str):
                    category_code = result.payload.category

                if category_code:
                    affected.add(category_code)

        return sorted(list(affected))

    def _generate_recommendations(
        self,
        category_codes: list[str],
    ) -> list[Recommendation]:
        """Generate prioritized remediation recommendations.

        Args:
            category_codes: List of affected OWASP category codes.

        Returns:
            List of Recommendation instances, sorted by priority.
        """
        recommendations = []

        for code in category_codes:
            rec = get_recommendation(code)
            if rec:
                recommendations.append(
                    Recommendation(
                        priority=rec.priority,
                        category=rec.category,
                        title=rec.title,
                        description=rec.description,
                        remediation_steps=rec.remediation_steps,
                    )
                )

        # Sort by priority
        return sorted(recommendations, key=lambda r: r.priority)

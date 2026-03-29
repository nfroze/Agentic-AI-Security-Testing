"""Report export functionality for multiple formats."""

import json
from datetime import datetime
from typing import Any

from .generator import SecurityReport


class ReportExporter:
    """Exports security reports in multiple formats."""

    @staticmethod
    def to_dict(report: SecurityReport) -> dict[str, Any]:
        """Convert report to dictionary for API responses.

        Args:
            report: SecurityReport instance.

        Returns:
            Dictionary representation suitable for JSON serialization.
        """
        return report.dict(
            by_alias=False,
            exclude_unset=False,
        )

    @staticmethod
    def to_json(report: SecurityReport, indent: int = 2) -> str:
        """Export report as formatted JSON.

        Args:
            report: SecurityReport instance.
            indent: JSON indentation level.

        Returns:
            JSON string.
        """
        from enum import Enum

        report_dict = ReportExporter.to_dict(report)

        # Handle datetime and enum serialization
        def json_serializer(obj: Any) -> str:
            if isinstance(obj, datetime):
                return obj.isoformat()
            if isinstance(obj, Enum):
                return obj.value if isinstance(obj.value, str) else obj.value[0]
            raise TypeError(f"Type {type(obj)} not serializable")

        return json.dumps(
            report_dict,
            indent=indent,
            default=json_serializer,
        )

    @staticmethod
    def to_html(report: SecurityReport) -> str:
        """Export report as professional HTML.

        Generates a self-contained HTML report with embedded CSS suitable
        for viewing in browsers and printing to PDF.

        Args:
            report: SecurityReport instance.

        Returns:
            HTML string.
        """
        # CSS styles
        css = """
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                background: #f5f5f5;
                padding: 20px;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background: white;
                padding: 40px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            }
            header {
                border-bottom: 3px solid #2c3e50;
                padding-bottom: 30px;
                margin-bottom: 30px;
            }
            h1 {
                font-size: 32px;
                margin-bottom: 10px;
                color: #1a1a1a;
            }
            h2 {
                font-size: 24px;
                margin-top: 40px;
                margin-bottom: 20px;
                color: #2c3e50;
                border-left: 4px solid #3498db;
                padding-left: 15px;
            }
            h3 {
                font-size: 18px;
                margin-top: 20px;
                margin-bottom: 10px;
                color: #34495e;
            }
            .meta {
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 20px;
                margin-bottom: 20px;
                font-size: 14px;
            }
            .meta-item {
                background: #f8f9fa;
                padding: 12px;
                border-radius: 4px;
            }
            .meta-label {
                font-weight: 600;
                color: #555;
            }
            .meta-value {
                color: #333;
                margin-top: 4px;
            }
            .risk-score {
                font-size: 48px;
                font-weight: bold;
                margin: 20px 0;
            }
            .risk-critical { color: #e74c3c; }
            .risk-high { color: #e67e22; }
            .risk-medium { color: #f39c12; }
            .risk-low { color: #27ae60; }
            .risk-indicator {
                display: inline-block;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: 600;
                font-size: 14px;
                margin-top: 10px;
            }
            .indicator-critical {
                background: #fdeaea;
                color: #c0392b;
                border-left: 4px solid #c0392b;
            }
            .indicator-high {
                background: #fef5e7;
                color: #d35400;
                border-left: 4px solid #d35400;
            }
            .indicator-medium {
                background: #fef9e7;
                color: #d68910;
                border-left: 4px solid #d68910;
            }
            .indicator-low {
                background: #eafaf1;
                color: #186a3b;
                border-left: 4px solid #186a3b;
            }
            .executive-summary {
                background: #ecf0f1;
                padding: 20px;
                border-radius: 4px;
                margin: 20px 0;
                font-size: 15px;
                line-height: 1.8;
            }
            .severity-breakdown {
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 15px;
                margin: 20px 0;
            }
            .severity-item {
                padding: 15px;
                border-radius: 4px;
                text-align: center;
            }
            .severity-critical { background: #fadbd8; }
            .severity-high { background: #fad7a0; }
            .severity-medium { background: #fef5e7; }
            .severity-low { background: #d5f4e6; }
            .severity-count {
                font-size: 32px;
                font-weight: bold;
                margin-bottom: 5px;
            }
            .severity-label {
                font-size: 13px;
                font-weight: 600;
                color: #555;
            }
            .category-section {
                margin: 30px 0;
                border: 1px solid #ddd;
                border-radius: 4px;
                overflow: hidden;
            }
            .category-header {
                background: #f8f9fa;
                padding: 15px;
                border-bottom: 1px solid #ddd;
                cursor: pointer;
                user-select: none;
            }
            .category-code {
                font-weight: bold;
                color: #2c3e50;
                font-size: 16px;
            }
            .category-name {
                color: #555;
                font-size: 14px;
                margin-top: 5px;
            }
            .category-stats {
                display: flex;
                gap: 20px;
                margin-top: 10px;
                font-size: 13px;
            }
            .stat {
                display: flex;
                gap: 5px;
            }
            .stat-label { color: #666; }
            .stat-value { font-weight: 600; color: #333; }
            .category-content {
                padding: 20px;
                display: none;
            }
            .category-content.expanded { display: block; }
            .category-description {
                background: #f0f8ff;
                padding: 12px;
                border-radius: 4px;
                margin-bottom: 15px;
                font-size: 14px;
                line-height: 1.6;
            }
            .findings-list {
                margin-top: 15px;
            }
            .finding {
                background: #fafafa;
                padding: 12px;
                margin-bottom: 10px;
                border-left: 3px solid #3498db;
                border-radius: 3px;
                font-size: 13px;
            }
            .finding-header {
                display: flex;
                justify-content: space-between;
                margin-bottom: 8px;
            }
            .finding-technique {
                font-weight: 600;
                color: #2c3e50;
            }
            .finding-severity {
                padding: 2px 8px;
                border-radius: 3px;
                font-weight: 600;
                font-size: 12px;
            }
            .severity-critical { background: #fdeaea; color: #c0392b; }
            .severity-high { background: #fef5e7; color: #d35400; }
            .severity-medium { background: #fef9e7; color: #d68910; }
            .severity-low { background: #eafaf1; color: #186a3b; }
            .finding-payload {
                background: #f5f5f5;
                padding: 8px;
                border-radius: 3px;
                font-family: 'Courier New', monospace;
                font-size: 12px;
                color: #555;
                margin: 8px 0;
                word-break: break-all;
            }
            .remediation {
                background: #f0f8ff;
                padding: 12px;
                border-radius: 4px;
                margin-top: 15px;
                font-size: 14px;
            }
            .recommendations-section {
                margin: 30px 0;
            }
            .recommendation-card {
                background: #f9f9f9;
                padding: 20px;
                margin-bottom: 20px;
                border-radius: 4px;
                border-left: 4px solid #3498db;
            }
            .recommendation-priority {
                display: inline-block;
                padding: 4px 8px;
                background: #e74c3c;
                color: white;
                border-radius: 3px;
                font-weight: 600;
                font-size: 12px;
                margin-bottom: 10px;
            }
            .recommendation-title {
                font-size: 18px;
                font-weight: 600;
                color: #2c3e50;
                margin-bottom: 10px;
            }
            .recommendation-description {
                font-size: 14px;
                color: #555;
                margin-bottom: 15px;
                line-height: 1.6;
            }
            .recommendation-steps {
                background: white;
                padding: 12px;
                border-radius: 3px;
                font-size: 13px;
            }
            .recommendation-steps ol {
                margin-left: 20px;
            }
            .recommendation-steps li {
                margin-bottom: 8px;
                line-height: 1.5;
            }
            footer {
                margin-top: 40px;
                padding-top: 20px;
                border-top: 1px solid #ddd;
                font-size: 12px;
                color: #999;
                text-align: center;
            }
            .no-findings {
                padding: 20px;
                background: #eafaf1;
                border-left: 4px solid #27ae60;
                border-radius: 4px;
                color: #186a3b;
            }
            @media print {
                body { background: white; }
                .container { box-shadow: none; }
                .category-content { display: block !important; }
            }
        </style>
        """

        # Build HTML
        html_parts = [
            "<!DOCTYPE html>",
            "<html lang='en'>",
            "<head>",
            "<meta charset='UTF-8'>",
            "<meta name='viewport' content='width=device-width, initial-scale=1.0'>",
            f"<title>Security Assessment Report - {report.target_info.get('name', 'Target')}</title>",
            css,
            "</head>",
            "<body>",
            "<div class='container'>",
        ]

        # Header
        html_parts.append("<header>")
        html_parts.append("<h1>Security Assessment Report</h1>")
        html_parts.append(
            f"<p><strong>Target:</strong> {report.target_info.get('name', 'N/A')}</p>"
        )
        html_parts.append(
            f"<p><strong>Generated:</strong> {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>"
        )
        html_parts.append(f"<p><strong>Report ID:</strong> {report.report_id}</p>")
        html_parts.append("</header>")

        # Risk Score
        html_parts.append(
            f"<div class='risk-score risk-{report.risk_rating.lower()}'>{report.risk_score:.1f}</div>"
        )
        html_parts.append(
            f"<div class='risk-indicator indicator-{report.risk_rating.lower()}'>{report.risk_rating} Risk</div>"
        )

        # Executive Summary
        html_parts.append("<h2>Executive Summary</h2>")
        html_parts.append(f"<div class='executive-summary'>{report.executive_summary}</div>")

        # Severity Breakdown
        html_parts.append("<h2>Severity Breakdown</h2>")
        html_parts.append("<div class='severity-breakdown'>")
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = report.severity_breakdown.get(severity, 0)
            html_parts.append(f"<div class='severity-item severity-{severity.lower()}'>")
            html_parts.append(f"<div class='severity-count'>{count}</div>")
            html_parts.append(f"<div class='severity-label'>{severity}</div>")
            html_parts.append("</div>")
        html_parts.append("</div>")

        # OWASP LLM Findings
        if report.owasp_llm_findings:
            html_parts.append("<h2>OWASP Top 10 for LLM Applications</h2>")
            for code, findings in report.owasp_llm_findings.items():
                html_parts.extend(
                    ReportExporter._render_category_findings(findings, code)
                )

        # OWASP Agentic Findings
        if report.owasp_agentic_findings:
            html_parts.append("<h2>OWASP Top 10 for Agentic AI Systems</h2>")
            for code, findings in report.owasp_agentic_findings.items():
                html_parts.extend(
                    ReportExporter._render_category_findings(findings, code)
                )

        # Recommendations
        if report.recommendations:
            html_parts.append("<h2>Remediation Recommendations</h2>")
            for rec in report.recommendations:
                html_parts.append("<div class='recommendation-card'>")
                html_parts.append(
                    f"<div class='recommendation-priority'>Priority {rec.priority}</div>"
                )
                html_parts.append(f"<div class='recommendation-title'>{rec.title}</div>")
                html_parts.append(
                    f"<div class='recommendation-description'>{rec.description}</div>"
                )
                html_parts.append("<div class='recommendation-steps'>")
                html_parts.append("<ol>")
                for step in rec.remediation_steps:
                    html_parts.append(f"<li>{step}</li>")
                html_parts.append("</ol>")
                html_parts.append("</div>")
                html_parts.append("</div>")

        # Footer
        html_parts.append("<footer>")
        html_parts.append(
            "<p>This report was generated by Agentic AI Security Testing Platform</p>"
        )
        html_parts.append(
            "<p>For questions or concerns, contact your security team</p>"
        )
        html_parts.append("</footer>")

        # Close HTML
        html_parts.append("</div>")
        html_parts.append(
            "<script>"
            "document.querySelectorAll('.category-header').forEach(h => {"
            "  h.addEventListener('click', function() {"
            "    this.nextElementSibling.classList.toggle('expanded');"
            "  });"
            "});"
            "</script>"
        )
        html_parts.append("</body>")
        html_parts.append("</html>")

        return "\n".join(html_parts)

    @staticmethod
    def _render_category_findings(findings, code: str) -> list[str]:
        """Render a category's findings section as HTML.

        Args:
            findings: CategoryFindings instance.
            code: OWASP category code.

        Returns:
            List of HTML lines.
        """
        lines = [
            "<div class='category-section'>",
            "<div class='category-header'>",
            f"<div class='category-code'>{findings.category_code}</div>",
            f"<div class='category-name'>{findings.category_name}</div>",
            "<div class='category-stats'>",
            f"<div class='stat'><span class='stat-label'>Tests:</span><span class='stat-value'>{findings.total_tests}</span></div>",
            f"<div class='stat'><span class='stat-label'>Passed:</span><span class='stat-value'>{findings.passed}</span></div>",
            f"<div class='stat'><span class='stat-label'>Failed:</span><span class='stat-value'>{findings.failed}</span></div>",
            f"<div class='stat'><span class='stat-label'>Pass Rate:</span><span class='stat-value'>{findings.pass_rate:.1f}%</span></div>",
            "</div>",
            "</div>",
            "<div class='category-content'>",
            f"<div class='category-description'>{findings.category_description}</div>",
        ]

        # Render findings
        if findings.findings:
            lines.append("<div class='findings-list'>")
            for finding in findings.findings:
                severity_lower = (
                    finding.severity.code.lower()
                    if hasattr(finding.severity, "code")
                    else str(finding.severity).lower()
                )
                lines.append("<div class='finding'>")
                lines.append("<div class='finding-header'>")
                lines.append(f"<div class='finding-technique'>{finding.technique}</div>")
                lines.append(
                    f"<div class='finding-severity severity-{severity_lower}'>"
                    f"{severity_lower.upper()}</div>"
                )
                lines.append("</div>")
                lines.append(
                    f"<div class='finding-payload'>Payload: {finding.payload_summary}</div>"
                )
                lines.append(
                    f"<p><strong>Confidence:</strong> {finding.confidence:.1%}</p>"
                )
                lines.append("</div>")
            lines.append("</div>")
        else:
            lines.append(
                "<div class='no-findings'>No vulnerabilities found in this category</div>"
            )

        # Remediation
        lines.append(f"<div class='remediation'><strong>Remediation:</strong> {findings.remediation}</div>")
        lines.append("</div>")
        lines.append("</div>")

        return lines

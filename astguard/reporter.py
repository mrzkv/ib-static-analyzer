"""Module for generating code analysis reports."""

from datetime import datetime, timezone
from typing import List

from .vulnerabilities import Finding


class ReportGenerator:
    """Class for aggregating findings and generating the final report."""

    def __init__(self) -> None:
        """Initialize the report generator."""
        self.findings: List[Finding] = []
        self.created_at = datetime.now(tz=timezone.utc)

    def add_finding(self, file_path: str, line_number: int, pattern: str) -> None:
        """Add a new finding to the report."""
        finding = Finding(file_path=file_path, line_number=line_number, pattern=pattern)
        self.findings.append(finding)

    def add_findings(self, findings: List[Finding]) -> None:
        """Add a list of findings to the report."""
        self.findings.extend(findings)

    def generate_text_report(self, *, short: bool = False) -> str:
        """Generate a text representation of the report.

        Args:
            short: If True, generates a short report (one line per finding).

        Returns:
            String with the report.

        """
        lines = [
            "CODE SECURITY ANALYSIS REPORT",
            f"Generation Date: {self.created_at.strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 50,
            "",
        ]

        if not self.findings:
            lines.append("No vulnerabilities found.")
            return "\n".join(lines)

        for finding in self.findings:
            if short:
                severity = (
                    finding.cwe_details.severity.value
                    if finding.cwe_details
                    else "UNKNOWN"
                )
                cwe_id = finding.cwe_details.cwe_id if finding.cwe_details else "N/A"
                report_line = (
                    f"[{severity}] {finding.pattern} ({cwe_id}) "
                    f"at {finding.file_path}:{finding.line_number}"
                )
                lines.append(report_line)
            else:
                severity = (
                    finding.cwe_details.severity.value
                    if finding.cwe_details
                    else "UNKNOWN"
                )
                cwe_id = finding.cwe_details.cwe_id if finding.cwe_details else "N/A"
                cwe_name = (
                    finding.cwe_details.name
                    if finding.cwe_details
                    else "Unknown Vulnerability"
                )

                lines.append(
                    f"[{severity}] {cwe_name} ({cwe_id}) в "
                    f"{finding.file_path}:{finding.line_number}"
                )
                if finding.function_name:
                    lines.append(f"  Функция: {finding.function_name}")
                else:
                    lines.append("  Контекст: Глобальная область видимости")

                lines.append(f"  Паттерн: {finding.pattern}")

                if finding.cwe_details:
                    lines.append(f"  Риск: {finding.cwe_details.risk}")
                    lines.append(
                        f"  Рекомендация: {finding.cwe_details.recommendation}"
                    )

                lines.append("")

        return "\n".join(lines)

"""
Security Report Generator
Generates comprehensive security testing reports.

Author: Marc Arévalo
Version: 1.0
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .response_analyzer import VulnerabilityDetection, VulnerabilitySeverity

logger = logging.getLogger(__name__)


@dataclass
class SecurityReport:
    """Represents a security testing report."""

    vulnerabilities: List[VulnerabilityDetection] = field(default_factory=list)
    total_tests: int = 0
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    end_time: Optional[str] = None
    target_url: str = ""
    test_types: List[str] = field(default_factory=list)

    def add_vulnerability(self, vuln: VulnerabilityDetection) -> None:
        """Add vulnerability to report."""
        self.vulnerabilities.append(vuln)

    def get_vulnerabilities_by_severity(
        self, severity: VulnerabilitySeverity
    ) -> List[VulnerabilityDetection]:
        """Get vulnerabilities by severity level."""
        return [v for v in self.vulnerabilities if v.severity == severity]

    def get_vulnerability_count(self) -> int:
        """Get total number of vulnerabilities found."""
        return len(self.vulnerabilities)

    def get_severity_counts(self) -> Dict[str, int]:
        """Get count of vulnerabilities by severity."""
        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for vuln in self.vulnerabilities:
            counts[vuln.severity.value] += 1

        return counts

    def has_critical_vulnerabilities(self) -> bool:
        """Check if report contains critical vulnerabilities."""
        return any(
            v.severity == VulnerabilitySeverity.CRITICAL
            for v in self.vulnerabilities
        )

    def to_dict(self) -> Dict:
        """Convert report to dictionary."""
        return {
            "summary": {
                "target_url": self.target_url,
                "total_tests": self.total_tests,
                "total_vulnerabilities": self.get_vulnerability_count(),
                "severity_counts": self.get_severity_counts(),
                "test_types": self.test_types,
                "start_time": self.start_time,
                "end_time": self.end_time or datetime.now().isoformat(),
            },
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
        }


class SecurityReportGenerator:
    """
    Generates security testing reports in various formats.

    Supports:
    - JSON format
    - HTML format
    - Markdown format
    """

    @staticmethod
    def generate_json_report(report: SecurityReport, output_path: str) -> None:
        """
        Generate JSON format report.

        Args:
            report: Security report
            output_path: Output file path
        """
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)

        logger.info(f"Security report saved to {output_path}")

    @staticmethod
    def generate_markdown_report(
        report: SecurityReport, output_path: str
    ) -> None:
        """
        Generate Markdown format report.

        Args:
            report: Security report
            output_path: Output file path
        """
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        severity_counts = report.get_severity_counts()

        # Build markdown content
        md = f"""# Security Testing Report

**Target:** {report.target_url}
**Date:** {report.end_time or datetime.now().isoformat()}
**Total Tests:** {report.total_tests}
**Total Vulnerabilities:** {report.get_vulnerability_count()}

## Summary

| Severity | Count |
|----------|-------|
| Critical | {severity_counts['critical']} |
| High     | {severity_counts['high']} |
| Medium   | {severity_counts['medium']} |
| Low      | {severity_counts['low']} |
| Info     | {severity_counts['info']} |

## Vulnerabilities Found

"""

        if not report.vulnerabilities:
            md += "✅ No vulnerabilities detected.\n"
        else:
            for i, vuln in enumerate(report.vulnerabilities, 1):
                md += f"""### {i}. {vuln.vulnerability_type} ({vuln.severity.value.upper()})

**URL:** `{vuln.url}`
**Method:** `{vuln.method}`
**Status Code:** `{vuln.status_code}`

**Description:**
{vuln.description}

**Payload Used:**
```
{vuln.payload_used}
```

**Evidence:**
"""
                for evidence_item in vuln.evidence:
                    md += f"- {evidence_item}\n"

                md += f"""
**Remediation:**
{vuln.remediation}

---

"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md)

        logger.info(f"Markdown report saved to {output_path}")

    @staticmethod
    def generate_html_report(report: SecurityReport, output_path: str) -> None:
        """
        Generate HTML format report.

        Args:
            report: Security report
            output_path: Output file path
        """
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        severity_counts = report.get_severity_counts()

        # Build HTML content
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Testing Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #007bff;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #555;
            margin-top: 30px;
        }}
        .summary {{
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .summary-item {{
            margin: 10px 0;
        }}
        .severity-badge {{
            padding: 5px 10px;
            border-radius: 3px;
            color: white;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 12px;
        }}
        .severity-critical {{ background-color: #dc3545; }}
        .severity-high {{ background-color: #fd7e14; }}
        .severity-medium {{ background-color: #ffc107; color: black; }}
        .severity-low {{ background-color: #28a745; }}
        .severity-info {{ background-color: #17a2b8; }}
        .vulnerability {{
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 20px;
            margin: 20px 0;
            background-color: #fafafa;
        }}
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        .code-block {{
            background-color: #f4f4f4;
            border: 1px solid #ddd;
            border-radius: 3px;
            padding: 10px;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
            margin: 10px 0;
        }}
        .evidence-list {{
            list-style-type: disc;
            margin-left: 20px;
        }}
        .no-vulns {{
            text-align: center;
            padding: 40px;
            color: #28a745;
            font-size: 18px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Security Testing Report</h1>

        <div class="summary">
            <div class="summary-item"><strong>Target URL:</strong> {report.target_url}</div>
            <div class="summary-item"><strong>Date:</strong> {report.end_time or datetime.now().isoformat()}</div>
            <div class="summary-item"><strong>Total Tests:</strong> {report.total_tests}</div>
            <div class="summary-item"><strong>Total Vulnerabilities:</strong> {report.get_vulnerability_count()}</div>
        </div>

        <h2>Severity Distribution</h2>
        <div class="summary">
            <div class="summary-item">
                <span class="severity-badge severity-critical">Critical</span> {severity_counts['critical']}
            </div>
            <div class="summary-item">
                <span class="severity-badge severity-high">High</span> {severity_counts['high']}
            </div>
            <div class="summary-item">
                <span class="severity-badge severity-medium">Medium</span> {severity_counts['medium']}
            </div>
            <div class="summary-item">
                <span class="severity-badge severity-low">Low</span> {severity_counts['low']}
            </div>
            <div class="summary-item">
                <span class="severity-badge severity-info">Info</span> {severity_counts['info']}
            </div>
        </div>

        <h2>Vulnerabilities Detected</h2>
"""

        if not report.vulnerabilities:
            html += """
        <div class="no-vulns">
            ✅ No vulnerabilities detected.
        </div>
"""
        else:
            for i, vuln in enumerate(report.vulnerabilities, 1):
                html += f"""
        <div class="vulnerability">
            <div class="vuln-header">
                <h3>{i}. {vuln.vulnerability_type}</h3>
                <span class="severity-badge severity-{vuln.severity.value}">{vuln.severity.value}</span>
            </div>

            <p><strong>URL:</strong> <code>{vuln.url}</code></p>
            <p><strong>Method:</strong> <code>{vuln.method}</code></p>
            <p><strong>Status Code:</strong> <code>{vuln.status_code}</code></p>

            <p><strong>Description:</strong></p>
            <p>{vuln.description}</p>

            <p><strong>Payload Used:</strong></p>
            <div class="code-block">{vuln.payload_used}</div>

            <p><strong>Evidence:</strong></p>
            <ul class="evidence-list">
"""
                for evidence_item in vuln.evidence:
                    html += f"                <li>{evidence_item}</li>\n"

                html += f"""
            </ul>

            <p><strong>Remediation:</strong></p>
            <p>{vuln.remediation}</p>
        </div>
"""

        html += """
    </div>
</body>
</html>
"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        logger.info(f"HTML report saved to {output_path}")

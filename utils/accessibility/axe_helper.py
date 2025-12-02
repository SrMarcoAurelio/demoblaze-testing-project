"""
Axe Accessibility Helper - DemoBlaze Test Automation
Author: Marc Arévalo
Version: 1.0 - Phase 9

Helper class for WCAG 2.1 accessibility testing using axe-core.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from axe_selenium_python import Axe

logger = logging.getLogger(__name__)


class AxeHelper:
    """Helper class for accessibility testing with axe-core."""

    # WCAG 2.1 Levels
    LEVEL_A = ["wcag2a", "wcag21a"]
    LEVEL_AA = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]
    LEVEL_AAA = [
        "wcag2a",
        "wcag2aa",
        "wcag2aaa",
        "wcag21a",
        "wcag21aa",
        "wcag21aaa",
    ]

    # Common rule sets
    BEST_PRACTICE = ["best-practice"]
    EXPERIMENTAL = ["experimental"]

    def __init__(self, driver):
        """
        Initialize AxeHelper.

        Args:
            driver: Selenium WebDriver instance
        """
        self.driver = driver
        self.axe = Axe(driver)

    def inject_axe(self) -> None:
        """Inject axe-core script into page."""
        self.axe.inject()
        logger.debug("✓ Axe-core injected into page")

    def run_wcag_aa(self) -> Dict[str, Any]:
        """
        Run WCAG 2.1 Level AA accessibility scan.

        Returns:
            Axe results dictionary
        """
        self.inject_axe()
        results = self.axe.run(
            options={"runOnly": {"type": "tag", "values": self.LEVEL_AA}}
        )
        logger.info(
            f"A11y scan complete - Violations: {len(results.get('violations', []))}"
        )
        return results

    def run_wcag_a(self) -> Dict[str, Any]:
        """Run WCAG 2.1 Level A accessibility scan."""
        self.inject_axe()
        results = self.axe.run(
            options={"runOnly": {"type": "tag", "values": self.LEVEL_A}}
        )
        return results

    def run_full(self) -> Dict[str, Any]:
        """Run full accessibility scan (all rules)."""
        self.inject_axe()
        results = self.axe.run()
        return results

    def get_violations(
        self, results: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Get violations from results.

        Args:
            results: Axe results (if None, runs new scan)

        Returns:
            List of violations
        """
        if results is None:
            results = self.run_wcag_aa()
        return results.get("violations", [])

    def get_violation_count(
        self, results: Optional[Dict[str, Any]] = None
    ) -> int:
        """Get total number of violations."""
        violations = self.get_violations(results)
        return len(violations)

    def get_critical_violations(
        self, results: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Get critical and serious violations only."""
        violations = self.get_violations(results)
        return [
            v for v in violations if v.get("impact") in ["critical", "serious"]
        ]

    def assert_no_violations(
        self,
        results: Optional[Dict[str, Any]] = None,
        allow_minor: bool = False,
    ) -> None:
        """
        Assert no accessibility violations.

        Args:
            results: Axe results
            allow_minor: If True, allows minor/moderate violations

        Raises:
            AssertionError: If violations found
        """
        if results is None:
            results = self.run_wcag_aa()

        if allow_minor:
            violations = self.get_critical_violations(results)
            error_msg = "Critical/Serious accessibility violations found"
        else:
            violations = self.get_violations(results)
            error_msg = "Accessibility violations found"

        if violations:
            violation_summary = self.format_violations_summary(violations)
            raise AssertionError(f"{error_msg}:\n{violation_summary}")

    def format_violations_summary(
        self, violations: List[Dict[str, Any]]
    ) -> str:
        """Format violations into readable summary."""
        summary = []
        for v in violations:
            impact = v.get("impact", "unknown").upper()
            rule_id = v.get("id", "unknown")
            description = v.get("description", "No description")
            help_url = v.get("helpUrl", "")
            node_count = len(v.get("nodes", []))

            summary.append(f"  [{impact}] {rule_id}")
            summary.append(f"    Description: {description}")
            summary.append(f"    Affected elements: {node_count}")
            summary.append(f"    Help: {help_url}")
            summary.append("")

        return "\n".join(summary)

    def save_report(
        self,
        results: Dict[str, Any],
        filepath: str,
        include_passes: bool = False,
    ) -> None:
        """
        Save accessibility report to file.

        Args:
            results: Axe results
            filepath: Output file path
            include_passes: Include passed checks
        """
        report_data = {
            "url": results.get("url"),
            "timestamp": results.get("timestamp"),
            "violations": results.get("violations", []),
            "incomplete": results.get("incomplete", []),
        }

        if include_passes:
            report_data["passes"] = results.get("passes", [])

        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(filepath, "w") as f:
            json.dump(report_data, f, indent=2)

        logger.info(f"Accessibility report saved: {filepath}")

    def get_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get summary statistics from results.

        Returns:
            Summary dictionary with counts
        """
        violations = results.get("violations", [])

        summary = {
            "total_violations": len(violations),
            "critical": len(
                [v for v in violations if v.get("impact") == "critical"]
            ),
            "serious": len(
                [v for v in violations if v.get("impact") == "serious"]
            ),
            "moderate": len(
                [v for v in violations if v.get("impact") == "moderate"]
            ),
            "minor": len(
                [v for v in violations if v.get("impact") == "minor"]
            ),
            "incomplete": len(results.get("incomplete", [])),
            "passes": len(results.get("passes", [])),
        }

        return summary

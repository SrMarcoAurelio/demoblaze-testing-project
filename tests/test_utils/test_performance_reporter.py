"""
Performance Reporter Unit Tests
Author: Marc Arévalo
Version: 1.0

Unit tests for utils/performance/reporter.py
Tests HTML report generation from performance metrics.
"""

import json
import tempfile
from pathlib import Path

import pytest

from utils.performance.reporter import (
    _build_html,
    _get_css,
    generate_html_report,
)


@pytest.mark.unit
@pytest.mark.test_utils
@pytest.mark.performance
class TestHtmlReportGeneration:
    """Test HTML report generation"""

    def test_generate_html_report_creates_file_PERF_REP_001(self):
        """Test generate_html_report creates HTML file"""
        metrics_data = {
            "summary": {
                "total_metrics": 10,
                "violations": 0,
                "thresholds_defined": 5,
                "categories": ["navigation", "api"],
                "generated_at": "2025-12-05",
            },
            "violations": [],
            "categories": {},
            "statistics": {},
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "report.html"
            generate_html_report(metrics_data, str(output_path))

            assert output_path.exists(), "HTML report file should be created"
            assert (
                output_path.stat().st_size > 0
            ), "HTML report should not be empty"

    def test_generated_html_contains_metrics_data_PERF_REP_002(self):
        """Test generated HTML contains metrics data"""
        metrics_data = {
            "summary": {
                "total_metrics": 15,
                "violations": 0,
                "thresholds_defined": 3,
                "categories": ["navigation", "api"],
                "generated_at": "2025-12-05",
            },
            "violations": [],
            "categories": {},
            "statistics": {},
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "report.html"
            generate_html_report(metrics_data, str(output_path))

            content = output_path.read_text()
            assert "15" in content or "total_metrics" in content.lower()

    def test_generate_html_creates_parent_directories_PERF_REP_003(self):
        """Test generate_html_report creates parent directories if needed"""
        metrics_data = {
            "summary": {"total_metrics": 5, "violations": 0, "categories": []},
            "violations": [],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "nested" / "dir" / "report.html"
            generate_html_report(metrics_data, str(output_path))

            assert output_path.exists(), "Should create nested directories"
            assert output_path.parent.exists()


@pytest.mark.unit
@pytest.mark.test_utils
@pytest.mark.performance
class TestBuildHtml:
    """Test _build_html function"""

    def test_build_html_returns_valid_html_PERF_REP_004(self):
        """Test _build_html returns valid HTML structure"""
        metrics_data = {
            "summary": {
                "total_metrics": 10,
                "violations": 0,
                "categories": [],
            },
            "categories": {},
            "violations": [],
            "statistics": {},
        }

        html = _build_html(metrics_data)

        assert html.startswith("<!DOCTYPE html>")
        assert "<html" in html
        assert "</html>" in html
        assert "<head>" in html
        assert "<body>" in html

    def test_build_html_includes_css_PERF_REP_005(self):
        """Test _build_html includes CSS styles"""
        metrics_data = {
            "summary": {"total_metrics": 5, "violations": 0, "categories": []}
        }
        html = _build_html(metrics_data)

        assert "<style>" in html
        assert "</style>" in html
        assert "font-family" in html.lower() or ".container" in html

    def test_build_html_includes_title_PERF_REP_006(self):
        """Test _build_html includes title"""
        metrics_data = {
            "summary": {"total_metrics": 5, "violations": 0, "categories": []}
        }
        html = _build_html(metrics_data)

        assert "<title>" in html
        assert "Performance" in html or "Report" in html

    def test_build_html_with_violations_PERF_REP_007(self):
        """Test _build_html handles violations data"""
        metrics_data = {
            "summary": {
                "total_metrics": 10,
                "violations": 1,
                "categories": [],
            },
            "violations": [
                {"name": "slow_operation", "duration": 10.5, "threshold": 5.0}
            ],
            "categories": {},
            "statistics": {},
        }

        html = _build_html(metrics_data)
        # Should not raise exception with violations data
        assert isinstance(html, str)
        assert len(html) > 0


@pytest.mark.unit
@pytest.mark.test_utils
@pytest.mark.performance
class TestGetCss:
    """Test _get_css function"""

    def test_get_css_returns_string_PERF_REP_008(self):
        """Test _get_css returns CSS string"""
        css = _get_css()

        assert isinstance(css, str)
        assert len(css) > 0

    def test_get_css_contains_valid_css_PERF_REP_009(self):
        """Test _get_css contains valid CSS rules"""
        css = _get_css()

        # Check for common CSS patterns
        assert "{" in css and "}" in css
        assert ":" in css and ";" in css

    def test_get_css_contains_styling_rules_PERF_REP_010(self):
        """Test _get_css contains expected styling rules"""
        css = _get_css()

        # Check for common CSS properties
        common_properties = [
            "font-family",
            "color",
            "background",
            "padding",
            "margin",
        ]
        found_properties = sum(
            1 for prop in common_properties if prop in css.lower()
        )

        assert (
            found_properties >= 3
        ), f"Expected at least 3 CSS properties, found {found_properties}"

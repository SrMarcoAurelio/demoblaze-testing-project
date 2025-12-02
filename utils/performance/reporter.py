"""
Performance Reporter - DemoBlaze Test Automation
Author: Marc Arévalo
Version: 1.0 - Phase 7

Generate HTML performance reports from collected metrics.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


def generate_html_report(
    metrics_data: Dict[str, Any], output_path: str
) -> None:
    """
    Generate HTML performance report from metrics data.

    Args:
        metrics_data: Performance metrics dictionary
        output_path: Path to save HTML file
    """
    html_content = _build_html(metrics_data)

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w") as f:
        f.write(html_content)


def _build_html(data: Dict[str, Any]) -> str:
    """Build complete HTML document."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Performance Test Report - DemoBlaze</title>
    <style>
        {_get_css()}
    </style>
</head>
<body>
    <div class="container">
        {_build_header(data)}
        {_build_summary(data)}
        {_build_violations_section(data)}
        {_build_categories_section(data)}
        {_build_statistics_section(data)}
        {_build_thresholds_section(data)}
        {_build_footer()}
    </div>
</body>
</html>"""


def _get_css() -> str:
    """Return CSS styles for report."""
    return """
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }

        .section {
            background: white;
            padding: 30px;
            margin-bottom: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .section h2 {
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e0e0e0;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }

        .metric-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }

        .metric-card .value {
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }

        .metric-card .label {
            font-size: 0.9em;
            opacity: 0.9;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .status-pass {
            background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
        }

        .status-fail {
            background: linear-gradient(135deg, #eb3349 0%, #f45c43 100%);
        }

        .status-warning {
            background: linear-gradient(135deg, #f46b45 0%, #eea849 100%);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }

        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }

        th {
            background: #f8f9fa;
            font-weight: 600;
            color: #667eea;
        }

        tr:hover {
            background: #f8f9fa;
        }

        .violation {
            background: #fff5f5;
            border-left: 4px solid #e53e3e;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 4px;
        }

        .violation-title {
            font-weight: bold;
            color: #e53e3e;
            margin-bottom: 5px;
        }

        .no-violations {
            background: #f0fff4;
            border-left: 4px solid #38a169;
            padding: 15px;
            border-radius: 4px;
            color: #2f855a;
        }

        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }

        .stat-item {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            border-left: 4px solid #667eea;
        }

        .stat-name {
            font-weight: bold;
            color: #667eea;
            margin-bottom: 10px;
        }

        .stat-details {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 8px;
            font-size: 0.9em;
        }

        .stat-label {
            color: #666;
        }

        .stat-value {
            font-weight: 600;
            text-align: right;
        }

        .footer {
            text-align: center;
            color: #666;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #e0e0e0;
        }

        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
        }

        .badge-success {
            background: #c6f6d5;
            color: #2f855a;
        }

        .badge-danger {
            background: #fed7d7;
            color: #c53030;
        }
    """


def _build_header(data: Dict[str, Any]) -> str:
    """Build header section."""
    summary = data.get("summary", {})
    generated_at = summary.get("generated_at", "")

    return f"""
    <div class="header">
        <h1>⚡ Performance Test Report</h1>
        <p>DemoBlaze Test Automation Framework - Phase 7</p>
        <p>Generated: {generated_at}</p>
    </div>
    """


def _build_summary(data: Dict[str, Any]) -> str:
    """Build summary section with key metrics."""
    summary = data.get("summary", {})
    total_metrics = summary.get("total_metrics", 0)
    violations_count = summary.get("violations", 0)
    thresholds = summary.get("thresholds_defined", 0)
    categories = len(summary.get("categories", []))

    status_class = "status-pass" if violations_count == 0 else "status-fail"

    return f"""
    <div class="section">
        <h2>📊 Summary</h2>
        <div class="summary-grid">
            <div class="metric-card">
                <div class="label">Total Metrics</div>
                <div class="value">{total_metrics}</div>
            </div>
            <div class="metric-card">
                <div class="label">Categories</div>
                <div class="value">{categories}</div>
            </div>
            <div class="metric-card">
                <div class="label">Thresholds</div>
                <div class="value">{thresholds}</div>
            </div>
            <div class="metric-card {status_class}">
                <div class="label">Violations</div>
                <div class="value">{violations_count}</div>
            </div>
        </div>
    </div>
    """


def _build_violations_section(data: Dict[str, Any]) -> str:
    """Build violations section."""
    violations = data.get("violations", [])

    if not violations:
        return """
        <div class="section">
            <h2>✅ Performance Violations</h2>
            <div class="no-violations">
                🎉 Excellent! All performance metrics are within defined thresholds.
            </div>
        </div>
        """

    violations_html = ""
    for v in violations:
        metric = v.get("metric", {})
        name = metric.get("name", "Unknown")
        duration = metric.get("duration", 0)
        threshold = v.get("threshold", 0)
        exceeded = v.get("exceeded_by", 0)
        percentage = v.get("percentage_over", 0)

        violations_html += f"""
        <div class="violation">
            <div class="violation-title">⚠️ {name}</div>
            <div><strong>Actual:</strong> {duration:.3f}s |
                 <strong>Threshold:</strong> {threshold:.3f}s |
                 <strong>Exceeded by:</strong> {exceeded:.3f}s ({percentage:.1f}%)</div>
        </div>
        """

    return f"""
    <div class="section">
        <h2>⚠️ Performance Violations ({len(violations)})</h2>
        {violations_html}
    </div>
    """


def _build_categories_section(data: Dict[str, Any]) -> str:
    """Build categories section."""
    categories = data.get("categories", {})

    if not categories:
        return ""

    rows = ""
    for category, stats in categories.items():
        count = stats.get("count", 0)
        total = stats.get("total_duration", 0)
        avg = stats.get("avg_duration", 0)
        rows += f"""
        <tr>
            <td>{category}</td>
            <td>{count}</td>
            <td>{total:.3f}s</td>
            <td>{avg:.3f}s</td>
        </tr>
        """

    return f"""
    <div class="section">
        <h2>📁 Categories</h2>
        <table>
            <thead>
                <tr>
                    <th>Category</th>
                    <th>Count</th>
                    <th>Total Duration</th>
                    <th>Average Duration</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </div>
    """


def _build_statistics_section(data: Dict[str, Any]) -> str:
    """Build statistics section."""
    stats = data.get("statistics", {})

    if not stats:
        return ""

    stats_html = ""
    for name, values in stats.items():
        count = values.get("count", 0)
        min_val = values.get("min", 0)
        max_val = values.get("max", 0)
        mean_val = values.get("mean", 0)
        median_val = values.get("median", 0)
        stddev_val = values.get("stddev", 0)

        stats_html += f"""
        <div class="stat-item">
            <div class="stat-name">{name}</div>
            <div class="stat-details">
                <span class="stat-label">Count:</span>
                <span class="stat-value">{count}</span>
                <span class="stat-label">Min:</span>
                <span class="stat-value">{min_val:.3f}s</span>
                <span class="stat-label">Max:</span>
                <span class="stat-value">{max_val:.3f}s</span>
                <span class="stat-label">Mean:</span>
                <span class="stat-value">{mean_val:.3f}s</span>
                <span class="stat-label">Median:</span>
                <span class="stat-value">{median_val:.3f}s</span>
                <span class="stat-label">StdDev:</span>
                <span class="stat-value">{stddev_val:.3f}s</span>
            </div>
        </div>
        """

    return f"""
    <div class="section">
        <h2>📈 Statistics</h2>
        <div class="stat-grid">
            {stats_html}
        </div>
    </div>
    """


def _build_thresholds_section(data: Dict[str, Any]) -> str:
    """Build thresholds section."""
    thresholds = data.get("thresholds", {})

    if not thresholds:
        return ""

    rows = ""
    for name, threshold_data in thresholds.items():
        max_duration = threshold_data.get("max_duration", 0)
        category = threshold_data.get("category", "")
        description = threshold_data.get("description", "")

        rows += f"""
        <tr>
            <td>{name}</td>
            <td><span class="badge badge-success">{max_duration}s</span></td>
            <td>{category}</td>
            <td>{description}</td>
        </tr>
        """

    return f"""
    <div class="section">
        <h2>🎯 Performance Thresholds</h2>
        <table>
            <thead>
                <tr>
                    <th>Metric</th>
                    <th>Max Duration</th>
                    <th>Category</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </div>
    """


def _build_footer() -> str:
    """Build footer section."""
    return f"""
    <div class="footer">
        <p>DemoBlaze Test Automation Framework | Phase 7 - Performance Testing</p>
        <p>Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>
    """


def load_and_generate_report(json_path: str, html_output_path: str) -> None:
    """
    Load JSON metrics and generate HTML report.

    Args:
        json_path: Path to JSON metrics file
        html_output_path: Path to save HTML report
    """
    with open(json_path, "r") as f:
        data = json.load(f)

    generate_html_report(data, html_output_path)

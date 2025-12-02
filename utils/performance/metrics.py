"""
Performance Metrics - DemoBlaze Test Automation
Author: Marc Arévalo
Version: 1.0 - Phase 7

System for collecting, tracking, and reporting performance metrics.
"""

import json
import logging
import statistics
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class PerformanceMetric:
    """Single performance measurement."""

    name: str
    duration: float
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    category: str = "general"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class PerformanceThreshold:
    """Performance threshold definition."""

    name: str
    max_duration: float
    category: str = "general"
    description: str = ""

    def is_within_threshold(self, duration: float) -> bool:
        """Check if duration is within threshold."""
        return duration <= self.max_duration

    def get_threshold_status(self, duration: float) -> str:
        """Get status string for duration vs threshold."""
        if duration <= self.max_duration:
            return f"✓ PASS ({duration:.3f}s <= {self.max_duration}s)"
        else:
            exceeds_by = duration - self.max_duration
            percentage = (exceeds_by / self.max_duration) * 100
            return f"✗ FAIL ({duration:.3f}s > {self.max_duration}s by {exceeds_by:.3f}s / {percentage:.1f}%)"


class PerformanceMetricsCollector:
    """Collects and manages performance metrics."""

    # Default thresholds (can be overridden)
    DEFAULT_THRESHOLDS = {
        "page_load": PerformanceThreshold(
            "page_load",
            max_duration=5.0,
            category="navigation",
            description="Maximum time for page load",
        ),
        "login": PerformanceThreshold(
            "login",
            max_duration=3.0,
            category="authentication",
            description="Maximum time for login operation",
        ),
        "add_to_cart": PerformanceThreshold(
            "add_to_cart",
            max_duration=2.0,
            category="shopping",
            description="Maximum time to add product to cart",
        ),
        "checkout": PerformanceThreshold(
            "checkout",
            max_duration=5.0,
            category="shopping",
            description="Maximum time for checkout process",
        ),
        "search": PerformanceThreshold(
            "search",
            max_duration=2.0,
            category="search",
            description="Maximum time for search operation",
        ),
        "api_response": PerformanceThreshold(
            "api_response",
            max_duration=1.0,
            category="api",
            description="Maximum API response time",
        ),
    }

    def __init__(self):
        """Initialize metrics collector."""
        self.metrics: List[PerformanceMetric] = []
        self.thresholds: Dict[str, PerformanceThreshold] = (
            self.DEFAULT_THRESHOLDS.copy()
        )
        self._start_times: Dict[str, float] = {}

    def start_timer(self, name: str) -> None:
        """Start a named timer."""
        self._start_times[name] = time.time()
        logger.debug(f"⏱️  Started timer: {name}")

    def stop_timer(
        self,
        name: str,
        category: str = "general",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> float:
        """
        Stop a named timer and record metric.

        Returns:
            Duration in seconds
        """
        if name not in self._start_times:
            logger.warning(f"Timer '{name}' was never started")
            return 0.0

        duration = time.time() - self._start_times[name]
        del self._start_times[name]

        metric = PerformanceMetric(
            name=name,
            duration=duration,
            category=category,
            metadata=metadata or {},
        )
        self.metrics.append(metric)

        logger.debug(f"⏱️  Stopped timer: {name} - {duration:.3f}s")
        return duration

    def record_metric(
        self,
        name: str,
        duration: float,
        category: str = "general",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record a metric directly without timer."""
        metric = PerformanceMetric(
            name=name,
            duration=duration,
            category=category,
            metadata=metadata or {},
        )
        self.metrics.append(metric)
        logger.debug(f"📊 Recorded metric: {name} - {duration:.3f}s")

    def add_threshold(self, threshold: PerformanceThreshold) -> None:
        """Add or update a performance threshold."""
        self.thresholds[threshold.name] = threshold
        logger.debug(
            f"Added threshold: {threshold.name} <= {threshold.max_duration}s"
        )

    def get_metrics_by_category(
        self, category: str
    ) -> List[PerformanceMetric]:
        """Get all metrics for a specific category."""
        return [m for m in self.metrics if m.category == category]

    def get_metrics_by_name(self, name: str) -> List[PerformanceMetric]:
        """Get all metrics with a specific name."""
        return [m for m in self.metrics if m.name == name]

    def get_statistics(self, name: str) -> Dict[str, float]:
        """
        Get statistics for a metric name.

        Returns:
            Dict with min, max, mean, median, stddev
        """
        metrics = self.get_metrics_by_name(name)
        if not metrics:
            return {}

        durations = [m.duration for m in metrics]

        stats = {
            "count": len(durations),
            "min": min(durations),
            "max": max(durations),
            "mean": statistics.mean(durations),
            "median": statistics.median(durations),
        }

        if len(durations) > 1:
            stats["stddev"] = statistics.stdev(durations)
        else:
            stats["stddev"] = 0.0

        return stats

    def check_threshold(self, name: str, duration: float) -> bool:
        """
        Check if duration meets threshold.

        Returns:
            True if within threshold or no threshold defined
        """
        if name not in self.thresholds:
            logger.warning(f"No threshold defined for '{name}'")
            return True

        threshold = self.thresholds[name]
        is_ok = threshold.is_within_threshold(duration)

        status = threshold.get_threshold_status(duration)
        if is_ok:
            logger.info(f"Performance check: {name} - {status}")
        else:
            logger.warning(f"Performance check: {name} - {status}")

        return is_ok

    def get_threshold_violations(self) -> List[Dict[str, Any]]:
        """Get all metrics that violate their thresholds."""
        violations = []

        for metric in self.metrics:
            if metric.name in self.thresholds:
                threshold = self.thresholds[metric.name]
                if not threshold.is_within_threshold(metric.duration):
                    violations.append(
                        {
                            "metric": metric.to_dict(),
                            "threshold": threshold.max_duration,
                            "exceeded_by": metric.duration
                            - threshold.max_duration,
                            "percentage_over": (
                                (metric.duration - threshold.max_duration)
                                / threshold.max_duration
                            )
                            * 100,
                        }
                    )

        return violations

    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report."""
        categories = set(m.category for m in self.metrics)

        report = {
            "summary": {
                "total_metrics": len(self.metrics),
                "categories": list(categories),
                "thresholds_defined": len(self.thresholds),
                "violations": len(self.get_threshold_violations()),
                "generated_at": datetime.now().isoformat(),
            },
            "categories": {},
            "statistics": {},
            "violations": self.get_threshold_violations(),
            "thresholds": {
                name: {
                    "max_duration": t.max_duration,
                    "category": t.category,
                    "description": t.description,
                }
                for name, t in self.thresholds.items()
            },
        }

        # Category summaries
        for category in categories:
            cat_metrics = self.get_metrics_by_category(category)
            durations = [m.duration for m in cat_metrics]

            report["categories"][category] = {
                "count": len(cat_metrics),
                "total_duration": sum(durations),
                "avg_duration": (
                    statistics.mean(durations) if durations else 0.0
                ),
            }

        # Statistics by metric name
        metric_names = set(m.name for m in self.metrics)
        for name in metric_names:
            report["statistics"][name] = self.get_statistics(name)

        return report

    def save_report(self, filepath: str) -> None:
        """Save report to JSON file."""
        report = self.generate_report()
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)

        logger.info(f"Performance report saved to: {filepath}")

    def clear_metrics(self) -> None:
        """Clear all collected metrics."""
        self.metrics.clear()
        self._start_times.clear()
        logger.debug("Cleared all metrics")

    def __len__(self) -> int:
        """Return number of collected metrics."""
        return len(self.metrics)


# Global collector instance
_global_collector: Optional[PerformanceMetricsCollector] = None


def get_collector() -> PerformanceMetricsCollector:
    """Get or create global metrics collector."""
    global _global_collector
    if _global_collector is None:
        _global_collector = PerformanceMetricsCollector()
    return _global_collector


def reset_collector() -> None:
    """Reset global collector."""
    global _global_collector
    _global_collector = None

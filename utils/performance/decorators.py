"""
Performance Decorators - DemoBlaze Test Automation
Author: Marc Arévalo
Version: 1.0 - Phase 7

Decorators and context managers for performance measurement.
"""

import functools
import logging
import time
from contextlib import contextmanager
from typing import Any, Callable, Optional

from .metrics import get_collector

logger = logging.getLogger(__name__)


def measure_performance(
    name: Optional[str] = None,
    category: str = "general",
    check_threshold: bool = True,
):
    """
    Decorator to measure function performance.

    Args:
        name: Metric name (defaults to function name)
        category: Metric category
        check_threshold: Whether to check against thresholds

    Example:
        @measure_performance(category="navigation")
        def navigate_to_page():
            # ... navigation code
            pass
    """

    def decorator(func: Callable) -> Callable:
        metric_name = name or func.__name__

        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            collector = get_collector()
            start_time = time.time()

            try:
                result = func(*args, **kwargs)
                return result
            finally:
                duration = time.time() - start_time
                collector.record_metric(
                    name=metric_name,
                    duration=duration,
                    category=category,
                    metadata={"function": func.__name__},
                )

                if check_threshold:
                    collector.check_threshold(metric_name, duration)

                logger.debug(f"⏱️  {metric_name} completed in {duration:.3f}s")

        return wrapper

    return decorator


@contextmanager
def performance_timer(
    name: str, category: str = "general", check_threshold: bool = True
):
    """
    Context manager for measuring code block performance.

    Example:
        with performance_timer("page_load", category="navigation"):
            page.load()
            page.wait_for_ready()
    """
    collector = get_collector()
    start_time = time.time()

    logger.debug(f"⏱️  Started: {name}")

    try:
        yield
    finally:
        duration = time.time() - start_time
        collector.record_metric(
            name=name, duration=duration, category=category
        )

        if check_threshold:
            collector.check_threshold(name, duration)

        logger.debug(f"⏱️  {name} completed in {duration:.3f}s")


class PerformanceMonitor:
    """
    Class-based performance monitor for more complex scenarios.

    Example:
        monitor = PerformanceMonitor("checkout_flow")
        monitor.start()

        # ... do checkout steps

        monitor.checkpoint("form_filled")
        # ... more steps

        monitor.checkpoint("payment_processed")
        monitor.stop()
    """

    def __init__(self, name: str, category: str = "general"):
        """Initialize monitor."""
        self.name = name
        self.category = category
        self.collector = get_collector()
        self.start_time: Optional[float] = None
        self.checkpoints: list = []

    def start(self) -> None:
        """Start monitoring."""
        self.start_time = time.time()
        logger.debug(f"⏱️  Monitor started: {self.name}")

    def checkpoint(self, checkpoint_name: str) -> float:
        """
        Record a checkpoint time.

        Returns:
            Time since start in seconds
        """
        if self.start_time is None:
            raise RuntimeError("Monitor not started")

        elapsed = time.time() - self.start_time
        self.checkpoints.append((checkpoint_name, elapsed))

        logger.debug(
            f"⏱️  Checkpoint '{checkpoint_name}': {elapsed:.3f}s since start"
        )
        return elapsed

    def stop(self) -> float:
        """
        Stop monitoring and record final metric.

        Returns:
            Total duration in seconds
        """
        if self.start_time is None:
            raise RuntimeError("Monitor not started")

        duration = time.time() - self.start_time

        # Record overall metric
        self.collector.record_metric(
            name=self.name,
            duration=duration,
            category=self.category,
            metadata={
                "checkpoints": [
                    {"name": name, "elapsed": elapsed}
                    for name, elapsed in self.checkpoints
                ]
            },
        )

        logger.debug(
            f"⏱️  Monitor stopped: {self.name} - {duration:.3f}s total"
        )
        return duration

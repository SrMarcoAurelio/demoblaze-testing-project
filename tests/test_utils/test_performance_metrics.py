"""
Performance Metrics Unit Tests
Author: Marc Arévalo
Version: 1.0

Unit tests for utils/performance/metrics.py
Tests metric collection, thresholds, and statistics.
"""

import json
import time
from pathlib import Path

import pytest

from utils.performance.metrics import (
    PerformanceMetric,
    PerformanceMetricsCollector,
    PerformanceThreshold,
)


@pytest.mark.unit
@pytest.mark.test_utils
@pytest.mark.performance
class TestPerformanceMetric:
    """Test PerformanceMetric dataclass"""

    def test_create_metric_with_defaults_PERF_MTR_001(self):
        """Test creating metric with default values"""
        metric = PerformanceMetric(name="test_operation", duration=1.5)

        assert metric.name == "test_operation"
        assert metric.duration == 1.5
        assert metric.category == "general"
        assert isinstance(metric.metadata, dict)
        assert len(metric.timestamp) > 0

    def test_create_metric_with_custom_values_PERF_MTR_002(self):
        """Test creating metric with custom values"""
        metadata = {"browser": "chrome", "url": "test.com"}
        metric = PerformanceMetric(
            name="page_load",
            duration=2.5,
            category="navigation",
            metadata=metadata,
        )

        assert metric.name == "page_load"
        assert metric.duration == 2.5
        assert metric.category == "navigation"
        assert metric.metadata == metadata

    def test_metric_to_dict_PERF_MTR_003(self):
        """Test converting metric to dictionary"""
        metric = PerformanceMetric(name="test", duration=1.0)
        metric_dict = metric.to_dict()

        assert isinstance(metric_dict, dict)
        assert metric_dict["name"] == "test"
        assert metric_dict["duration"] == 1.0
        assert "timestamp" in metric_dict


@pytest.mark.unit
@pytest.mark.test_utils
@pytest.mark.performance
class TestPerformanceThreshold:
    """Test PerformanceThreshold dataclass"""

    def test_create_threshold_PERF_MTR_004(self):
        """Test creating performance threshold"""
        threshold = PerformanceThreshold(
            name="page_load",
            max_duration=5.0,
            category="navigation",
            description="Max page load time",
        )

        assert threshold.name == "page_load"
        assert threshold.max_duration == 5.0
        assert threshold.category == "navigation"

    def test_is_within_threshold_pass_PERF_MTR_005(self):
        """Test is_within_threshold returns True for passing duration"""
        threshold = PerformanceThreshold(name="test", max_duration=5.0)

        assert threshold.is_within_threshold(3.0) is True
        assert threshold.is_within_threshold(5.0) is True  # Equal is passing

    def test_is_within_threshold_fail_PERF_MTR_006(self):
        """Test is_within_threshold returns False for exceeding duration"""
        threshold = PerformanceThreshold(name="test", max_duration=5.0)

        assert threshold.is_within_threshold(6.0) is False
        assert threshold.is_within_threshold(10.0) is False

    def test_get_threshold_status_pass_PERF_MTR_007(self):
        """Test get_threshold_status for passing duration"""
        threshold = PerformanceThreshold(name="test", max_duration=5.0)
        status = threshold.get_threshold_status(3.5)

        assert "✓ PASS" in status
        assert "3.500s" in status
        assert "5.0s" in status

    def test_get_threshold_status_fail_PERF_MTR_008(self):
        """Test get_threshold_status for failing duration"""
        threshold = PerformanceThreshold(name="test", max_duration=5.0)
        status = threshold.get_threshold_status(7.5)

        assert "✗ FAIL" in status
        assert "7.500s" in status
        assert "5.0s" in status
        assert "2.500s" in status  # Exceeds by 2.5s


@pytest.mark.unit
@pytest.mark.test_utils
@pytest.mark.performance
class TestPerformanceMetricsCollector:
    """Test PerformanceMetricsCollector class"""

    def test_collector_initialization_PERF_MTR_009(self):
        """Test collector initializes with empty metrics"""
        collector = PerformanceMetricsCollector()

        assert len(collector.metrics) == 0
        assert len(collector.thresholds) > 0  # Has default thresholds

    def test_record_metric_PERF_MTR_010(self):
        """Test recording a metric"""
        collector = PerformanceMetricsCollector()
        collector.record_metric(name="test_op", duration=1.5, category="test")

        assert len(collector.metrics) == 1
        metric = collector.metrics[0]
        assert metric.name == "test_op"
        assert metric.duration == 1.5
        assert metric.category == "test"

    def test_get_metrics_by_category_PERF_MTR_011(self):
        """Test filtering metrics by category"""
        collector = PerformanceMetricsCollector()
        collector.record_metric("op1", 1.0, category="navigation")
        collector.record_metric("op2", 2.0, category="api")
        collector.record_metric("op3", 3.0, category="navigation")

        nav_metrics = collector.get_metrics_by_category("navigation")
        assert len(nav_metrics) == 2
        assert all(m.category == "navigation" for m in nav_metrics)

    def test_clear_metrics_PERF_MTR_012(self):
        """Test clearing all metrics"""
        collector = PerformanceMetricsCollector()
        collector.record_metric("op1", 1.0)
        collector.record_metric("op2", 2.0)
        assert len(collector.metrics) == 2

        collector.clear_metrics()
        assert len(collector.metrics) == 0

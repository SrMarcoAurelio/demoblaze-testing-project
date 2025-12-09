"""
Performance Decorators Unit Tests
Author: Marc Arévalo
Version: 1.0

Unit tests for utils/performance/decorators.py
Tests performance measurement decorators and context managers.
"""

import time

import pytest

from utils.performance.decorators import measure_performance, performance_timer
from utils.performance.metrics import get_collector


@pytest.mark.unit
@pytest.mark.test_utils
@pytest.mark.performance
class TestMeasurePerformanceDecorator:
    """Test @measure_performance decorator"""

    def test_decorator_measures_function_PERF_DEC_001(self):
        """Test decorator measures function execution time"""
        collector = get_collector()
        collector.clear_metrics()

        @measure_performance(category="test", check_threshold=False)
        def test_function():
            time.sleep(0.1)
            return "result"

        result = test_function()

        assert result == "result"
        assert len(collector.metrics) == 1
        assert collector.metrics[0].name == "test_function"
        assert collector.metrics[0].duration >= 0.1

    def test_decorator_with_custom_name_PERF_DEC_002(self):
        """Test decorator with custom metric name"""
        collector = get_collector()
        collector.clear_metrics()

        @measure_performance(
            name="custom_op", category="test", check_threshold=False
        )
        def my_function():
            return 42

        result = my_function()

        assert result == 42
        assert len(collector.metrics) == 1
        assert collector.metrics[0].name == "custom_op"

    def test_decorator_preserves_function_attributes_PERF_DEC_003(self):
        """Test decorator preserves original function attributes"""

        @measure_performance(check_threshold=False)
        def documented_function():
            """This is a test function."""
            return "test"

        assert documented_function.__name__ == "documented_function"
        assert documented_function.__doc__ == "This is a test function."

    def test_decorator_with_exceptions_PERF_DEC_004(self):
        """Test decorator still records metrics when function raises exception"""
        collector = get_collector()
        collector.clear_metrics()

        @measure_performance(category="test", check_threshold=False)
        def failing_function():
            time.sleep(0.05)
            raise ValueError("Test error")

        with pytest.raises(ValueError, match="Test error"):
            failing_function()

        # Metric should still be recorded
        assert len(collector.metrics) == 1
        assert collector.metrics[0].duration >= 0.05


@pytest.mark.unit
@pytest.mark.test_utils
@pytest.mark.performance
class TestPerformanceTimerContextManager:
    """Test performance_timer context manager"""

    def test_context_manager_measures_block_PERF_DEC_005(self):
        """Test context manager measures code block execution"""
        collector = get_collector()
        collector.clear_metrics()

        with performance_timer(
            "test_block", category="test", check_threshold=False
        ):
            time.sleep(0.1)

        assert len(collector.metrics) == 1
        assert collector.metrics[0].name == "test_block"
        assert collector.metrics[0].duration >= 0.1

    def test_context_manager_with_return_value_PERF_DEC_006(self):
        """Test context manager doesn't interfere with return values"""
        collector = get_collector()
        collector.clear_metrics()

        def function_with_context():
            with performance_timer("operation", check_threshold=False):
                time.sleep(0.05)
                return "success"

        result = function_with_context()
        assert result == "success"
        assert len(collector.metrics) == 1

    def test_context_manager_with_exception_PERF_DEC_007(self):
        """Test context manager records metrics even with exceptions"""
        collector = get_collector()
        collector.clear_metrics()

        with pytest.raises(ValueError, match="Test error"):
            with performance_timer("failing_block", check_threshold=False):
                time.sleep(0.05)
                raise ValueError("Test error")

        # Metric should still be recorded
        assert len(collector.metrics) == 1
        assert collector.metrics[0].duration >= 0.05

    def test_nested_performance_timers_PERF_DEC_008(self):
        """Test nested context managers record separately"""
        collector = get_collector()
        collector.clear_metrics()

        with performance_timer("outer", check_threshold=False):
            time.sleep(0.05)
            with performance_timer("inner", check_threshold=False):
                time.sleep(0.05)

        assert len(collector.metrics) == 2
        inner_metric = [m for m in collector.metrics if m.name == "inner"][0]
        outer_metric = [m for m in collector.metrics if m.name == "outer"][0]

        assert inner_metric.duration >= 0.05
        assert outer_metric.duration >= 0.1  # Includes inner duration

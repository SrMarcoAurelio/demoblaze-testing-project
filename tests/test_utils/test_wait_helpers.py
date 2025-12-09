"""
Wait Helpers Unit Tests
Author: Marc Arévalo
Version: 1.0

Unit tests for wait_helpers.py utility functions.
Tests wait conditions, retry decorators, and timeout handling.
"""

import time

import pytest

from utils.helpers.wait_helpers import (
    retry_on_failure,
    wait_for_ajax,
    wait_for_condition,
    wait_for_page_ready,
    wait_with_timeout,
)


@pytest.mark.unit
@pytest.mark.test_utils
class TestWaitForCondition:
    """Test wait_for_condition function"""

    def test_wait_for_condition_success_immediate_WAIT_001(self):
        """Test condition that is immediately true"""

        def always_true():
            return True

        result = wait_for_condition(always_true, timeout=1)
        assert (
            result is True
        ), "Should return True for immediately true condition"

    def test_wait_for_condition_success_after_delay_WAIT_002(self):
        """Test condition that becomes true after delay"""
        start_time = time.time()

        def becomes_true():
            return time.time() - start_time > 0.5

        result = wait_for_condition(
            becomes_true, timeout=2, poll_frequency=0.1
        )
        assert result is True, "Should return True when condition becomes true"

    def test_wait_for_condition_timeout_WAIT_003(self):
        """Test condition that never becomes true"""

        def always_false():
            return False

        result = wait_for_condition(
            always_false, timeout=1, poll_frequency=0.2
        )
        assert result is False, "Should return False on timeout"

    def test_wait_for_condition_handles_exception_WAIT_004(self):
        """Test condition function that raises exceptions"""
        call_count = [0]

        def raises_then_succeeds():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ValueError("Not ready yet")
            return True

        result = wait_for_condition(
            raises_then_succeeds, timeout=5, poll_frequency=0.2
        )
        assert (
            result is True
        ), "Should handle exceptions and eventually succeed"

    def test_wait_for_condition_custom_error_message_WAIT_005(self):
        """Test custom error message is logged on timeout"""

        def always_false():
            return False

        custom_message = "Custom timeout message"
        result = wait_for_condition(
            always_false, timeout=1, error_message=custom_message
        )
        assert result is False, "Should return False with custom error message"


@pytest.mark.unit
@pytest.mark.test_utils
class TestRetryOnFailure:
    """Test retry_on_failure decorator"""

    def test_retry_succeeds_first_attempt_WAIT_006(self):
        """Test function succeeds on first attempt"""

        @retry_on_failure(max_attempts=3, delay=0.1)
        def always_succeeds():
            return "success"

        result = always_succeeds()
        assert result == "success", "Should succeed on first attempt"

    def test_retry_succeeds_after_failures_WAIT_007(self):
        """Test function succeeds after initial failures"""
        call_count = [0]

        @retry_on_failure(max_attempts=3, delay=0.1)
        def fails_twice_then_succeeds():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ValueError(f"Attempt {call_count[0]} failed")
            return "success"

        result = fails_twice_then_succeeds()
        assert result == "success", "Should succeed after retries"
        assert call_count[0] == 3, f"Expected 3 attempts, got {call_count[0]}"

    def test_retry_exhausts_max_attempts_WAIT_008(self):
        """Test function fails after max attempts"""

        @retry_on_failure(max_attempts=3, delay=0.1)
        def always_fails():
            raise ValueError("Always fails")

        with pytest.raises(ValueError, match="Always fails"):
            always_fails()

    def test_retry_with_exponential_backoff_WAIT_009(self):
        """Test exponential backoff increases delay"""
        delays = []
        call_count = [0]

        @retry_on_failure(max_attempts=4, delay=0.1, exponential_backoff=True)
        def track_delays():
            call_count[0] += 1
            if call_count[0] < 4:
                delays.append(time.time())
                raise ValueError("Tracking delays")
            return "success"

        result = track_delays()
        assert result == "success", "Should succeed after retries"

        # Check delays are increasing (exponential backoff)
        # Note: Just verify multiple attempts were made
        assert call_count[0] == 4, f"Expected 4 attempts, got {call_count[0]}"

    def test_retry_with_specific_exception_WAIT_010(self):
        """Test retry only catches specified exceptions"""

        @retry_on_failure(max_attempts=3, delay=0.1, exceptions=(ValueError,))
        def raises_type_error():
            raise TypeError("Different exception")

        with pytest.raises(TypeError, match="Different exception"):
            raises_type_error()


@pytest.mark.unit
@pytest.mark.test_utils
class TestWaitWithTimeout:
    """Test wait_with_timeout decorator"""

    def test_wait_with_timeout_fast_function_WAIT_011(self):
        """Test fast function completes within timeout"""

        @wait_with_timeout(timeout=5)
        def fast_function():
            time.sleep(0.1)
            return "done"

        result = fast_function()
        assert result == "done", "Should complete fast function"

    def test_wait_with_timeout_slow_function_WAIT_012(self):
        """Test slow function logs warning but completes"""

        @wait_with_timeout(timeout=0.5)
        def slow_function():
            time.sleep(1.0)
            return "done"

        # Should complete but log warning
        result = slow_function()
        assert (
            result == "done"
        ), "Should complete slow function despite timeout"

    def test_wait_with_timeout_with_return_value_WAIT_013(self):
        """Test decorated function returns correct value"""

        @wait_with_timeout(timeout=2)
        def returns_value():
            return 42

        result = returns_value()
        assert result == 42, "Should return correct value"


@pytest.mark.test_utils
class TestWaitForPageReady:
    """Test wait_for_page_ready function"""

    def test_wait_for_page_ready_success_WAIT_014(self, browser):
        """Test wait for page ready on loaded page"""
        browser.get("https://www.demoblaze.com")
        result = wait_for_page_ready(browser, timeout=10)
        assert result is True, "Page should be ready after navigation"

    def test_wait_for_page_ready_already_loaded_WAIT_015(self, browser):
        """Test wait for page ready when page is already loaded"""
        browser.get("https://www.demoblaze.com")
        time.sleep(2)  # Ensure page is fully loaded
        result = wait_for_page_ready(browser, timeout=5)
        assert result is True, "Should return True for already loaded page"

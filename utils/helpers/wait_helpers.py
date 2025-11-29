"""
Wait Helpers - Universal Test Automation Framework
Author: Marc Arévalo
Version: 1.0

Helper functions for waiting and retrying operations.
Universal and reusable across any web application.
"""

import time
import logging
from typing import Callable, Any
from functools import wraps

logger = logging.getLogger(__name__)


def wait_for_condition(
    condition_func: Callable[[], bool],
    timeout: float = 10,
    poll_frequency: float = 0.5,
    error_message: str = "Condition not met within timeout"
) -> bool:
    """
    Wait for a condition to become true.

    Args:
        condition_func: Function that returns True when condition is met
        timeout: Maximum time to wait in seconds (default: 10)
        poll_frequency: How often to check condition in seconds (default: 0.5)
        error_message: Message to log if timeout occurs

    Returns:
        True if condition met, False if timeout

    Example:
        >>> def is_element_visible():
        ...     return driver.find_element(By.ID, "btn").is_displayed()
        >>> wait_for_condition(is_element_visible, timeout=5)
        True
    """
    end_time = time.time() + timeout
    while time.time() < end_time:
        try:
            if condition_func():
                return True
        except Exception as e:
            logger.debug(f"Condition check raised exception: {e}")
        time.sleep(poll_frequency)

    logger.error(error_message)
    return False


def retry_on_failure(
    max_attempts: int = 3,
    delay: float = 1.0,
    exponential_backoff: bool = False,
    exceptions: tuple = (Exception,)
):
    """
    Decorator to retry a function on failure.

    Args:
        max_attempts: Maximum number of attempts (default: 3)
        delay: Delay between attempts in seconds (default: 1.0)
        exponential_backoff: Use exponential backoff for delays (default: False)
        exceptions: Tuple of exceptions to catch (default: all exceptions)

    Returns:
        Decorated function with retry logic

    Example:
        >>> @retry_on_failure(max_attempts=3, delay=2.0)
        ... def click_flaky_button():
        ...     driver.find_element(By.ID, "btn").click()
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            current_delay = delay
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    if attempt == max_attempts:
                        logger.error(f"{func.__name__} failed after {max_attempts} attempts")
                        raise
                    logger.warning(
                        f"{func.__name__} attempt {attempt}/{max_attempts} failed: {e}. "
                        f"Retrying in {current_delay}s..."
                    )
                    time.sleep(current_delay)
                    if exponential_backoff:
                        current_delay *= 2
        return wrapper
    return decorator


def wait_with_timeout(timeout: float = 30):
    """
    Decorator to add timeout to a function.

    Args:
        timeout: Maximum execution time in seconds (default: 30)

    Returns:
        Decorated function with timeout

    Note:
        This is a simple implementation. For more complex scenarios,
        consider using threading or multiprocessing with proper timeouts.

    Example:
        >>> @wait_with_timeout(timeout=10)
        ... def slow_operation():
        ...     time.sleep(5)
        ...     return "Done"
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            start_time = time.time()
            result = func(*args, **kwargs)
            elapsed = time.time() - start_time
            if elapsed > timeout:
                logger.warning(
                    f"{func.__name__} took {elapsed:.2f}s (timeout: {timeout}s)"
                )
            return result
        return wrapper
    return decorator


def wait_for_page_ready(driver, timeout: float = 30) -> bool:
    """
    Wait for page to be fully loaded (document.readyState === 'complete').

    Args:
        driver: Selenium WebDriver instance
        timeout: Maximum time to wait in seconds (default: 30)

    Returns:
        True if page is ready, False if timeout

    Example:
        >>> wait_for_page_ready(driver, timeout=10)
        True
    """
    def page_is_ready():
        return driver.execute_script('return document.readyState') == 'complete'

    return wait_for_condition(
        page_is_ready,
        timeout=timeout,
        error_message="Page did not load within timeout"
    )


def wait_for_ajax(driver, timeout: float = 10) -> bool:
    """
    Wait for all AJAX requests to complete (jQuery).

    Note: Only works if jQuery is present on the page.

    Args:
        driver: Selenium WebDriver instance
        timeout: Maximum time to wait in seconds (default: 10)

    Returns:
        True if AJAX complete, False if timeout or no jQuery

    Example:
        >>> wait_for_ajax(driver, timeout=5)
        True
    """
    def ajax_is_complete():
        try:
            jquery_active = driver.execute_script('return jQuery.active == 0')
            return jquery_active
        except Exception:
            return True

    return wait_for_condition(
        ajax_is_complete,
        timeout=timeout,
        error_message="AJAX requests did not complete within timeout"
    )

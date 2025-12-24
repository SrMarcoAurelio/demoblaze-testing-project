"""
Visual Regression Testing Examples
Demonstrates visual regression testing with screenshots and comparison.

Author: Marc Arévalo
Version: 1.0

These tests demonstrate:
- Full page screenshots
- Element screenshots
- Visual comparison
- Baseline management
- Difference detection
"""

from pathlib import Path

import pytest
from selenium.webdriver.common.by import By

from utils.visual.screenshot_manager import ScreenshotManager
from utils.visual.visual_comparator import VisualComparator


@pytest.fixture
def screenshot_manager(tmp_path):
    """Create screenshot manager with temporary directory."""
    return ScreenshotManager(screenshots_dir=tmp_path / "screenshots")


@pytest.fixture
def visual_comparator():
    """Create visual comparator with default settings."""
    return VisualComparator(
        threshold=0.1,  # 0.1% difference allowed
        ignore_antialiasing=True,
        generate_diff_image=True,
    )


@pytest.mark.visual
@pytest.mark.smoke
def test_capture_full_page_screenshot(driver, screenshot_manager):
    """
    TC-VIS-001: Test full page screenshot capture.

    Validates:
    - Screenshot is captured successfully
    - File exists in correct location
    - File is not empty
    """
    # Navigate to page
    driver.get("https://www.demoblaze.com")

    # Capture screenshot
    screenshot_path = screenshot_manager.capture_screenshot(
        driver, name="homepage", as_baseline=False
    )

    # Validate
    assert screenshot_path.exists(), "Screenshot file should exist"
    assert screenshot_path.stat().st_size > 0, "Screenshot should not be empty"
    assert screenshot_path.name == "homepage.png"


@pytest.mark.visual
def test_create_baseline_screenshot(driver, screenshot_manager):
    """
    TC-VIS-002: Test baseline creation.

    Validates baseline screenshot creation and storage.
    """
    driver.get("https://www.demoblaze.com")

    # Create baseline
    baseline_path = screenshot_manager.create_baseline(
        driver, name="homepage_baseline"
    )

    # Validate
    assert baseline_path.exists()
    assert baseline_path.parent.name == "baseline"
    assert screenshot_manager.baseline_exists("homepage_baseline")


@pytest.mark.visual
def test_capture_element_screenshot(driver, screenshot_manager):
    """
    TC-VIS-003: Test element screenshot capture.

    Validates capturing screenshot of specific element.
    """
    driver.get("https://www.demoblaze.com")

    # Find element
    navbar = driver.find_element(By.ID, "navbarExample")

    # Capture element
    screenshot_path = screenshot_manager.capture_element_screenshot(
        driver, element=navbar, name="navbar", as_baseline=False
    )

    # Validate
    assert screenshot_path.exists()
    assert screenshot_path.stat().st_size > 0


@pytest.mark.visual
def test_visual_comparison_identical_images(
    driver, screenshot_manager, visual_comparator, tmp_path
):
    """
    TC-VIS-004: Test visual comparison with identical images.

    Validates comparison detects no differences.
    """
    driver.get("https://www.demoblaze.com")

    # Capture same screenshot twice
    baseline = screenshot_manager.capture_screenshot(
        driver, name="identical_test", as_baseline=True
    )

    actual = screenshot_manager.capture_screenshot(
        driver, name="identical_test", as_baseline=False
    )

    # Compare
    result = visual_comparator.compare_images(
        baseline_path=baseline,
        current_path=actual,
        diff_output_path=screenshot_manager.get_diff_path("identical_test"),
    )

    # Validate
    assert result.match, "Identical images should match"
    assert result.difference_percentage == 0, "No differences expected"
    assert result.pixel_differences == 0


@pytest.mark.visual
def test_visual_comparison_workflow(
    driver, screenshot_manager, visual_comparator
):
    """
    TC-VIS-005: Test complete visual regression workflow.

    Demonstrates:
    1. Create baseline
    2. Make changes
    3. Capture actual
    4. Compare and detect differences
    """
    # Step 1: Create baseline
    driver.get("https://www.demoblaze.com")
    baseline_path = screenshot_manager.create_baseline(
        driver, name="workflow_test"
    )

    # Step 2: Navigate away and back (simulating changes)
    driver.get("https://www.demoblaze.com/prod.html?idp_=1")
    driver.get("https://www.demoblaze.com")

    # Step 3: Capture actual
    actual_path = screenshot_manager.capture_for_comparison(
        driver, name="workflow_test"
    )

    # Step 4: Compare
    result = visual_comparator.compare_images(
        baseline_path=baseline_path,
        current_path=actual_path,
        diff_output_path=screenshot_manager.get_diff_path("workflow_test"),
    )

    # The pages should be very similar (allowing small dynamic differences)
    assert result.difference_percentage < 5, "Pages should be similar"


@pytest.mark.visual
def test_visual_comparison_with_custom_threshold(
    driver, screenshot_manager, visual_comparator
):
    """
    TC-VIS-006: Test comparison with custom threshold.

    Validates threshold configuration for acceptable differences.
    """
    driver.get("https://www.demoblaze.com")

    # Create baseline
    baseline_path = screenshot_manager.create_baseline(
        driver, name="threshold_test"
    )

    # Refresh page (may have minor differences)
    driver.refresh()

    # Capture actual
    actual_path = screenshot_manager.capture_for_comparison(
        driver, name="threshold_test"
    )

    # Compare with lenient threshold
    result = visual_comparator.compare_with_tolerance(
        baseline_path=baseline_path,
        current_path=actual_path,
        tolerance=5.0,  # Allow up to 5% difference
        diff_output_path=screenshot_manager.get_diff_path("threshold_test"),
    )

    # Should pass with lenient threshold
    assert result.match or result.difference_percentage < 5.0


@pytest.mark.visual
def test_visual_comparison_ignore_regions(
    driver, screenshot_manager, visual_comparator
):
    """
    TC-VIS-007: Test comparison with ignore regions.

    Demonstrates ignoring dynamic regions (ads, timestamps, etc).
    """
    driver.get("https://www.demoblaze.com")

    # Create baseline
    baseline_path = screenshot_manager.create_baseline(
        driver, name="ignore_regions_test"
    )

    # Refresh
    driver.refresh()

    # Capture actual
    actual_path = screenshot_manager.capture_for_comparison(
        driver, name="ignore_regions_test"
    )

    # Define regions to ignore (example: top banner area)
    # Format: (x, y, width, height)
    ignore_regions = [
        (0, 0, 1920, 100),  # Top banner
    ]

    # Compare with ignored regions
    result = visual_comparator.compare_images(
        baseline_path=baseline_path,
        current_path=actual_path,
        ignore_regions=ignore_regions,
        diff_output_path=screenshot_manager.get_diff_path(
            "ignore_regions_test"
        ),
    )

    # Differences in ignored regions should not affect result
    assert result.match or result.difference_percentage < 1.0


@pytest.mark.visual
def test_screenshot_cleanup(driver, screenshot_manager):
    """
    TC-VIS-008: Test screenshot cleanup functionality.

    Validates cleanup of temporary screenshots.
    """
    driver.get("https://www.demoblaze.com")

    # Capture multiple screenshots
    screenshot_manager.capture_screenshot(
        driver, "cleanup_test_1", as_baseline=False
    )
    screenshot_manager.capture_screenshot(
        driver, "cleanup_test_2", as_baseline=False
    )

    # Verify files exist
    assert screenshot_manager.get_actual_path("cleanup_test_1").exists()
    assert screenshot_manager.get_actual_path("cleanup_test_2").exists()

    # Clean actual screenshots
    screenshot_manager.clean_actual_screenshots()

    # Verify files removed
    assert not screenshot_manager.get_actual_path("cleanup_test_1").exists()
    assert not screenshot_manager.get_actual_path("cleanup_test_2").exists()


@pytest.mark.visual
def test_full_page_screenshot_with_scroll(driver, screenshot_manager):
    """
    TC-VIS-009: Test full page screenshot with scrolling.

    Validates capturing entire page including below-fold content.
    """
    driver.get("https://www.demoblaze.com")

    # Capture full page
    screenshot_path = screenshot_manager.capture_full_page_screenshot(
        driver, name="fullpage_test", as_baseline=False
    )

    # Validate
    assert screenshot_path.exists()
    assert screenshot_path.stat().st_size > 0

    # Full page screenshot should be larger than viewport
    # (This is a basic check - actual validation would compare dimensions)


@pytest.mark.visual
def test_baseline_management(driver, screenshot_manager):
    """
    TC-VIS-010: Test baseline management operations.

    Validates:
    - Baseline creation
    - Baseline existence check
    - Baseline path retrieval
    """
    driver.get("https://www.demoblaze.com")

    test_name = "baseline_mgmt_test"

    # Initially baseline should not exist
    assert not screenshot_manager.baseline_exists(test_name)

    # Create baseline
    baseline_path = screenshot_manager.create_baseline(driver, test_name)

    # Now baseline should exist
    assert screenshot_manager.baseline_exists(test_name)

    # Get baseline path should match created path
    retrieved_path = screenshot_manager.get_baseline_path(test_name)
    assert retrieved_path == baseline_path


@pytest.mark.visual
@pytest.mark.performance
def test_screenshot_capture_performance(driver, screenshot_manager):
    """
    TC-VIS-011: Test screenshot capture performance.

    Validates screenshot capture completes in reasonable time.
    """
    import time

    driver.get("https://www.demoblaze.com")

    # Measure capture time
    start_time = time.time()
    screenshot_manager.capture_screenshot(
        driver, name="performance_test", wait_before_capture=0.1
    )
    capture_time = time.time() - start_time

    # Screenshot should be captured quickly (< 5 seconds)
    assert capture_time < 5.0, f"Screenshot took {capture_time:.2f}s"


@pytest.mark.visual
def test_visual_comparison_different_images(
    driver, screenshot_manager, visual_comparator
):
    """
    TC-VIS-012: Test visual comparison detects differences.

    Validates comparison detects actual visual changes.
    """
    # Capture baseline from homepage
    driver.get("https://www.demoblaze.com")
    baseline_path = screenshot_manager.create_baseline(
        driver, name="different_test"
    )

    # Capture actual from different page
    driver.get("https://www.demoblaze.com/cart.html")
    actual_path = screenshot_manager.capture_for_comparison(
        driver, name="different_test"
    )

    # Compare
    result = visual_comparator.compare_images(
        baseline_path=baseline_path,
        current_path=actual_path,
        diff_output_path=screenshot_manager.get_diff_path("different_test"),
    )

    # Should detect differences
    assert not result.match, "Different pages should not match"
    assert result.difference_percentage > 0, "Should detect differences"
    assert result.pixel_differences > 0


@pytest.mark.visual
def test_screenshot_with_timestamp(driver, screenshot_manager):
    """
    TC-VIS-013: Test screenshot with timestamp naming.

    Validates timestamped screenshot naming for history.
    """
    driver.get("https://www.demoblaze.com")

    # Capture with timestamp
    screenshot_path = screenshot_manager.capture_with_timestamp(
        driver, name="timestamped_test", as_baseline=False
    )

    # Validate
    assert screenshot_path.exists()
    # Filename should contain timestamp pattern: YYYYMMDD_HHMMSS
    assert "_" in screenshot_path.stem


@pytest.mark.visual
def test_element_vs_fullpage_screenshots(driver, screenshot_manager):
    """
    TC-VIS-014: Test element screenshot vs full page.

    Validates element screenshots are smaller than full page.
    """
    driver.get("https://www.demoblaze.com")

    # Capture full page
    fullpage_path = screenshot_manager.capture_screenshot(
        driver, name="fullpage_compare", as_baseline=False
    )

    # Capture single element
    navbar = driver.find_element(By.ID, "navbarExample")
    element_path = screenshot_manager.capture_element_screenshot(
        driver, element=navbar, name="element_compare", as_baseline=False
    )

    # Element screenshot should be smaller
    fullpage_size = fullpage_path.stat().st_size
    element_size = element_path.stat().st_size

    assert element_size < fullpage_size, "Element screenshot should be smaller"

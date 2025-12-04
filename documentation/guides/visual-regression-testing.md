# Visual Regression Testing Guide

Complete guide for visual regression testing to detect unintended UI changes.

## Overview

The Visual Regression Testing Module provides professional tools for detecting visual changes:

- **ScreenshotManager** - Screenshot capture and organization
- **VisualComparator** - Image comparison and diff generation
- **Baseline Management** - Baseline creation and versioning
- **Diff Visualization** - Visual highlighting of differences

## Quick Start

```python
from utils.visual.screenshot_manager import ScreenshotManager
from utils.visual.visual_comparator import VisualComparator

# Create managers
screenshot_mgr = ScreenshotManager()
comparator = VisualComparator(threshold=0.1)

# Create baseline
baseline_path = screenshot_mgr.create_baseline(driver, "homepage")

# Later: capture and compare
actual_path = screenshot_mgr.capture_for_comparison(driver, "homepage")
result = comparator.compare_images(baseline_path, actual_path)

assert result.match, f"Visual regression detected: {result.difference_percentage}%"
```

## Why Visual Regression Testing?

Visual regression testing catches:
- **Layout Changes** - Broken CSS, responsive issues
- **Style Changes** - Color, font, spacing changes
- **Content Changes** - Missing elements, text changes
- **Cross-browser Issues** - Browser-specific rendering
- **Responsive Issues** - Mobile/tablet layout problems

## ScreenshotManager

### Basic Usage

```python
from utils.visual.screenshot_manager import ScreenshotManager

# Initialize
screenshot_mgr = ScreenshotManager(
    screenshots_dir="screenshots",
    baseline_dir="baseline",
    actual_dir="actual",
    diff_dir="diff"
)

# Capture screenshot
driver.get("https://www.example.com")
screenshot_path = screenshot_mgr.capture_screenshot(
    driver,
    name="homepage",
    as_baseline=False
)
```

### Directory Structure

```
screenshots/
├── baseline/       # Expected screenshots
│   ├── homepage.png
│   └── login.png
├── actual/         # Current test screenshots
│   ├── homepage.png
│   └── login.png
└── diff/           # Difference visualizations
    ├── homepage_diff.png
    └── login_diff.png
```

### Screenshot Types

#### Full Page Screenshot

```python
# Standard viewport screenshot
screenshot_mgr.capture_screenshot(driver, "homepage")

# Full page with scrolling
screenshot_mgr.capture_full_page_screenshot(driver, "long_page")
```

#### Element Screenshot

```python
# Capture specific element only
element = driver.find_element(By.ID, "navbar")
screenshot_mgr.capture_element_screenshot(
    driver,
    element=element,
    name="navbar"
)
```

#### Timestamped Screenshot

```python
# Include timestamp in filename
screenshot_mgr.capture_with_timestamp(
    driver,
    name="debug_screenshot"
)
# Creates: debug_screenshot_20231204_143022.png
```

### Baseline Management

```python
# Create baseline
baseline_path = screenshot_mgr.create_baseline(driver, "homepage")

# Check if baseline exists
if screenshot_mgr.baseline_exists("homepage"):
    print("Baseline found")

# Get baseline path
baseline_path = screenshot_mgr.get_baseline_path("homepage")
```

### Cleanup

```python
# Clean actual screenshots (after test run)
screenshot_mgr.clean_actual_screenshots()

# Clean diff images
screenshot_mgr.clean_diff_screenshots()

# Clean everything
screenshot_mgr.clean_all_screenshots()
```

## VisualComparator

### Basic Comparison

```python
from utils.visual.visual_comparator import VisualComparator

comparator = VisualComparator(
    threshold=0.1,              # 0.1% difference allowed
    ignore_antialiasing=True,   # Reduce false positives
    generate_diff_image=True    # Create visual diff
)

result = comparator.compare_images(
    baseline_path=baseline_path,
    current_path=actual_path,
    diff_output_path=diff_path
)

if result.match:
    print("✓ Images match")
else:
    print(f"✗ Difference: {result.difference_percentage:.2f}%")
```

### ComparisonResult

```python
result = comparator.compare_images(baseline, actual)

# Check match
assert result.match

# Get difference metrics
print(f"Difference: {result.difference_percentage}%")
print(f"Different pixels: {result.pixel_differences}")
print(f"Total pixels: {result.total_pixels}")

# Get diff image path
if result.diff_image_path:
    print(f"Diff saved: {result.diff_image_path}")
```

### Custom Threshold

```python
# Different threshold for specific comparison
result = comparator.compare_with_tolerance(
    baseline_path=baseline,
    current_path=actual,
    tolerance=5.0  # Allow 5% difference
)
```

### Ignore Regions

```python
# Ignore dynamic regions (ads, timestamps, etc)
ignore_regions = [
    (0, 0, 1920, 100),      # Top banner
    (1600, 0, 320, 600),    # Right sidebar ads
    (0, 900, 1920, 50)      # Footer with timestamp
]

result = comparator.compare_images(
    baseline_path=baseline,
    current_path=actual,
    ignore_regions=ignore_regions
)
```

## Complete Test Example

```python
import pytest
from utils.visual.screenshot_manager import ScreenshotManager
from utils.visual.visual_comparator import VisualComparator

@pytest.fixture(scope="module")
def screenshot_manager():
    return ScreenshotManager()

@pytest.fixture(scope="module")
def visual_comparator():
    return VisualComparator(threshold=0.1)

@pytest.mark.visual
def test_homepage_visual_regression(driver, screenshot_manager, visual_comparator):
    """Test homepage has no visual regressions."""
    test_name = "homepage"

    # Navigate to page
    driver.get("https://www.example.com")

    # Create baseline if doesn't exist
    if not screenshot_manager.baseline_exists(test_name):
        screenshot_manager.create_baseline(driver, test_name)
        pytest.skip("Baseline created, run test again")

    # Capture actual
    actual_path = screenshot_manager.capture_for_comparison(driver, test_name)
    baseline_path = screenshot_manager.get_baseline_path(test_name)

    # Compare
    result = visual_comparator.compare_images(
        baseline_path=baseline_path,
        current_path=actual_path,
        diff_output_path=screenshot_manager.get_diff_path(test_name)
    )

    # Assert
    assert result.match, (
        f"Visual regression detected: {result.difference_percentage:.2f}% "
        f"difference (threshold: {visual_comparator.threshold}%)"
    )
```

## Advanced Patterns

### Page Object Integration

```python
class HomePage(BasePage):
    def capture_screenshot(self, name: str, screenshot_manager):
        """Capture homepage screenshot."""
        return screenshot_manager.capture_screenshot(
            self.driver,
            name=name,
            wait_before_capture=1.0  # Wait for animations
        )

    def verify_visual_consistency(self, name: str, screenshot_manager, comparator):
        """Verify page matches baseline."""
        if not screenshot_manager.baseline_exists(name):
            screenshot_manager.create_baseline(self.driver, name)
            return True

        actual = screenshot_manager.capture_for_comparison(self.driver, name)
        baseline = screenshot_manager.get_baseline_path(name)

        result = comparator.compare_images(baseline, actual)
        return result.match
```

### Responsive Testing

```python
@pytest.mark.parametrize("viewport", [
    (1920, 1080),  # Desktop
    (768, 1024),   # Tablet
    (375, 667)     # Mobile
])
def test_responsive_visual(driver, viewport, screenshot_manager, visual_comparator):
    """Test visual consistency across viewports."""
    width, height = viewport
    test_name = f"homepage_{width}x{height}"

    # Set viewport
    driver.set_window_size(width, height)

    # Navigate
    driver.get("https://www.example.com")

    # Visual regression check
    if not screenshot_manager.baseline_exists(test_name):
        screenshot_manager.create_baseline(driver, test_name)
        pytest.skip("Baseline created")

    actual = screenshot_manager.capture_for_comparison(driver, test_name)
    baseline = screenshot_manager.get_baseline_path(test_name)

    result = visual_comparator.compare_images(baseline, actual)
    assert result.match
```

### Multi-page Visual Suite

```python
PAGES_TO_TEST = [
    ("homepage", "https://www.example.com"),
    ("login", "https://www.example.com/login"),
    ("products", "https://www.example.com/products"),
    ("cart", "https://www.example.com/cart"),
]

@pytest.mark.parametrize("name,url", PAGES_TO_TEST)
def test_page_visual_regression(
    driver, name, url, screenshot_manager, visual_comparator
):
    """Test all pages for visual regressions."""
    driver.get(url)

    if not screenshot_manager.baseline_exists(name):
        screenshot_manager.create_baseline(driver, name)
        pytest.skip("Baseline created")

    actual = screenshot_manager.capture_for_comparison(driver, name)
    baseline = screenshot_manager.get_baseline_path(name)

    result = visual_comparator.compare_images(baseline, actual)
    assert result.match, f"{name}: {result.difference_percentage}% difference"
```

## Best Practices

### 1. Baseline Management

```python
# Store baselines in version control
screenshots/
└── baseline/
    ├── homepage.png
    └── login.png

# Add to .gitignore:
screenshots/actual/
screenshots/diff/
```

### 2. Wait for Rendering

```python
# Wait for animations, lazy loading
screenshot_mgr.capture_screenshot(
    driver,
    name="homepage",
    wait_before_capture=2.0  # 2 second wait
)

# Or use explicit waits
from selenium.webdriver.support.ui import WebDriverWait

wait = WebDriverWait(driver, 10)
wait.until(lambda d: d.execute_script("return document.readyState") == "complete")
screenshot_mgr.capture_screenshot(driver, "homepage")
```

### 3. Handle Dynamic Content

```python
# Ignore dynamic regions
ignore_regions = [
    (0, 0, 1920, 100),  # Banner with rotating ads
]

result = comparator.compare_images(
    baseline, actual,
    ignore_regions=ignore_regions
)

# Or hide dynamic elements before capture
driver.execute_script("""
    document.querySelector('.ad-banner').style.display = 'none';
    document.querySelector('.timestamp').style.display = 'none';
""")
screenshot_mgr.capture_screenshot(driver, "homepage")
```

### 4. Appropriate Thresholds

```python
# Strict for static pages
strict_comparator = VisualComparator(threshold=0.1)

# Lenient for pages with animations/dynamic content
lenient_comparator = VisualComparator(threshold=2.0)

# Per-page thresholds
THRESHOLDS = {
    "homepage": 0.5,      # Some dynamic content
    "login": 0.1,         # Static page
    "dashboard": 2.0,     # Lots of dynamic widgets
}

threshold = THRESHOLDS.get(page_name, 0.1)
result = comparator.compare_with_tolerance(baseline, actual, tolerance=threshold)
```

### 5. CI/CD Integration

```python
# In conftest.py
def pytest_runtest_makereport(item, call):
    """Attach diff images to test reports."""
    if call.when == "call" and call.excinfo:
        # Test failed - attach diff image if exists
        test_name = item.name
        diff_path = f"screenshots/diff/{test_name}_diff.png"
        if Path(diff_path).exists():
            # Attach to HTML report
            extra = getattr(item, "extra", [])
            extra.append(pytest_html.extras.image(diff_path))
```

## Configuration

### pytest.ini

```ini
[pytest]
markers =
    visual: Visual regression tests
    visual_strict: Visual tests with strict thresholds

# Run visual tests separately
# pytest -m visual
```

### Environment-specific Baselines

```python
import os

env = os.getenv("TEST_ENV", "dev")

screenshot_mgr = ScreenshotManager(
    screenshots_dir=f"screenshots/{env}"
)
```

## Running Visual Tests

```bash
# Run all visual tests
pytest tests/visual/ -v

# Run with marker
pytest -m visual -v

# Update all baselines (USE WITH CAUTION)
pytest tests/visual/ --update-baselines

# Generate HTML report with diffs
pytest tests/visual/ --html=report.html --self-contained-html
```

## Troubleshooting

### False Positives

**Problem**: Tests fail due to minor rendering differences

**Solutions**:
1. Increase threshold
2. Enable `ignore_antialiasing=True`
3. Add ignore regions for dynamic content
4. Wait longer before capture

### Size Mismatches

**Problem**: "Image size mismatch" error

**Solutions**:
```python
# Set consistent viewport
driver.set_window_size(1920, 1080)

# Or capture at consistent window size
original_size = driver.get_window_size()
driver.set_window_size(1920, 1080)
screenshot_mgr.capture_screenshot(driver, "test")
driver.set_window_size(original_size["width"], original_size["height"])
```

### Font Rendering Differences

**Problem**: Different font rendering across environments

**Solutions**:
1. Use Docker for consistent environment
2. Increase threshold slightly
3. Use web-safe fonts in application

## Requirements

```bash
pip install Pillow  # Image processing
```

## Integration with Other Modules

### With Page Objects

```python
from pages.base_page import BasePage

class BasePageWithVisual(BasePage):
    def verify_visual(self, screenshot_manager, comparator, name=None):
        """Verify page visual consistency."""
        if name is None:
            name = self.__class__.__name__.lower()

        if not screenshot_manager.baseline_exists(name):
            screenshot_manager.create_baseline(self.driver, name)
            return True

        actual = screenshot_manager.capture_for_comparison(self.driver, name)
        baseline = screenshot_manager.get_baseline_path(name)
        result = comparator.compare_images(baseline, actual)

        return result.match
```

### With CI/CD

```yaml
# .github/workflows/visual-tests.yml
name: Visual Regression Tests

on: [push, pull_request]

jobs:
  visual-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Run visual tests
        run: pytest tests/visual/ -v

      - name: Upload diff images
        if: failure()
        uses: actions/upload-artifact@v2
        with:
          name: visual-diffs
          path: screenshots/diff/
```

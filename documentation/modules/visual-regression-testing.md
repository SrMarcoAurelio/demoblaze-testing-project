# Visual Regression Testing Module

## Overview

The Visual Regression Testing Module provides automated visual comparison testing to detect unintended UI changes. This module captures screenshots, compares them against baseline images, and identifies visual differences using pixel-perfect comparison algorithms.

## Table of Contents

- [Architecture](#architecture)
- [Features](#features)
- [Implementation Details](#implementation-details)
- [Usage](#usage)
- [Configuration](#configuration)
- [Maintenance](#maintenance)
- [Best Practices](#best-practices)

## Architecture

### Component Structure

```
tests/visual/
├── __init__.py
├── test_visual_login.py              # Login page visual tests
├── test_visual_catalog.py            # Catalog page visual tests
├── test_visual_product.py            # Product page visual tests
└── test_visual_responsive.py        # Responsive design tests

utils/visual/
├── __init__.py
├── screenshot_manager.py            # Screenshot capture and management
├── image_comparator.py              # Image comparison algorithms
└── visual_report_generator.py      # Visual diff reporting

results/visual/
├── baseline/                        # Baseline reference images
├── current/                         # Current test screenshots
└── diff/                            # Difference highlighting images
```

### Dependencies

- **Selenium WebDriver**: Browser automation for screenshots
- **Pillow (PIL)**: Image processing and manipulation
- **pixelmatch**: Pixel-level image comparison
- **pytest-html**: Visual test reporting

## Features

### Core Capabilities

1. **Automated Screenshot Capture**
   - Full page screenshots
   - Element-specific screenshots
   - Multiple viewport sizes
   - Cross-browser support

2. **Visual Comparison**
   - Pixel-perfect comparison
   - Fuzzy matching with tolerance
   - Ignore regions configuration
   - Anti-aliasing handling

3. **Baseline Management**
   - Automatic baseline creation
   - Baseline versioning
   - Selective baseline updates
   - Environment-specific baselines

4. **Difference Detection**
   - Pixel difference highlighting
   - Percentage difference calculation
   - Region-based analysis
   - Color-coded diff images

5. **Responsive Testing**
   - Multiple viewport sizes (mobile, tablet, desktop)
   - Orientation testing (portrait, landscape)
   - Device-specific testing

## Implementation Details

### Screenshot Manager (`utils/visual/screenshot_manager.py`)

```python
class ScreenshotManager:
    """
    Manages screenshot capture and storage.
    """

    def capture_full_page(self, driver: WebDriver, name: str) -> str:
        """
        Capture full page screenshot.

        Args:
            driver: Selenium WebDriver instance
            name: Screenshot name identifier

        Returns:
            Path to saved screenshot
        """

    def capture_element(self, driver: WebDriver, element: WebElement,
                       name: str) -> str:
        """
        Capture screenshot of specific element.

        Args:
            driver: Selenium WebDriver instance
            element: WebElement to capture
            name: Screenshot name identifier

        Returns:
            Path to saved screenshot
        """

    def capture_viewport(self, driver: WebDriver, name: str,
                        viewport_size: Tuple[int, int]) -> str:
        """
        Capture screenshot at specific viewport size.

        Args:
            driver: Selenium WebDriver
            name: Screenshot identifier
            viewport_size: (width, height) tuple

        Returns:
            Path to saved screenshot
        """
```

### Image Comparator (`utils/visual/image_comparator.py`)

```python
class ImageComparator:
    """
    Compares images and detects visual differences.
    """

    def compare_images(self, baseline_path: str, current_path: str,
                      threshold: float = 0.01) -> ComparisonResult:
        """
        Compare two images.

        Args:
            baseline_path: Path to baseline image
            current_path: Path to current image
            threshold: Acceptable difference threshold (0.0-1.0)

        Returns:
            ComparisonResult with match status and difference percentage
        """

    def generate_diff_image(self, baseline_path: str, current_path: str,
                           output_path: str) -> str:
        """
        Generate visual diff image highlighting differences.

        Args:
            baseline_path: Baseline image path
            current_path: Current image path
            output_path: Where to save diff image

        Returns:
            Path to generated diff image
        """

    def get_difference_percentage(self, baseline_path: str,
                                 current_path: str) -> float:
        """
        Calculate percentage difference between images.

        Args:
            baseline_path: Baseline image
            current_path: Current image

        Returns:
            Difference percentage (0.0-100.0)
        """
```

## Usage

### Running Visual Tests

**Run all visual tests:**
```bash
pytest -m visual -v
```

**Run specific visual tests:**
```bash
pytest tests/visual/test_visual_login.py -v
```

**Update baselines:**
```bash
pytest -m visual --update-baselines
```

**Generate visual report:**
```bash
pytest -m visual --html=results/visual_report.html
```

### Basic Visual Test Example

```python
import pytest
from utils.visual.screenshot_manager import ScreenshotManager
from utils.visual.image_comparator import ImageComparator

@pytest.mark.visual
class TestLoginPageVisual:
    """Visual regression tests for login page"""

    def test_login_page_layout_VIS_001(self, browser):
        """Test login page matches baseline"""
        # Navigate to login page
        browser.get("https://example.com/login")

        # Capture screenshot
        screenshot_mgr = ScreenshotManager()
        current_screenshot = screenshot_mgr.capture_full_page(
            browser,
            "login_page"
        )

        # Compare with baseline
        comparator = ImageComparator()
        result = comparator.compare_images(
            baseline_path="results/visual/baseline/login_page.png",
            current_path=current_screenshot,
            threshold=0.01  # 1% tolerance
        )

        # Assert images match
        assert result.matches, \
            f"Visual difference detected: {result.difference_percentage}%"

        # Generate diff if mismatch
        if not result.matches:
            comparator.generate_diff_image(
                baseline_path="results/visual/baseline/login_page.png",
                current_path=current_screenshot,
                output_path="results/visual/diff/login_page_diff.png"
            )
```

### Element-Specific Visual Testing

```python
def test_header_visual_VIS_002(browser):
    """Test header element visual consistency"""
    browser.get("https://example.com")

    # Find header element
    header = browser.find_element("css selector", "header")

    # Capture element screenshot
    screenshot_mgr = ScreenshotManager()
    current_screenshot = screenshot_mgr.capture_element(
        browser,
        header,
        "header_element"
    )

    # Compare with baseline
    comparator = ImageComparator()
    result = comparator.compare_images(
        baseline_path="results/visual/baseline/header_element.png",
        current_path=current_screenshot
    )

    assert result.matches
```

### Responsive Visual Testing

```python
@pytest.mark.visual
@pytest.mark.responsive
def test_responsive_layouts_VIS_003(browser):
    """Test responsive design across viewport sizes"""
    screenshot_mgr = ScreenshotManager()
    comparator = ImageComparator()

    # Test different viewport sizes
    viewports = {
        "mobile": (375, 667),      # iPhone
        "tablet": (768, 1024),     # iPad
        "desktop": (1920, 1080)    # Desktop
    }

    browser.get("https://example.com")

    for device_name, viewport_size in viewports.items():
        # Set viewport
        browser.set_window_size(*viewport_size)

        # Capture screenshot
        current_screenshot = screenshot_mgr.capture_viewport(
            browser,
            f"homepage_{device_name}",
            viewport_size
        )

        # Compare with baseline
        result = comparator.compare_images(
            baseline_path=f"results/visual/baseline/homepage_{device_name}.png",
            current_path=current_screenshot,
            threshold=0.02  # 2% tolerance for responsive
        )

        assert result.matches, \
            f"{device_name} layout mismatch: {result.difference_percentage}%"
```

## Configuration

### Visual Testing Configuration

Configure in `conftest.py`:

```python
VISUAL_CONFIG = {
    "baseline_dir": "results/visual/baseline/",
    "current_dir": "results/visual/current/",
    "diff_dir": "results/visual/diff/",
    "threshold": 0.01,  # 1% acceptable difference
    "ignore_antialiasing": True,
    "ignore_regions": [
        {"x": 0, "y": 0, "width": 100, "height": 50},  # Ignore header timestamp
    ],
    "viewports": {
        "mobile": (375, 667),
        "tablet": (768, 1024),
        "desktop": (1920, 1080)
    },
    "update_baselines": False  # Set to True to update baselines
}
```

### Pytest Markers

```ini
[pytest]
markers =
    visual: Visual regression tests
    responsive: Responsive design tests
    baseline: Tests that generate baseline images
```

### Ignore Regions Configuration

Ignore dynamic content areas:

```python
# Ignore regions with dynamic content
IGNORE_REGIONS = [
    {"name": "timestamp", "x": 10, "y": 10, "width": 200, "height": 30},
    {"name": "user_avatar", "x": 100, "y": 50, "width": 50, "height": 50},
    {"name": "ads", "x": 800, "y": 100, "width": 300, "height": 600},
]
```

## Maintenance

### Creating Baselines

**First-time baseline creation:**
```bash
# Run tests with --update-baselines flag
pytest -m visual --update-baselines -v
```

**Selective baseline updates:**
```python
# Update specific test baseline
pytest tests/visual/test_visual_login.py::test_login_page_layout_VIS_001 \
      --update-baselines
```

### Handling Dynamic Content

For pages with dynamic content (timestamps, user-specific data):

```python
def test_page_with_dynamic_content_VIS_004(browser):
    """Test page with dynamic content"""
    screenshot_mgr = ScreenshotManager()

    browser.get("https://example.com/dashboard")

    # Hide dynamic elements before screenshot
    browser.execute_script("""
        document.querySelector('.timestamp').style.visibility = 'hidden';
        document.querySelector('.user-avatar').style.visibility = 'hidden';
    """)

    current_screenshot = screenshot_mgr.capture_full_page(
        browser,
        "dashboard"
    )

    # Compare with baseline
    # ...
```

### Baseline Versioning

Organize baselines by version:

```
results/visual/baseline/
├── v1.0/
│   ├── login_page.png
│   └── homepage.png
├── v2.0/
│   ├── login_page.png
│   └── homepage.png
└── current -> v2.0/  # Symlink to current version
```

## Best Practices

### 1. Use Appropriate Thresholds

```python
# Strict threshold for critical UI
test_checkout_button(threshold=0.001)  # 0.1%

# Relaxed threshold for complex layouts
test_dashboard_layout(threshold=0.02)  # 2%
```

### 2. Ignore Known Dynamic Areas

```python
# Configure ignore regions
comparator = ImageComparator(
    ignore_regions=[
        {"x": 0, "y": 0, "width": 100, "height": 20}  # Header timestamp
    ]
)
```

### 3. Test Across Browsers

```python
@pytest.mark.visual
@pytest.mark.parametrize("browser_name", ["chrome", "firefox", "safari"])
def test_cross_browser_visual(browser_name):
    """Test visual consistency across browsers"""
    # Test implementation
```

### 4. Use Consistent Test Data

```python
# Use static test data for visual tests
TEST_USER = {
    "name": "Test User",
    "avatar": "static_avatar.png"
}
```

### 5. Wait for Page Stability

```python
def test_animated_page_VIS_005(browser):
    """Test page with animations"""
    browser.get("https://example.com")

    # Wait for animations to complete
    time.sleep(2)  # Wait for animations

    # Wait for fonts to load
    browser.execute_script("""
        return document.fonts.ready;
    """)

    # Capture screenshot
    # ...
```

## Common Issues and Solutions

### Issue: Font Rendering Differences

**Problem:** Different font rendering across environments.

**Solution:**
```python
# Use higher threshold for text-heavy pages
threshold = 0.05  # 5% tolerance

# Or use webfont loading
browser.execute_script("""
    WebFont.load({
        google: { families: ['Roboto'] }
    });
""")
```

### Issue: Anti-aliasing Differences

**Problem:** Pixel-level anti-aliasing varies.

**Solution:**
```python
comparator = ImageComparator(
    ignore_antialiasing=True,
    antialiasing_tolerance=2  # pixels
)
```

### Issue: Flaky Visual Tests

**Problem:** Tests pass/fail inconsistently.

**Solution:**
```python
# Increase stability
def capture_stable_screenshot(browser, name):
    """Capture screenshot with stability checks"""
    # Wait for page load
    WebDriverWait(browser, 10).until(
        lambda d: d.execute_script("return document.readyState") == "complete"
    )

    # Wait for images
    browser.execute_script("""
        return Array.from(document.images).every(img => img.complete);
    """)

    # Capture
    return screenshot_mgr.capture_full_page(browser, name)
```

## Performance Considerations

- **Screenshot capture**: ~500ms per full page screenshot
- **Image comparison**: ~100-500ms depending on image size
- **Storage**: ~50-200KB per screenshot (PNG format)

**Optimize performance:**
```python
# Use lower resolution for non-critical tests
browser.set_window_size(1280, 720)  # Instead of 1920x1080

# Compress screenshots
screenshot_mgr.capture_full_page(browser, "page", quality=85)
```

## Future Enhancements

1. **AI-powered visual testing** (ignore irrelevant changes)
2. **Video comparison** for animation testing
3. **Automatic baseline selection** based on Git branch
4. **Cloud-based baseline storage**
5. **Visual test analytics dashboard**

## References

- [Selenium Screenshot Documentation](https://www.selenium.dev/documentation/)
- [Pillow Documentation](https://pillow.readthedocs.io/)
- [Visual Regression Testing Best Practices](https://applitools.com/blog/visual-regression-testing/)

## Support

For visual testing issues:
- Review diff images in `results/visual/diff/`
- Check baseline images for correctness
- Verify viewport and browser settings

## License

Internal testing module - follows project license.

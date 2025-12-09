# Visual Testing Utilities

## Overview

Visual regression testing utilities for screenshot capture and image comparison.

## Files

- `screenshot_manager.py` - Screenshot capture and storage
- `image_comparator.py` - Pixel-level image comparison
- `visual_report_generator.py` - Visual diff reporting

## Key Classes

### ScreenshotManager

Manages screenshot capture and baseline storage.

**Methods:**
- `capture_full_page(driver, name)` - Full page screenshot
- `capture_element(driver, element, name)` - Element screenshot
- `capture_viewport(driver, name, viewport_size)` - Viewport-specific screenshot

### ImageComparator

Compares images and detects visual differences.

**Methods:**
- `compare_images(baseline_path, current_path, threshold)` - Compare two images
- `generate_diff_image(baseline_path, current_path, output_path)` - Create diff image
- `get_difference_percentage(baseline_path, current_path)` - Calculate difference

## Usage

```python
from utils.visual.screenshot_manager import ScreenshotManager
from utils.visual.image_comparator import ImageComparator

# Capture screenshot
mgr = ScreenshotManager()
current = mgr.capture_full_page(driver, "login_page")

# Compare with baseline
comparator = ImageComparator()
result = comparator.compare_images("baseline/login.png", current, threshold=0.01)

assert result.matches, f"Visual difference: {result.difference_percentage}%"
```

## Documentation

See [Visual Regression Module](../../documentation/modules/visual-regression-testing.md)

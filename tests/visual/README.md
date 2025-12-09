# Visual Regression Tests

## Overview

Automated visual comparison testing to detect unintended UI changes. Captures screenshots and compares against baselines.

## Test Coverage

- Login page visual tests
- Catalog page visual tests
- Product page visual tests
- Responsive design tests (mobile, tablet, desktop)

## Utilities

Uses `utils/visual/`:
- `screenshot_manager.py` - Capture and storage
- `image_comparator.py` - Pixel comparison
- `visual_report_generator.py` - Diff reporting

## Running Tests

```bash
pytest -m visual -v
pytest tests/visual/ -v

# Update baselines
pytest -m visual --update-baselines
```

## Baseline Management

Baselines stored in `results/visual/baseline/`

## Documentation

See [Visual Regression Module](../../documentation/modules/visual-regression-testing.md)

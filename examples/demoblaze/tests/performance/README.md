# Performance Tests

## Overview

Performance monitoring and Core Web Vitals validation. Tracks page load times and action durations.

## Test Coverage (20 tests)

- Page load performance
- Action duration metrics
- Core Web Vitals (LCP, FID, CLS)
- Performance regression detection

## Utilities

Uses `utils/performance/` and `utils/helpers/performance_monitor.py`

## Running Tests

```bash
pytest -m performance -v
pytest tests/performance/ -v
```

## Standards

- Google Core Web Vitals
- Web Performance Working Group (W3C)

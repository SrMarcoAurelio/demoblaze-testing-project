# Helper Utilities

## Overview

Common helper functions for waits, performance monitoring, and data validation.

## Files

- `wait_helpers.py` (203 lines) - Custom wait conditions
- `performance_monitor.py` - Real-time performance tracking
- `data_generator.py` - Test data generation
- `validators.py` - Input validation helpers

## Key Functions

### wait_helpers.py (18 tests)

Custom Selenium wait conditions:
- `wait_for_page_ready(driver, timeout)` - Full page load
- `wait_for_element_visible(driver, locator, timeout)` - Element visibility
- `wait_for_text_present(driver, locator, text, timeout)` - Text appearance

### performance_monitor.py

Real-time performance tracking:
- `start_monitoring()` - Begin tracking
- `get_metrics()` - Retrieve collected metrics
- `stop_monitoring()` - End tracking

## Usage

```python
from utils.helpers.wait_helpers import wait_for_page_ready
from utils.helpers.performance_monitor import PerformanceMonitor

wait_for_page_ready(driver, timeout=10)

monitor = PerformanceMonitor()
monitor.start_monitoring()
# Perform actions
metrics = monitor.get_metrics()
```

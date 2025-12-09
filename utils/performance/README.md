# Performance Utilities

## Overview

Performance testing utilities for Core Web Vitals monitoring and metrics collection.

## Features

- Core Web Vitals measurement (LCP, FID, CLS)
- Response time tracking
- Resource loading analysis
- Performance regression detection

## Usage

```python
from utils.performance import CoreWebVitalsMonitor

monitor = CoreWebVitalsMonitor(driver)
metrics = monitor.collect_metrics()

assert metrics['lcp'] < 2.5  # Good LCP
assert metrics['fid'] < 100  # Good FID
assert metrics['cls'] < 0.1  # Good CLS
```

## Standards

- Google Core Web Vitals
- Web Performance Working Group (W3C)

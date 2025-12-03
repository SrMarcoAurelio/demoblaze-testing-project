# Performance Metrics API Reference

Performance testing and metrics collection system.

**File:** `utils/performance/metrics.py`
**Version:** 1.0
**Author:** Marc Arévalo

## Overview

The Performance Metrics system provides tools for collecting, tracking, and reporting performance data during test execution.

**Components:**
- `PerformanceMetric` - Data class for individual metrics
- `PerformanceThreshold` - Data class for threshold definitions
- `PerformanceMetricsCollector` - Main collector class
- `get_collector()` - Singleton accessor function

---

## PerformanceMetric Class

Dataclass representing a single performance measurement.

**Definition:**
```python
@dataclass
class PerformanceMetric:
    name: str
    duration: float
    timestamp: str
    category: str = "general"
    metadata: Dict[str, Any] = field(default_factory=dict)
```

**Fields:**
- `name` (str): Metric identifier (e.g., "login", "page_load")
- `duration` (float): Duration in seconds
- `timestamp` (str): ISO format timestamp
- `category` (str): Category (e.g., "auth", "navigation")
- `metadata` (Dict): Additional data

**Methods:**
```python
def to_dict(self) -> Dict[str, Any]:
    """Convert metric to dictionary."""
```

**Example:**
```python
metric = PerformanceMetric(
    name="login",
    duration=2.35,
    category="auth",
    metadata={"browser": "chrome"}
)

print(metric.to_dict())
# {
#     'name': 'login',
#     'duration': 2.35,
#     'timestamp': '2025-12-03T14:30:15.123456',
#     'category': 'auth',
#     'metadata': {'browser': 'chrome'}
# }
```

---

## PerformanceThreshold Class

Dataclass representing a performance threshold.

**Definition:**
```python
@dataclass
class PerformanceThreshold:
    name: str
    max_duration: float
    category: str = "general"
    description: str = ""
```

**Fields:**
- `name` (str): Threshold identifier
- `max_duration` (float): Maximum allowed duration in seconds
- `category` (str): Category
- `description` (str): Human-readable description

**Methods:**

```python
def is_within_threshold(self, duration: float) -> bool:
    """Check if duration is within threshold."""
    return duration <= self.max_duration

def get_threshold_status(self, duration: float) -> str:
    """Get status string for duration vs threshold."""
    # Returns formatted status message
```

**Example:**
```python
threshold = PerformanceThreshold(
    name="login",
    max_duration=3.0,
    category="auth",
    description="Maximum time for login operation"
)

# Check duration
assert threshold.is_within_threshold(2.5) == True
assert threshold.is_within_threshold(3.5) == False

# Get status
status = threshold.get_threshold_status(2.5)
# "✓ PASS (2.500s <= 3.0s)"

status = threshold.get_threshold_status(4.0)
# "✗ FAIL (4.000s > 3.0s by 1.000s / 33.3%)"
```

---

## PerformanceMetricsCollector Class

Main class for collecting and managing performance metrics.

### Constructor

```python
def __init__(self) -> None:
```

**Internal State:**
- `metrics`: List of collected metrics
- `thresholds`: Dict of defined thresholds
- `_start_times`: Dict of active timers

**Default Thresholds:**
- page_load: 5.0s
- login: 3.0s
- add_to_cart: 2.0s
- checkout: 5.0s
- search: 2.0s
- api_response: 1.0s

---

### Timer Methods

#### start_timer(name)

Start a named timer.

**Signature:**
```python
def start_timer(self, name: str) -> None:
```

**Parameters:**
- `name` (str): Timer identifier

**Example:**
```python
collector.start_timer("login")
# ... perform login ...
duration = collector.stop_timer("login")
```

**Location:** metrics.py:110-114

---

#### stop_timer(name, category="general", metadata=None)

Stop a named timer and record metric.

**Signature:**
```python
def stop_timer(
    self,
    name: str,
    category: str = "general",
    metadata: Optional[Dict[str, Any]] = None,
) -> float:
```

**Parameters:**
- `name` (str): Timer identifier (must match start_timer call)
- `category` (str): Metric category. Default: "general"
- `metadata` (Optional[Dict]): Additional metadata

**Returns:**
- `float`: Duration in seconds

**Example:**
```python
collector.start_timer("page_load")
browser.get("https://example.com")
duration = collector.stop_timer(
    "page_load",
    category="navigation",
    metadata={"url": "https://example.com"}
)

print(f"Page loaded in {duration:.3f}s")
```

**Location:** metrics.py:115-144

---

#### record_metric(name, duration, category="general", metadata=None)

Record a metric directly without using timer.

**Signature:**
```python
def record_metric(
    self,
    name: str,
    duration: float,
    category: str = "general",
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
```

**Parameters:**
- `name` (str): Metric identifier
- `duration` (float): Duration in seconds
- `category` (str): Metric category
- `metadata` (Optional[Dict]): Additional metadata

**Example:**
```python
# Record pre-calculated duration
duration = 2.45
collector.record_metric(
    "api_call",
    duration,
    category="api",
    metadata={"endpoint": "/login"}
)
```

**Location:** metrics.py:145-161

---

### Threshold Methods

#### add_threshold(threshold)

Add or update a performance threshold.

**Signature:**
```python
def add_threshold(self, threshold: PerformanceThreshold) -> None:
```

**Parameters:**
- `threshold` (PerformanceThreshold): Threshold definition

**Example:**
```python
# Add custom threshold
threshold = PerformanceThreshold(
    name="checkout",
    max_duration=10.0,
    category="shopping",
    description="Maximum checkout time"
)

collector.add_threshold(threshold)
```

**Location:** metrics.py:162-168

---

#### check_threshold(name, duration)

Check if duration meets threshold.

**Signature:**
```python
def check_threshold(self, name: str, duration: float) -> bool:
```

**Parameters:**
- `name` (str): Threshold name
- `duration` (float): Duration to check

**Returns:**
- `bool`: True if within threshold or no threshold defined

**Internal Behavior:**
- Logs info if passed
- Logs warning if failed
- Returns True if no threshold defined

**Example:**
```python
duration = collector.stop_timer("login")

if collector.check_threshold("login", duration):
    print("✓ Login performance acceptable")
else:
    print("✗ Login too slow!")
    pytest.fail(f"Login exceeded threshold: {duration}s")
```

**Location:** metrics.py:207-228

---

#### get_threshold_violations()

Get all metrics that violate their thresholds.

**Signature:**
```python
def get_threshold_violations(self) -> List[Dict[str, Any]]:
```

**Returns:**
- `List[Dict]`: List of violation records

**Violation Record:**
```python
{
    'metric': {...},           # Metric dict
    'threshold': 3.0,          # Max duration
    'exceeded_by': 1.5,        # Amount over threshold
    'percentage_over': 50.0    # Percentage over threshold
}
```

**Example:**
```python
violations = collector.get_threshold_violations()

if violations:
    print(f"⚠ {len(violations)} performance violations:")
    for v in violations:
        metric = v['metric']
        print(f"  {metric['name']}: {metric['duration']:.3f}s > {v['threshold']}s")
```

**Location:** metrics.py:229-252

---

### Data Retrieval Methods

#### get_metrics_by_category(category)

Get all metrics for a specific category.

**Signature:**
```python
def get_metrics_by_category(
    self, category: str
) -> List[PerformanceMetric]:
```

**Parameters:**
- `category` (str): Category name

**Returns:**
- `List[PerformanceMetric]`: List of metrics in category

**Example:**
```python
auth_metrics = collector.get_metrics_by_category("auth")
print(f"Auth operations: {len(auth_metrics)}")
```

**Location:** metrics.py:169-174

---

#### get_metrics_by_name(name)

Get all metrics with a specific name.

**Signature:**
```python
def get_metrics_by_name(self, name: str) -> List[PerformanceMetric]:
```

**Parameters:**
- `name` (str): Metric name

**Returns:**
- `List[PerformanceMetric]`: List of metrics with that name

**Example:**
```python
# Get all login metrics from test suite
login_metrics = collector.get_metrics_by_name("login")

for metric in login_metrics:
    print(f"Login: {metric.duration:.3f}s")
```

**Location:** metrics.py:175-178

---

#### get_statistics(name)

Get statistics for a metric name.

**Signature:**
```python
def get_statistics(self, name: str) -> Dict[str, float]:
```

**Parameters:**
- `name` (str): Metric name

**Returns:**
- `Dict[str, float]`: Statistics dictionary

**Return Dictionary:**
```python
{
    'count': 10,           # Number of measurements
    'min': 1.2,            # Minimum duration
    'max': 3.5,            # Maximum duration
    'mean': 2.1,           # Average duration
    'median': 2.0,         # Median duration
    'stddev': 0.5          # Standard deviation (if count > 1)
}
```

**Example:**
```python
stats = collector.get_statistics("login")

print(f"Login statistics ({stats['count']} tests):")
print(f"  Min: {stats['min']:.3f}s")
print(f"  Max: {stats['max']:.3f}s")
print(f"  Mean: {stats['mean']:.3f}s")
print(f"  Median: {stats['median']:.3f}s")
print(f"  StdDev: {stats['stddev']:.3f}s")
```

**Location:** metrics.py:179-206

---

### Report Methods

#### generate_report()

Generate comprehensive performance report.

**Signature:**
```python
def generate_report(self) -> Dict[str, Any]:
```

**Returns:**
- `Dict[str, Any]`: Complete performance report

**Report Structure:**
```python
{
    'summary': {
        'total_metrics': 150,
        'categories': ['auth', 'navigation', 'shopping'],
        'thresholds_defined': 6,
        'violations': 5,
        'generated_at': '2025-12-03T14:30:15.123456'
    },
    'categories': {
        'auth': {
            'count': 50,
            'total_duration': 125.5,
            'avg_duration': 2.51
        },
        ...
    },
    'statistics': {
        'login': {...},
        'page_load': {...},
        ...
    },
    'violations': [...],
    'thresholds': {...}
}
```

**Example:**
```python
report = collector.generate_report()

print(f"Total metrics: {report['summary']['total_metrics']}")
print(f"Violations: {report['summary']['violations']}")

for category, data in report['categories'].items():
    print(f"{category}: {data['count']} metrics, avg {data['avg_duration']:.3f}s")
```

**Location:** metrics.py:253-297

---

#### save_report(filepath)

Save report to JSON file.

**Signature:**
```python
def save_report(self, filepath: str) -> None:
```

**Parameters:**
- `filepath` (str): Output file path (creates parent directories)

**Example:**
```python
collector.save_report("results/performance/report_20251203.json")
# Creates: results/performance/report_20251203.json
```

**Location:** metrics.py:298-308

---

### Utility Methods

#### clear_metrics()

Clear all collected metrics.

**Signature:**
```python
def clear_metrics(self) -> None:
```

**Example:**
```python
# Clear metrics before each test
collector.clear_metrics()
```

**Location:** metrics.py:309-314

---

#### `__len__()`

Return number of collected metrics.

**Signature:**
```python
def __len__(self) -> int:
```

**Example:**
```python
if len(collector) > 0:
    print(f"Collected {len(collector)} metrics")
```

**Location:** metrics.py:315-318

---

## Helper Functions

### get_collector()

Get or create global metrics collector singleton.

**Signature:**
```python
def get_collector() -> PerformanceMetricsCollector:
```

**Returns:**
- `PerformanceMetricsCollector`: Singleton instance

**Example:**
```python
from utils.performance.metrics import get_collector

collector = get_collector()
collector.start_timer("operation")
```

**Location:** metrics.py:324-330

---

### reset_collector()

Reset global collector (creates new instance).

**Signature:**
```python
def reset_collector() -> None:
```

**Example:**
```python
from utils.performance.metrics import reset_collector

# Reset collector (loses all data)
reset_collector()
```

**Location:** metrics.py:332-336

---

## Usage Examples

### Example 1: Basic Performance Test

```python
def test_login_performance(login_page, valid_user, performance_collector):
    # Start timer
    performance_collector.start_timer("login")

    # Perform operation
    login_page.login(**valid_user)

    # Stop timer and get duration
    duration = performance_collector.stop_timer("login", category="auth")

    # Check threshold
    assert performance_collector.check_threshold("login", duration)

    print(f"Login completed in {duration:.3f}s")
```

### Example 2: Multiple Metrics

```python
def test_full_checkout_flow(performance_collector):
    # Measure each step
    performance_collector.start_timer("page_load")
    browser.get(base_url)
    performance_collector.stop_timer("page_load", category="navigation")

    performance_collector.start_timer("login")
    login_page.login(**valid_user)
    performance_collector.stop_timer("login", category="auth")

    performance_collector.start_timer("add_to_cart")
    catalog_page.add_product_to_cart()
    performance_collector.stop_timer("add_to_cart", category="shopping")

    performance_collector.start_timer("checkout")
    cart_page.checkout()
    performance_collector.stop_timer("checkout", category="shopping")

    # Check all thresholds
    violations = performance_collector.get_threshold_violations()
    assert len(violations) == 0, f"Performance violations: {violations}"
```

### Example 3: Custom Thresholds

```python
def test_with_custom_threshold(performance_collector):
    # Add custom threshold
    custom_threshold = PerformanceThreshold(
        name="search",
        max_duration=1.5,
        category="search",
        description="Search should complete in 1.5s"
    )
    performance_collector.add_threshold(custom_threshold)

    # Measure
    performance_collector.start_timer("search")
    search_page.search("laptop")
    duration = performance_collector.stop_timer("search", category="search")

    # Check
    assert performance_collector.check_threshold("search", duration)
```

### Example 4: Statistics Analysis

```python
@pytest.mark.parametrize("iteration", range(10))
def test_login_performance_repeated(login_page, valid_user, performance_collector, iteration):
    """Run login 10 times and analyze statistics."""
    performance_collector.start_timer("login")
    login_page.login(**valid_user)
    performance_collector.stop_timer("login", category="auth")

def test_analyze_login_stats(performance_collector):
    """Analyze statistics from repeated tests."""
    stats = performance_collector.get_statistics("login")

    print(f"Login Statistics:")
    print(f"  Tests: {stats['count']}")
    print(f"  Min: {stats['min']:.3f}s")
    print(f"  Max: {stats['max']:.3f}s")
    print(f"  Mean: {stats['mean']:.3f}s")
    print(f"  Median: {stats['median']:.3f}s")

    # Assert mean is within acceptable range
    assert stats['mean'] < 3.0
```

---

## Best Practices

1. **Use meaningful metric names:**
```python
# Good
performance_collector.start_timer("checkout_complete_purchase")

# Avoid
performance_collector.start_timer("test1")
```

2. **Always use categories:**
```python
performance_collector.stop_timer(
    "login",
    category="auth"  # Helps organize metrics
)
```

3. **Add metadata for debugging:**
```python
performance_collector.stop_timer(
    "page_load",
    category="navigation",
    metadata={
        "url": browser.current_url,
        "browser": "chrome",
        "headless": True
    }
)
```

4. **Check thresholds in tests:**
```python
duration = performance_collector.stop_timer("operation")

if not performance_collector.check_threshold("operation", duration):
    pytest.fail(f"Operation exceeded threshold: {duration:.3f}s")
```

---

## Pytest Fixture Integration

The framework provides automatic integration via fixtures:

```python
def test_with_fixture(performance_collector):
    # Collector is automatically provided
    # Metrics are automatically cleared before test
    # Report is automatically saved after session

    performance_collector.start_timer("operation")
    # ...
```

**Automatic Report Generation:**
- Report saved to `results/performance/{timestamp}/performance_report.json`
- Generated automatically at end of test session
- Only if metrics were collected

---

## Related Documentation

- [Fixtures API](fixtures-api.md) - performance_collector fixture
- [Performance Testing Guide](../guides/performance-testing.md) - Full guide
- [Code Coverage Guide](../guides/code-coverage.md) - Related quality metrics

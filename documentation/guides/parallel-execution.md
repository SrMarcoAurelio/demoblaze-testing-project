# Parallel Test Execution Guide

**Master parallel testing with pytest-xdist for maximum speed**

---

## 📋 Overview

This guide covers parallel test execution using pytest-xdist, enabling you to run tests across multiple CPU cores simultaneously for dramatically faster test execution.

**Performance Impact:**
- 2 workers: **50% faster**
- 4 workers: **75% faster**
- 8 workers: **85% faster**
- auto workers: **Optimal for your machine**

**Example**: 100 tests × 3s each
- Sequential: 300 seconds (5 minutes)
- Parallel (4 cores): 75 seconds (1.25 minutes) ⚡

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [How It Works](#how-it-works)
3. [Configuration](#configuration)
4. [Test Isolation](#test-isolation)
5. [Distribution Strategies](#distribution-strategies)
6. [Best Practices](#best-practices)
7. [Troubleshooting](#troubleshooting)
8. [CI/CD Integration](#cicd-integration)
9. [Performance Tuning](#performance-tuning)

---

## Quick Start

### Installation

pytest-xdist is already included in `requirements.txt`:

```bash
pip install pytest-xdist  # Already installed if you ran: pip install -r requirements.txt
```

### Basic Usage

```bash
# Auto-detect CPU cores (recommended)
pytest -n auto

# Specific number of workers
pytest -n 4

# Disable parallel execution
pytest -n 0  # or just: pytest
```

**That's it!** Tests will run in parallel automatically.

---

## How It Works

### Architecture

```
Master Process (pytest)
    ├── Worker 1 (subprocess)
    │   ├── Test 1
    │   ├── Test 4
    │   └── Test 7
    ├── Worker 2 (subprocess)
    │   ├── Test 2
    │   ├── Test 5
    │   └── Test 8
    ├── Worker 3 (subprocess)
    │   ├── Test 3
    │   ├── Test 6
    │   └── Test 9
    └── Worker 4 (subprocess)
        └── ...
```

**Process:**
1. Master process discovers all tests
2. Spawns N worker subprocesses
3. Distributes tests to workers
4. Workers run tests in parallel
5. Master collects results and reports

### Test Distribution

By default, tests are distributed using **load balancing**:
- Worker finishes test → Master assigns next test
- Keeps all workers busy
- Balances execution time

---

## Configuration

### Command-Line Options

```bash
# Auto-detect optimal number of workers
pytest -n auto

# Specific number of workers
pytest -n 2   # 2 workers
pytest -n 4   # 4 workers
pytest -n 8   # 8 workers

# Distribution strategy
pytest -n auto --dist load        # Load balancing (default)
pytest -n auto --dist loadscope   # Load balancing by scope
pytest -n auto --dist loadfile    # Load balancing by file
pytest -n auto --dist loadgroup   # Load balancing by group
pytest -n auto --dist no          # No distribution (sequential)

# Maximum workers
pytest -n auto --maxworkers=8     # Cap at 8 workers

# Debug parallel execution
pytest -n 2 --dist-debug         # Show distribution details
```

### pytest.ini Configuration

```ini
[pytest]
# Enable parallel execution by default
addopts =
    -n auto
    --dist loadscope
    --maxworkers=8
```

**Framework Default**: Already configured in pytest.ini!

```ini
# pytest.ini
addopts =
    -n auto  # Parallel execution enabled by default
    # ... other options
```

### Disable Parallel for Specific Tests

```python
# Disable parallel for entire file
# At top of test file
pytestmark = pytest.mark.notparallel

# Or for specific test
@pytest.mark.notparallel
def test_requires_sequential_execution():
    pass
```

Or run sequentially:
```bash
pytest -n 0  # Disable parallel
```

---

## Test Isolation

### Critical Requirements

For parallel execution to work correctly, tests MUST be:

1. **Independent** - No test depends on another test running first
2. **Isolated** - Each test has its own resources (browser, data, files)
3. **Stateless** - No shared global state between tests

### ✅ Good: Isolated Tests

```python
def test_login_user1(browser):
    """Each test gets fresh browser - PARALLEL SAFE"""
    login_page = LoginPage(browser)
    login_page.login("user1", "pass1")
    assert login_page.is_logged_in()

def test_login_user2(browser):
    """Different browser instance - NO CONFLICT"""
    login_page = LoginPage(browser)
    login_page.login("user2", "pass2")
    assert login_page.is_logged_in()
```

### ❌ Bad: Shared State

```python
# Global state - BREAKS PARALLEL
logged_in_user = None

def test_login():
    global logged_in_user
    logged_in_user = do_login()  # ❌ Shared across workers!

def test_profile():
    assert logged_in_user is not None  # ❌ May be None from different worker!
```

### Ensuring Isolation

#### 1. Use Function-Scoped Fixtures

```python
# conftest.py

# ✅ GOOD - Each test gets fresh browser
@pytest.fixture(scope="function")
def browser():
    driver = webdriver.Chrome()
    yield driver
    driver.quit()

# ❌ BAD - Shared across tests in worker
@pytest.fixture(scope="session")
def browser_shared():
    driver = webdriver.Chrome()
    yield driver
    driver.quit()
```

#### 2. Unique Test Data

```python
# ✅ GOOD - Unique username per test
import uuid

def test_signup(signup_page):
    unique_username = f"user_{uuid.uuid4().hex[:8]}"
    signup_page.signup(unique_username, "password")
    assert signup_page.is_signup_successful()

# ❌ BAD - Same username causes conflicts
def test_signup_bad(signup_page):
    signup_page.signup("testuser", "password")  # ❌ Conflict with other workers!
```

#### 3. File/Database Isolation

```python
# ✅ GOOD - Worker-specific files
def test_download(browser, worker_id):
    download_dir = f"downloads/worker_{worker_id}"
    os.makedirs(download_dir, exist_ok=True)
    # Each worker has separate download directory

# ✅ GOOD - Transaction rollback for DB tests
@pytest.fixture
def db_transaction():
    connection = db.connect()
    transaction = connection.begin()
    yield connection
    transaction.rollback()  # Undo changes
    connection.close()
```

#### 4. Port Isolation

```python
# ❌ BAD - Hardcoded port causes conflicts
def test_start_server():
    server = start_server(port=8000)  # ❌ Port conflict!

# ✅ GOOD - Dynamic port assignment
def test_start_server(worker_id):
    # Each worker gets different port
    port = 8000 + int(worker_id.replace('gw', ''))
    server = start_server(port=port)
```

### Worker ID Fixture

pytest-xdist provides `worker_id` fixture:

```python
def test_with_worker_id(worker_id):
    """worker_id is: gw0, gw1, gw2, etc."""
    print(f"Running on worker: {worker_id}")

    # Use for isolation
    temp_file = f"temp_{worker_id}.txt"
    port = 8000 + int(worker_id.replace('gw', ''))
```

---

## Distribution Strategies

### 1. Load Distribution (Default)

**Strategy**: Distribute tests as workers become available

```bash
pytest -n auto --dist load
```

**Best For:**
- Tests with varying execution times
- General-purpose parallel execution
- Default choice

**How it works:**
- Master maintains queue of tests
- When worker finishes → assigns next test
- Balances execution time automatically

### 2. Load Scope

**Strategy**: Tests from same scope (module, class) go to same worker

```bash
pytest -n auto --dist loadscope
```

**Best For:**
- Tests with module or class-scoped fixtures
- Sharing expensive setup within module

**How it works:**
- Groups tests by scope (module/class)
- All tests in same module → same worker
- Fixture setup happens once per worker

**Example:**
```python
# All tests in this class run on same worker
class TestLogin:
    @pytest.fixture(scope="class")
    def shared_browser(self):
        driver = webdriver.Chrome()
        yield driver
        driver.quit()

    def test_1(self, shared_browser):
        pass

    def test_2(self, shared_browser):
        pass  # Uses same browser as test_1
```

### 3. Load File

**Strategy**: Tests from same file go to same worker

```bash
pytest -n auto --dist loadfile
```

**Best For:**
- File-level fixtures
- Tests that share file resources

### 4. Load Group

**Strategy**: Tests with same `@pytest.mark.xdist_group` go to same worker

```bash
pytest -n auto --dist loadgroup
```

**Best For:**
- Custom grouping logic
- Tests that must run together

**Example:**
```python
@pytest.mark.xdist_group("database_tests")
def test_db_1():
    pass

@pytest.mark.xdist_group("database_tests")
def test_db_2():
    pass  # Runs on same worker as test_db_1

@pytest.mark.xdist_group("api_tests")
def test_api_1():
    pass  # Runs on different worker
```

### 5. No Distribution

**Strategy**: Run tests sequentially

```bash
pytest -n auto --dist no
```

**Best For:**
- Debugging parallel issues
- Tests that can't be parallelized

---

## Best Practices

### 1. Start Small, Scale Up

```bash
# Start with 2 workers to verify isolation
pytest -n 2

# Increase gradually
pytest -n 4

# Then use auto
pytest -n auto
```

### 2. Use Appropriate Fixture Scopes

```python
# Function scope for isolation (parallel-safe)
@pytest.fixture(scope="function")
def browser():
    driver = webdriver.Chrome()
    yield driver
    driver.quit()

# Class scope for shared state within worker
@pytest.fixture(scope="class")
def expensive_resource():
    resource = setup_expensive_resource()
    yield resource
    resource.cleanup()

# Session scope only for truly read-only resources
@pytest.fixture(scope="session")
def config():
    return load_config()  # Read-only, safe to share
```

### 3. Generate Unique Test Data

```python
import uuid
from datetime import datetime

def test_create_user():
    # Unique per execution
    username = f"user_{uuid.uuid4().hex[:8]}"

    # Or timestamp-based
    username = f"user_{datetime.now().strftime('%Y%m%d%H%M%S%f')}"

    # Or use Faker
    from faker import Faker
    fake = Faker()
    username = fake.user_name()
```

### 4. Avoid Global State

```python
# ❌ BAD - Global state
test_results = []

def test_1():
    test_results.append("result1")  # ❌ Shared across workers!

# ✅ GOOD - Local state or fixtures
def test_1(test_results_collector):
    test_results_collector.append("result1")

@pytest.fixture
def test_results_collector():
    return []  # Fresh for each test
```

### 5. Clean Up Resources

```python
@pytest.fixture
def temp_file(worker_id):
    """Create temp file with worker isolation"""
    filename = f"temp_{worker_id}_{uuid.uuid4().hex[:8]}.txt"

    yield filename

    # Cleanup
    if os.path.exists(filename):
        os.remove(filename)
```

### 6. Use Retry for Flaky Tests

```python
# Combine parallel with retry
pytest -n auto --reruns 2

# Flaky tests get retried, speeding up overall suite
```

---

## Troubleshooting

### Issue 1: Tests Fail in Parallel but Pass Sequentially

**Cause:** Test isolation issues (shared state, race conditions)

**Debug:**
```bash
# Run sequentially to verify
pytest -n 0

# Run with 2 workers to isolate issue
pytest -n 2 -v

# Check for shared resources
grep -r "global " tests/
```

**Solution:** Fix isolation (see Test Isolation section)

### Issue 2: ResourceWarning (unclosed files/sockets)

**Cause:** Resources not cleaned up properly

**Solution:**
```python
# Use context managers
def test_file():
    with open("file.txt") as f:
        data = f.read()

# Or ensure cleanup in fixture
@pytest.fixture
def resource():
    r = create_resource()
    try:
        yield r
    finally:
        r.close()
```

### Issue 3: Slower with Parallel

**Possible Causes:**
1. CPU-bound tests (not I/O-bound)
2. Too many workers for available resources
3. Worker overhead > time savings

**Solutions:**
```bash
# Reduce workers
pytest -n 2  # Instead of -n auto

# Use loadscope for expensive fixtures
pytest -n auto --dist loadscope

# Check resource usage
top  # Monitor CPU/memory during test run
```

### Issue 4: Port Conflicts

**Error:** `Address already in use`

**Solution:**
```python
import socket

def get_free_port():
    """Get free port for test"""
    sock = socket.socket()
    sock.bind(('', 0))
    port = sock.getsockname()[1]
    sock.close()
    return port

def test_server(worker_id):
    port = get_free_port()
    server = start_server(port)
```

### Issue 5: Database Lock Errors

**Error:** `database is locked`

**Solution:**
```python
# Use separate test databases per worker
@pytest.fixture(scope="session")
def database(worker_id):
    db_name = f"test_db_{worker_id}.sqlite"
    db = create_database(db_name)
    yield db
    db.close()
    os.remove(db_name)
```

---

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/tests.yml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v3

    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'

    - name: Install dependencies
      run: pip install -r requirements.txt

    - name: Run tests in parallel
      run: |
        pytest -n auto --dist loadscope -v

    - name: Run with performance optimization
      run: |
        pytest -n auto --performance=fast --headless -v
```

### Docker

```yaml
# docker-compose.yml
services:
  tests:
    build: .
    command: pytest -n auto --dist loadscope
    environment:
      - BASE_URL=${BASE_URL}
      - TEST_USERNAME=${TEST_USERNAME}
      - TEST_PASSWORD=${TEST_PASSWORD}
```

### Jenkins

```groovy
// Jenkinsfile
stage('Test') {
    steps {
        sh 'pytest -n auto --dist loadscope --junitxml=results.xml'
    }
}
```

---

## Performance Tuning

### Optimal Worker Count

**Rule of Thumb:** Number of CPU cores

```python
import os

# Auto-detect
workers = os.cpu_count()

# Or cap it
workers = min(os.cpu_count(), 8)
```

**Testing:**
```bash
# Benchmark different worker counts
time pytest -n 1
time pytest -n 2
time pytest -n 4
time pytest -n 8
time pytest -n auto
```

### Distribution Strategy Selection

| Test Suite Characteristics | Best Strategy |
|---------------------------|--------------|
| Uniform test duration | `load` |
| Expensive module fixtures | `loadscope` |
| Fast tests (<1s each) | `loadfile` |
| Custom grouping needed | `loadgroup` |

### Combine with Performance Optimization

```bash
# Maximum speed: parallel + fast browser + headless
pytest -n auto --performance=fast --headless

# Example: 100 tests
# Sequential (basic): 300s (5 min)
# Parallel (4 workers): 75s (1.25 min)
# + Fast browser: 30s (30 sec)
# + Headless: 20s (20 sec)
# Total speedup: 15x faster! 🚀
```

### Memory Considerations

Each worker needs:
- Browser instance: ~200-500 MB
- Python runtime: ~50-100 MB
- Test data: varies

**Example:** 8 workers × 500 MB = 4 GB

**Adjust if low memory:**
```bash
# Reduce workers
pytest -n 4  # Instead of -n auto (8)

# Or use headless mode (less memory)
pytest -n auto --headless
```

---

## Quick Reference

### Common Commands

```bash
# Basic parallel execution
pytest -n auto

# Parallel with specific workers
pytest -n 4

# Parallel with distribution strategy
pytest -n auto --dist loadscope

# Parallel with performance optimization
pytest -n auto --performance=fast --headless

# Parallel with retry
pytest -n auto --reruns 2

# Disable parallel (debug)
pytest -n 0

# Parallel specific markers
pytest -n auto -m functional

# Parallel with HTML report
pytest -n auto --html=report.html
```

### Fixture Scopes for Parallel

| Scope | Sharing | Parallel Safe? | Use For |
|-------|---------|----------------|---------|
| `function` | None (fresh each test) | ✅ Yes | Browsers, test data |
| `class` | Within test class | ⚠️ With loadscope | Expensive resources |
| `module` | Within test file | ⚠️ With loadscope/loadfile | File-level setup |
| `session` | Across all workers | ❌ No (read-only only) | Config, constants |

### Troubleshooting Checklist

- [ ] Tests pass sequentially? (`pytest -n 0`)
- [ ] Using function-scoped fixtures?
- [ ] No global variables?
- [ ] Unique test data per test?
- [ ] Proper resource cleanup?
- [ ] No hardcoded ports/files?
- [ ] Database isolation?
- [ ] Enough memory for workers?

---

## Related Documentation

- [Performance Optimization Guide](performance-optimization.md)
- [Best Practices Guide](best-practices.md)
- [Test Fixtures Guide](test-fixtures.md)
- [CI/CD Advanced Guide](ci-cd-advanced.md)

---

**Last Updated**: December 24, 2025
**Framework Version**: 6.0
**pytest-xdist**: 3.5.0+

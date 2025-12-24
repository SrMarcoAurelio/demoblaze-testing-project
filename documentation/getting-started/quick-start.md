# Quick Start Guide

Get up and running in 5 minutes.

## Prerequisites

Ensure you've completed the [Installation Guide](installation.md).

## Step 1: Verify Setup

```bash
# Activate virtual environment
source venv/bin/activate  # Windows: venv\Scripts\activate

# Verify pytest
pytest --version
```

## Step 2: Run Your First Test

```bash
# Run a single test file
pytest tests/login/test_login_functional.py::test_successful_login -v

# Expected output:
# tests/login/test_login_functional.py::test_successful_login PASSED
```

## Step 3: Run Test Suite

```bash
# Run all login tests
pytest tests/login/ -v

# Run unit tests (fast)
pytest tests/test_utils/ -v

# Run with HTML report
pytest tests/login/ --html=report.html
```

## Step 4: View Test Results

Test results are saved in `/results` directory:

```
results/
├── general/           # HTML test reports
├── coverage/          # Code coverage reports
├── performance/       # Performance metrics
└── accessibility/     # Accessibility reports
```

## Common Test Commands

```bash
# Run tests by marker
pytest -m functional          # Functional tests only
pytest -m security           # Security tests only
pytest -m accessibility      # Accessibility tests only

# Run with coverage
pytest --cov=framework --cov=utils

# Parallel execution (faster)
pytest -n auto

# Stop on first failure
pytest -x

# Verbose output with live logs
pytest -v -s
```

## Understanding Test Output

### Successful Test
```
tests/login/test_login_functional.py::test_successful_login PASSED [100%]
```

### Failed Test
```
tests/login/test_login_functional.py::test_invalid_credentials FAILED [100%]
```

Failed tests show:
- Error message
- Stack trace
- Expected vs actual results
- Location of failure

## Next Steps

1. [Create Your First Test](first-test.md)
2. Review [Test Fixtures Guide](../guides/test-fixtures.md)
3. Explore [Implementation Guide](../guides/implementation-guide.md)

## Docker Quick Start

If using Docker:

```bash
# Build and run
docker-compose up --build

# Run specific tests
docker-compose run tests pytest tests/login/ -v

# View results
# Results are automatically saved to ./results/ on host machine
```

## Getting Help

- Review [Complete Guides](../guides/)
- Check existing tests in `/tests` for examples
- Open GitHub issue for support

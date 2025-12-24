# Configuration Examples

This directory contains example configurations for different environments and use cases.

## 📁 Files

### Environment Configurations

- **`.env.development`** - Development environment settings
  - Verbose logging, no headless, relaxed thresholds
  - Use for local development and debugging

- **`.env.staging`** - Staging environment settings
  - Headless mode, moderate logging, moderate thresholds
  - Use for pre-production testing

- **`.env.production`** - Production environment settings
  - Headless mode, minimal logging, strict thresholds
  - Use ONLY for smoke tests against production
  - ⚠️ READ-ONLY MODE - no destructive operations!

### Browser Optimizations

- **`browser_options.py`** - Optimized browser configurations
  - Multiple performance levels (basic, fast, ultra-fast)
  - Mobile emulation
  - Download configuration
  - Selenium Grid optimizations

## 🚀 Quick Start

### 1. Choose Your Environment

```bash
# For local development
cp config/examples/.env.development .env

# For staging tests
cp config/examples/.env.staging .env

# For production smoke tests (READ-ONLY!)
cp config/examples/.env.production .env
```

### 2. Customize the Configuration

Edit `.env` with YOUR application details:

```bash
# Update BASE_URL
BASE_URL=https://your-actual-application.com

# Update credentials (use test data!)
TEST_USERNAME=your_test_user
TEST_PASSWORD=your_test_password
```

### 3. Run Tests

```bash
# Tests will automatically use .env configuration
pytest tests/

# Override specific settings
BASE_URL=https://other-url.com pytest tests/
```

## 🎯 Browser Performance Optimization

### Using Optimized Browser Options

Copy functions from `browser_options.py` to your `conftest.py`:

```python
# conftest.py
from config.examples.browser_options import get_chrome_options_fast

@pytest.fixture(scope="function")
def browser():
    options = get_chrome_options_fast()  # 70-80% faster!
    driver = webdriver.Chrome(options=options)
    yield driver
    driver.quit()
```

### Performance Levels

| Level | Speed Gain | Use For | Trade-offs |
|-------|------------|---------|------------|
| **Basic** | Baseline | Local development, debugging | None |
| **Headless** | +33% | CI/CD, background testing | No visual debugging |
| **Fast** | +60% | Functional tests, non-visual | Images disabled |
| **Ultra** | +80% | Data extraction, API-driven | CSS disabled, eager loading |

### Example: Conditional Performance

```python
# conftest.py
import os
from config.examples.browser_options import (
    get_chrome_options_basic,
    get_chrome_options_fast,
    get_chrome_options_ultra_fast
)

@pytest.fixture(scope="function")
def browser(request):
    # Choose based on command-line option
    perf = request.config.getoption("--performance", "basic")

    if perf == "ultra":
        options = get_chrome_options_ultra_fast()
    elif perf == "fast":
        options = get_chrome_options_fast()
    else:
        options = get_chrome_options_basic()

    driver = webdriver.Chrome(options=options)
    yield driver
    driver.quit()
```

```bash
# Run with different performance levels
pytest --performance=basic   # Standard (for visual tests)
pytest --performance=fast    # 60% faster (most tests)
pytest --performance=ultra   # 80% faster (non-UI tests)
```

## 🌍 Multi-Environment Setup

### Approach 1: Multiple .env Files

Keep separate `.env` files for each environment:

```
.env.dev
.env.staging
.env.prod
```

Load with environment variable:

```bash
# In conftest.py
import os
from dotenv import load_dotenv

env = os.getenv("TEST_ENV", "dev")
load_dotenv(f".env.{env}")
```

```bash
# Run tests
TEST_ENV=dev pytest tests/
TEST_ENV=staging pytest tests/
TEST_ENV=prod pytest tests/
```

### Approach 2: Environment-Specific Directories

```
environments/
├── dev/
│   └── .env
├── staging/
│   └── .env
└── prod/
    └── .env
```

### Approach 3: CI/CD Secrets

Store sensitive values as CI/CD secrets:

```yaml
# .github/workflows/tests.yml
env:
  BASE_URL: ${{ secrets.STAGING_URL }}
  TEST_USERNAME: ${{ secrets.TEST_USER }}
  TEST_PASSWORD: ${{ secrets.TEST_PASSWORD }}
```

## 🔒 Security Best Practices

### ✅ DO

- Use environment variables for sensitive data
- Keep `.env` files in `.gitignore`
- Use different credentials per environment
- Rotate test credentials regularly
- Use read-only mode for production

### ❌ DON'T

- Commit `.env` files with real credentials
- Use production credentials for testing
- Run destructive tests against production
- Share credentials in code/comments
- Use personal accounts for testing

## 📊 Example Configurations

### Development - Fast Iteration

```bash
# .env
BASE_URL=http://localhost:3000
HEADLESS=false  # See browser for debugging
LOG_LEVEL=DEBUG
TIMEOUT_DEFAULT=5
PERF_PAGE_LOAD_THRESHOLD=10.0  # Relaxed for local
```

### CI/CD - Fast Execution

```bash
# .env
BASE_URL=https://staging.your-app.com
HEADLESS=true  # Headless for speed
LOG_LEVEL=INFO
TIMEOUT_DEFAULT=10
PERF_PAGE_LOAD_THRESHOLD=5.0  # Stricter
```

### Production Monitoring - Reliable

```bash
# .env
BASE_URL=https://www.your-app.com
HEADLESS=true
LOG_LEVEL=WARNING  # Minimal logs
TIMEOUT_DEFAULT=10
PERF_PAGE_LOAD_THRESHOLD=2.0  # Strict
READ_ONLY_MODE=true  # Safety first!
```

## 🛠️ Troubleshooting

### Issue: Tests can't find .env file

**Solution**: Ensure `.env` is in project root (not in `config/`)

```bash
# Correct location
test-automation-framework/
├── .env  # ✅ Here
├── config/
│   └── examples/
│       └── .env.development  # ❌ Not here
```

### Issue: Environment variables not loading

**Solution**: Install python-dotenv

```bash
pip install python-dotenv
```

```python
# In config.py or conftest.py
from dotenv import load_dotenv
load_dotenv()  # Load .env from project root
```

### Issue: Browser too slow

**Solution**: Use optimized browser options

```python
from config.examples.browser_options import get_chrome_options_fast
options = get_chrome_options_fast()  # 60-70% faster
```

### Issue: Tests fail with optimized options

**Solution**: Some tests may require images/CSS

```python
# Use basic options for visual tests
@pytest.mark.visual
def test_layout(browser):
    # Will use basic options (keep images/CSS)
    pass

# Use fast options for functional tests
@pytest.mark.functional
def test_login(browser):
    # Will use fast options (no images needed)
    pass
```

## 📚 Related Documentation

- [Performance Optimization Guide](../../documentation/guides/performance-optimization.md)
- [Best Practices Guide](../../documentation/guides/best-practices.md)
- [Implementation Guide](../../documentation/guides/implementation-guide.md)

---

**Remember**: These are EXAMPLES. Adapt them to YOUR application and team's needs!

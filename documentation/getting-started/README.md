# Getting Started

Quick start guides for new users of the framework.

## Prerequisites

- Python 3.11 or higher
- Git
- Chrome, Firefox, or Edge browser
- Basic knowledge of Python and Selenium
- Familiarity with pytest framework (recommended)

## Quick Start Steps

### 1. [Installation](installation.md)
Complete installation guide including:
- Cloning the repository
- Setting up virtual environment
- Installing dependencies
- Verifying installation

### 2. [Quick Start](quick-start.md)
Get up and running in 5 minutes:
- Basic configuration
- Running your first test
- Understanding test results
- Next steps

### 3. [Your First Test](first-test.md)
Create your first test from scratch:
- Understanding project structure
- Writing a simple test
- Using page objects
- Running and debugging

## Common Issues

**Import errors after installation:**
- Ensure virtual environment is activated
- Verify all dependencies installed: `pip list`
- Check Python version: `python --version`

**Browser driver issues:**
- Framework uses webdriver-manager for automatic driver management
- No manual driver installation required
- Ensure browser is up to date

**Test failures on first run:**
- Check BASE_URL in config/config.py
- Verify application is accessible
- Review test data in tests/test_data.py

## Next Steps

After completing the getting started guides:

1. Read the [Implementation Guide](../guides/implementation-guide.md) for comprehensive framework overview
2. Explore [Test Templates](../templates/) for creating new tests
3. Review [Architecture Documentation](../architecture/) to understand framework design

## Getting Help

- Check [Complete Guides](../guides/) for detailed documentation
- Review existing tests in `/tests` directory for examples
- Open an issue on GitHub for bugs or feature requests

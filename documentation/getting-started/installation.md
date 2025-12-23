# Installation Guide

## System Requirements

- Python 3.11 or higher
- Git 2.x or higher
- 4GB RAM minimum (8GB recommended)
- Modern browser (Chrome, Firefox, or Edge)

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/SrMarcoAurelio/test-automation-framework.git
cd test-automation-framework
```

### 2. Create Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Linux/Mac:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Verify Installation

```bash
# Check pytest installation
pytest --version

# Check Python packages
pip list | grep -E "selenium|pytest"

# Run unit tests to verify setup
pytest tests/test_utils/ -v
```

## Docker Installation (Optional)

For isolated execution environment:

```bash
# Build and run with Docker Compose
docker-compose up --build

# Run specific tests
docker-compose run tests pytest tests/login/ -v
```

## Configuration

### 1. Application URL

Edit `config/config.py`:

```python
BASE_URL: str = os.getenv('BASE_URL', 'https://your-application.com/')
```

### 2. Browser Settings

Default browser is Chrome. To change:

```python
BROWSER: str = os.getenv('BROWSER', 'firefox')  # or 'edge'
HEADLESS: bool = os.getenv('HEADLESS', 'false').lower() == 'true'
```

### 3. Pre-commit Hooks (Optional)

Install automated code quality checks:

```bash
pre-commit install
```

## Troubleshooting

### Virtual Environment Issues

**Problem:** Cannot activate virtual environment
**Solution:**
```bash
# Recreate virtual environment
rm -rf venv
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Dependency Conflicts

**Problem:** Package version conflicts
**Solution:**
```bash
# Upgrade pip
pip install --upgrade pip

# Install with exact versions
pip install -r requirements.txt --no-cache-dir
```

### Browser Driver Issues

**Problem:** WebDriver not found
**Solution:** Framework uses webdriver-manager for automatic driver management. Ensure browser is installed and up to date.

## Next Steps

- Continue to [Quick Start Guide](quick-start.md)
- Review [Project Structure](../../README.md#project-structure)
- Read [Implementation Guide](../guides/implementation-guide.md)

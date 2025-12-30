# Framework Feature Examples

This directory contains **example tests** that demonstrate framework capabilities. These are NOT tests of the framework itself, but rather examples showing how to use framework features.

## Purpose

These examples demonstrate:
- ✅ How to use framework utilities (API client, database, etc.)
- ✅ Patterns and best practices
- ✅ Real-world usage scenarios
- ✅ Integration with external systems

## What's Included

### `api/` - API Testing Examples
Demonstrates how to test REST APIs using the framework's `APIClient`:

- **test_api_example.py** - Complete API testing examples
  - GET/POST/PUT/PATCH/DELETE requests
  - Response validation (status, JSON, schema)
  - Authentication (Bearer tokens, headers)
  - Query parameters and filtering
  - Performance validation (response time)
  - Error handling (404, timeouts)

**Uses:** JSONPlaceholder (https://jsonplaceholder.typicode.com) as example API

**Run:** `pytest tests/examples/api/ -v`

### `database/` - Database Testing Examples
Demonstrates how to test database operations using framework utilities:

- **test_database_example.py** - Database testing patterns
  - INSERT/SELECT/UPDATE/DELETE operations
  - SQLite (no setup required)
  - MySQL and PostgreSQL (skipped, require servers)
  - Query validation
  - Foreign key relationships
  - Row existence and count validation

**Run:** `pytest tests/examples/database/ -v`

## These Are Examples, Not Tests

**Important Distinction:**

| Directory | Purpose | What's Tested |
|-----------|---------|---------------|
| `tests/examples/` | **Examples** | Shows HOW to use features |
| `tests/unit/` | **Framework tests** | Tests framework code itself |
| `tests/framework/` | **Framework tests** | Tests framework utilities |
| `tests/` (your tests) | **Application tests** | Tests YOUR application |

## How to Use These Examples

### 1. Learn From Them
Read the code to understand patterns:
```bash
# See how API testing works
cat tests/examples/api/test_api_example.py
```

### 2. Copy and Adapt
Use as starting point for your tests:
```bash
# Copy API example
cp tests/examples/api/test_api_example.py tests/test_my_api.py

# Edit to test YOUR API
# - Change base_url to your API
# - Update endpoints
# - Modify assertions for your data
```

### 3. Run to Verify Setup
Verify framework features work:
```bash
# Test API client works
pytest tests/examples/api/ -v --tb=short

# Test database utilities work
pytest tests/examples/database/ -v --tb=short
```

## Example Test Structure

### API Test Example
```python
import pytest
from utils.api.api_client import APIClient

@pytest.fixture
def api_client():
    """Create API client for YOUR API."""
    client = APIClient(base_url="https://your-api.com")
    yield client
    client.close()

@pytest.mark.api
def test_get_users(api_client):
    """Test GET /users endpoint."""
    response = api_client.get("/users")
    assert response.status_code == 200
```

### Database Test Example
```python
import pytest
from utils.database.query_executor import QueryExecutor

@pytest.mark.database
def test_user_exists(query_executor):
    """Verify test user exists in database."""
    user = query_executor.select_one("users", {"username": "testuser"})
    assert user is not None
    assert user["email"] == "test@example.com"
```

## When to Run These

### During Setup
Verify framework features work after installation:
```bash
pytest tests/examples/ -v
```

### When Learning
Understand how to use a feature:
```bash
# Learn API testing
pytest tests/examples/api/test_api_example.py::test_get_request -v -s
```

### As Reference
Check syntax when writing your own tests:
```bash
# See how authentication works
grep -A 10 "test_authentication" tests/examples/api/test_api_example.py
```

## What NOT to Do

❌ **Don't modify these examples** - They're reference material
❌ **Don't add app-specific tests here** - Use `tests/` root for your tests
❌ **Don't expect these to test YOUR app** - They test example APIs/DBs

## Adding Your Own Examples

If you create reusable patterns for your team:

```bash
# Create examples for your team
tests/examples/
├── api/                    # API examples (provided)
├── database/               # Database examples (provided)
└── custom/                 # Your team's custom examples
    ├── test_auth_pattern.py
    └── test_reporting_pattern.py
```

## Dependencies

Some examples require optional dependencies:

```bash
# API examples require core deps (always installed)
# Database examples with SQLite: No extra deps needed

# MySQL examples require:
pip install -r requirements-optional.txt  # Includes pymysql

# PostgreSQL examples require:
pip install -r requirements-optional.txt  # Includes psycopg2-binary
```

## Need Help?

- **API Testing Guide:** `documentation/guides/api-testing.md`
- **Database Testing Guide:** `documentation/guides/database-testing.md`
- **APIClient Reference:** `documentation/api-reference/`

---

**Remember:** These are demonstrations. Real application tests go in `tests/` root directory.

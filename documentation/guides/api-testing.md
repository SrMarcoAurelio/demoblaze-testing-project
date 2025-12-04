## API Testing Guide

Complete guide for testing REST APIs using the framework's API testing module.

## Overview

The API Testing Module provides professional tools for testing REST APIs:

- **APIClient** - HTTP client wrapper with authentication and session management
- **ResponseValidator** - Comprehensive response validation
- **SchemaValidator** - JSON Schema validation
- **Request/Response Logging** - Detailed logging for debugging

## Quick Start

### Basic API Test

```python
from utils.api.api_client import APIClient
from utils.api.response_validator import ResponseValidator

def test_get_user():
    # Create client
    with APIClient(base_url="https://api.example.com") as client:
        # Send request
        response = client.get("/users/1")

        # Validate response
        ResponseValidator.validate_status_code(response, 200)
        data = ResponseValidator.validate_json_response(response)

        # Validate fields
        ResponseValidator.validate_json_field(data, "id", expected_value=1)
        ResponseValidator.validate_json_field(data, "name")
```

## APIClient

### Initialization

```python
from utils.api.api_client import APIClient

# Basic client
client = APIClient(base_url="https://api.example.com")

# With custom configuration
client = APIClient(
    base_url="https://api.example.com",
    timeout=30,
    verify_ssl=True,
    default_headers={
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
)
```

### HTTP Methods

#### GET Request

```python
# Simple GET
response = client.get("/users")

# With query parameters
response = client.get("/users", params={"page": 1, "limit": 10})

# With custom headers
response = client.get("/users", headers={"X-Custom": "value"})
```

#### POST Request

```python
# JSON payload
payload = {"name": "John", "email": "john@example.com"}
response = client.post("/users", json=payload)

# Form data
data = {"username": "john", "password": "secret"}
response = client.post("/login", data=data)
```

#### PUT Request

```python
# Full update
payload = {"name": "John Updated", "email": "john@example.com"}
response = client.put("/users/1", json=payload)
```

#### PATCH Request

```python
# Partial update
payload = {"name": "John Updated"}
response = client.patch("/users/1", json=payload)
```

#### DELETE Request

```python
response = client.delete("/users/1")
```

### Authentication

#### Bearer Token

```python
# Set Bearer token
client.set_auth_token("your_token_here")

# Make authenticated requests
response = client.get("/protected/resource")

# Clear authentication
client.clear_auth()
```

#### Basic Authentication

```python
client.set_basic_auth("username", "password")
```

#### Custom Authentication Header

```python
client.set_header("X-API-Key", "your_api_key")
```

### Custom Headers

```python
# Set header
client.set_header("X-Request-ID", "12345")

# Remove header
client.remove_header("X-Request-ID")
```

### Session Management

```python
# Using context manager (recommended)
with APIClient(base_url="https://api.example.com") as client:
    response = client.get("/users")
    # Session automatically closed

# Manual management
client = APIClient(base_url="https://api.example.com")
try:
    response = client.get("/users")
finally:
    client.close()
```

## ResponseValidator

### Status Code Validation

```python
from utils.api.response_validator import ResponseValidator

# Single status code
ResponseValidator.validate_status_code(response, 200)

# Multiple acceptable codes
ResponseValidator.validate_status_code(response, [200, 201])
```

### JSON Validation

```python
# Validate response is valid JSON
data = ResponseValidator.validate_json_response(response)

# Validate field exists
ResponseValidator.validate_json_field(data, "id")

# Validate field value
ResponseValidator.validate_json_field(data, "status", expected_value="active")

# Validate nested field (dot notation)
ResponseValidator.validate_json_field(data, "user.profile.name")
```

### Field Type Validation

```python
# Validate field types
ResponseValidator.validate_json_field_type(data, "id", int)
ResponseValidator.validate_json_field_type(data, "name", str)
ResponseValidator.validate_json_field_type(data, "tags", list)
ResponseValidator.validate_json_field_type(data, "metadata", dict)
```

### Array Validation

```python
# Validate exact length
ResponseValidator.validate_json_array_length(data, "items", expected_length=10)

# Validate minimum length
ResponseValidator.validate_json_array_length(data, "items", min_length=1)

# Validate maximum length
ResponseValidator.validate_json_array_length(data, "items", max_length=100)

# Combined constraints
ResponseValidator.validate_json_array_length(
    data, "items",
    min_length=1,
    max_length=50
)
```

### Header Validation

```python
# Check header exists
ResponseValidator.validate_header_exists(response, "Content-Type")

# Validate header value
ResponseValidator.validate_header_value(
    response,
    "Content-Type",
    "application/json"
)

# Validate Content-Type
ResponseValidator.validate_content_type(response, "application/json")
```

### Response Time Validation

```python
# Response must be under 2 seconds
ResponseValidator.validate_response_time(response, max_time_ms=2000)
```

### Error Response Validation

```python
# Validate error status code
ResponseValidator.validate_error_response(response)

# Validate error message
ResponseValidator.validate_error_response(
    response,
    expected_error_message="User not found"
)
```

## SchemaValidator

### JSON Schema Validation

```python
from utils.api.schema_validator import SchemaValidator

# Define schema
schema = {
    "type": "object",
    "properties": {
        "id": {"type": "integer"},
        "name": {"type": "string"},
        "email": {"type": "string", "format": "email"}
    },
    "required": ["id", "name", "email"]
}

# Validate response
SchemaValidator.validate_schema(data, schema)
```

### Simple Schema Creation

```python
# Create simple schema
schema = SchemaValidator.create_simple_schema(
    required_fields=["id", "name", "email"],
    field_types={
        "id": "integer",
        "name": "string",
        "email": "string"
    }
)

SchemaValidator.validate_schema(data, schema)
```

### Array Schema

```python
# Define item schema
item_schema = SchemaValidator.create_simple_schema(
    required_fields=["id", "title"],
    field_types={"id": "integer", "title": "string"}
)

# Create array schema
array_schema = SchemaValidator.create_array_schema(item_schema)

# Validate array response
SchemaValidator.validate_schema(data, array_schema)
```

## Complete Examples

### Example 1: CRUD Operations

```python
import pytest
from utils.api.api_client import APIClient
from utils.api.response_validator import ResponseValidator

@pytest.fixture
def api_client():
    with APIClient(base_url="https://api.example.com") as client:
        client.set_auth_token("test_token")
        yield client

def test_create_user(api_client):
    # Create user
    payload = {"name": "John", "email": "john@example.com"}
    response = api_client.post("/users", json=payload)

    ResponseValidator.validate_status_code(response, 201)
    data = ResponseValidator.validate_json_response(response)

    user_id = data["id"]
    return user_id

def test_get_user(api_client):
    response = api_client.get(f"/users/1")

    ResponseValidator.validate_status_code(response, 200)
    data = ResponseValidator.validate_json_response(response)

    ResponseValidator.validate_json_field(data, "id")
    ResponseValidator.validate_json_field(data, "name")

def test_update_user(api_client):
    payload = {"name": "John Updated"}
    response = api_client.patch(f"/users/1", json=payload)

    ResponseValidator.validate_status_code(response, 200)
    data = ResponseValidator.validate_json_response(response)

    ResponseValidator.validate_json_field(data, "name", expected_value="John Updated")

def test_delete_user(api_client):
    response = api_client.delete(f"/users/1")
    ResponseValidator.validate_status_code(response, [200, 204])
```

### Example 2: Pagination

```python
def test_pagination(api_client):
    # Get first page
    response = api_client.get("/users", params={"page": 1, "per_page": 10})

    ResponseValidator.validate_status_code(response, 200)
    data = ResponseValidator.validate_json_response(response)

    # Validate pagination metadata
    ResponseValidator.validate_json_field(data, "page", expected_value=1)
    ResponseValidator.validate_json_field(data, "per_page", expected_value=10)
    ResponseValidator.validate_json_field(data, "total")

    # Validate items array
    ResponseValidator.validate_json_array_length(
        data, "items",
        max_length=10
    )
```

### Example 3: Search and Filtering

```python
def test_search_users(api_client):
    # Search users
    response = api_client.get("/users", params={
        "q": "john",
        "status": "active",
        "sort": "created_at",
        "order": "desc"
    })

    ResponseValidator.validate_status_code(response, 200)
    data = ResponseValidator.validate_json_response(response)

    # Validate all results match search
    items = data["items"]
    for item in items:
        assert "john" in item["name"].lower()
        assert item["status"] == "active"
```

### Example 4: Error Handling

```python
def test_unauthorized_access(api_client):
    # Clear authentication
    api_client.clear_auth()

    # Try to access protected resource
    response = api_client.get("/protected/resource")

    # Validate 401 Unauthorized
    ResponseValidator.validate_status_code(response, 401)
    ResponseValidator.validate_error_response(
        response,
        expected_error_message="Unauthorized"
    )

def test_not_found(api_client):
    response = api_client.get("/users/99999")

    ResponseValidator.validate_status_code(response, 404)
    ResponseValidator.validate_error_response(
        response,
        expected_error_message="User not found"
    )

def test_validation_error(api_client):
    # Invalid payload
    payload = {"email": "invalid_email"}  # Missing required fields
    response = api_client.post("/users", json=payload)

    ResponseValidator.validate_status_code(response, 400)
    ResponseValidator.validate_error_response(response)
```

## Best Practices

### 1. Use Fixtures for API Clients

```python
@pytest.fixture
def api_client():
    """Reusable API client fixture."""
    with APIClient(base_url="https://api.example.com") as client:
        client.set_auth_token("test_token")
        yield client
```

### 2. Validate Response Time for Performance

```python
def test_api_performance(api_client):
    response = api_client.get("/users")
    ResponseValidator.validate_response_time(response, max_time_ms=1000)
```

### 3. Use JSON Schema for Complex Validation

```python
def test_complex_response(api_client):
    response = api_client.get("/users/1")
    data = ResponseValidator.validate_json_response(response)

    schema = {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "profile": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "email": {"type": "string", "format": "email"}
                },
                "required": ["name", "email"]
            }
        },
        "required": ["id", "profile"]
    }

    SchemaValidator.validate_schema(data, schema)
```

### 4. Test Both Success and Error Cases

```python
def test_create_user_success(api_client):
    # Test successful creation
    payload = {"name": "John", "email": "john@example.com"}
    response = api_client.post("/users", json=payload)
    ResponseValidator.validate_status_code(response, 201)

def test_create_user_duplicate_email(api_client):
    # Test error case
    payload = {"name": "John", "email": "existing@example.com"}
    response = api_client.post("/users", json=payload)
    ResponseValidator.validate_status_code(response, 409)
```

### 5. Cleanup Test Data

```python
@pytest.fixture
def test_user(api_client):
    # Create test user
    payload = {"name": "Test User", "email": "test@example.com"}
    response = api_client.post("/users", json=payload)
    data = response.json()
    user_id = data["id"]

    yield user_id

    # Cleanup
    api_client.delete(f"/users/{user_id}")
```

## Running API Tests

```bash
# Run all API tests
pytest tests/api/ -v

# Run with markers
pytest -m api

# Run specific test file
pytest tests/api/test_api_example.py -v

# Run with detailed output
pytest tests/api/ -v --tb=short

# Run in parallel
pytest tests/api/ -n auto
```

## Troubleshooting

### SSL Certificate Errors

```python
# Disable SSL verification (not recommended for production)
client = APIClient(base_url="https://api.example.com", verify_ssl=False)
```

### Timeout Issues

```python
# Increase timeout
client = APIClient(base_url="https://api.example.com", timeout=60)
```

### Debug Logging

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Integration with CI/CD

```yaml
# .github/workflows/api-tests.yml
- name: Run API Tests
  run: pytest tests/api/ -v --html=reports/api-tests.html

- name: Upload API Test Report
  uses: actions/upload-artifact@v2
  with:
    name: api-test-report
    path: reports/api-tests.html
```

## Conclusion

The API Testing Module provides comprehensive tools for testing REST APIs with:
- Professional HTTP client
- Extensive validation capabilities
- JSON Schema support
- Authentication handling
- Performance testing

Use these tools to create robust, maintainable API tests that validate both functionality and performance.

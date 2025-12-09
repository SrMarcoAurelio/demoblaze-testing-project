# API Testing Module

## Overview

The API Testing Module provides comprehensive REST API testing capabilities with schema validation, response verification, and contract testing support. This module enables automated testing of backend services, microservices, and API endpoints with detailed validation and reporting.

## Table of Contents

- [Architecture](#architecture)
- [Features](#features)
- [Implementation Details](#implementation-details)
- [Usage](#usage)
- [Configuration](#configuration)
- [Test Coverage](#test-coverage)
- [Maintenance](#maintenance)
- [Best Practices](#best-practices)

## Architecture

### Component Structure

```
tests/api/
├── __init__.py
├── test_api_endpoints.py          # API endpoint tests
├── test_api_authentication.py     # Authentication flow tests
└── test_api_contracts.py          # Contract testing

utils/api/
├── __init__.py
├── api_client.py                  # HTTP client with retry logic
├── response_validator.py          # Response validation engine
└── schema_validator.py            # JSON schema validation
```

### Dependencies

- **requests**: HTTP library for API calls
- **jsonschema**: JSON Schema validation
- **pytest**: Test framework with API markers
- **responses**: HTTP response mocking for unit tests

## Features

### Core Capabilities

1. **REST API Testing**
   - GET, POST, PUT, PATCH, DELETE operations
   - Query parameters and headers
   - Request/response body validation
   - Status code verification

2. **Schema Validation**
   - JSON Schema Draft-07 support
   - Automatic schema generation
   - Schema versioning
   - Custom validation rules

3. **Response Validation**
   - Status code checking
   - Header validation
   - Response time monitoring
   - Content-type verification
   - Body structure validation

4. **Authentication Testing**
   - Basic authentication
   - Bearer token authentication
   - API key authentication
   - OAuth 2.0 flows

5. **Contract Testing**
   - Provider verification
   - Consumer-driven contracts
   - API versioning compatibility

## Implementation Details

### API Client (`utils/api/api_client.py`)

The API Client provides a robust HTTP client with automatic retries, timeout handling, and comprehensive logging.

**Key Methods:**

```python
class APIClient:
    def __init__(self, base_url: str, timeout: int = 30):
        """
        Initialize API client.

        Args:
            base_url: Base URL for API endpoints
            timeout: Request timeout in seconds (default: 30)
        """

    def get(self, endpoint: str, params: Dict = None, headers: Dict = None) -> Response:
        """
        Send GET request.

        Args:
            endpoint: API endpoint path
            params: Query parameters
            headers: Request headers

        Returns:
            Response object with status, headers, and body
        """

    def post(self, endpoint: str, data: Dict = None, json: Dict = None,
             headers: Dict = None) -> Response:
        """
        Send POST request.

        Args:
            endpoint: API endpoint path
            data: Form data
            json: JSON payload
            headers: Request headers

        Returns:
            Response object
        """

    def put(self, endpoint: str, data: Dict = None, json: Dict = None,
            headers: Dict = None) -> Response:
        """Send PUT request for updating resources."""

    def delete(self, endpoint: str, headers: Dict = None) -> Response:
        """Send DELETE request for removing resources."""
```

### Response Validator (`utils/api/response_validator.py`)

The Response Validator provides comprehensive response validation with detailed error reporting.

**Key Methods:**

```python
class ResponseValidator:
    def validate_status_code(self, response: Response, expected: int) -> bool:
        """
        Validate HTTP status code.

        Args:
            response: Response object
            expected: Expected status code

        Returns:
            True if status code matches

        Raises:
            ValidationError: If status code doesn't match
        """

    def validate_response_time(self, response: Response, max_time: float) -> bool:
        """
        Validate response time.

        Args:
            response: Response object
            max_time: Maximum acceptable response time in seconds

        Returns:
            True if response time is acceptable
        """

    def validate_headers(self, response: Response,
                        expected_headers: Dict[str, str]) -> bool:
        """
        Validate response headers.

        Args:
            response: Response object
            expected_headers: Dictionary of expected headers

        Returns:
            True if all headers match
        """

    def validate_json_body(self, response: Response, schema: Dict) -> bool:
        """
        Validate JSON response body against schema.

        Args:
            response: Response object
            schema: JSON Schema dictionary

        Returns:
            True if body matches schema
        """
```

### Schema Validator (`utils/api/schema_validator.py`)

The Schema Validator provides JSON Schema validation with support for custom formats and validators.

**Key Methods:**

```python
class SchemaValidator:
    def validate(self, data: Dict, schema: Dict) -> Tuple[bool, List[str]]:
        """
        Validate data against JSON schema.

        Args:
            data: Data to validate
            schema: JSON Schema

        Returns:
            Tuple of (is_valid, error_messages)
        """

    def generate_schema(self, sample_data: Dict) -> Dict:
        """
        Generate JSON schema from sample data.

        Args:
            sample_data: Sample JSON data

        Returns:
            Generated JSON Schema
        """
```

## Usage

### Running API Tests

**Run all API tests:**
```bash
pytest -m api -v
```

**Run specific API test file:**
```bash
pytest tests/api/test_api_endpoints.py -v
```

**Run with detailed output:**
```bash
pytest -m api -v --tb=long
```

### Basic API Testing Example

```python
import pytest
from utils.api.api_client import APIClient
from utils.api.response_validator import ResponseValidator

@pytest.mark.api
class TestProductAPI:
    """Test product API endpoints"""

    def test_get_products_API_001(self):
        """Test GET /api/products endpoint"""
        # Initialize client
        client = APIClient(base_url="https://api.example.com")
        validator = ResponseValidator()

        # Make request
        response = client.get("/api/products")

        # Validate response
        assert validator.validate_status_code(response, 200)
        assert validator.validate_response_time(response, max_time=2.0)

        # Validate body structure
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0

    def test_create_product_API_002(self):
        """Test POST /api/products endpoint"""
        client = APIClient(base_url="https://api.example.com")
        validator = ResponseValidator()

        # Prepare payload
        payload = {
            "name": "Test Product",
            "price": 99.99,
            "category": "Electronics"
        }

        # Make request
        response = client.post("/api/products", json=payload)

        # Validate response
        assert validator.validate_status_code(response, 201)

        # Validate created resource
        data = response.json()
        assert data["name"] == payload["name"]
        assert "id" in data
```

### Schema Validation Example

```python
from utils.api.schema_validator import SchemaValidator

def test_product_schema_API_003():
    """Test product response schema"""
    # Define schema
    product_schema = {
        "type": "object",
        "required": ["id", "name", "price"],
        "properties": {
            "id": {"type": "integer"},
            "name": {"type": "string", "minLength": 1},
            "price": {"type": "number", "minimum": 0},
            "category": {"type": "string"}
        }
    }

    # Get product data
    client = APIClient(base_url="https://api.example.com")
    response = client.get("/api/products/1")
    data = response.json()

    # Validate schema
    validator = SchemaValidator()
    is_valid, errors = validator.validate(data, product_schema)

    assert is_valid, f"Schema validation failed: {errors}"
```

### Authentication Testing Example

```python
def test_authenticated_endpoint_API_004():
    """Test endpoint with authentication"""
    client = APIClient(base_url="https://api.example.com")

    # Set authentication header
    headers = {
        "Authorization": "Bearer YOUR_API_TOKEN"
    }

    # Make authenticated request
    response = client.get("/api/user/profile", headers=headers)

    # Validate response
    assert response.status_code == 200
```

## Configuration

### API Client Configuration

Configure the API client in `conftest.py`:

```python
@pytest.fixture
def api_client():
    """Fixture for API client"""
    return APIClient(
        base_url=os.getenv("API_BASE_URL", "https://api.example.com"),
        timeout=30,
        retry_config={
            "max_retries": 3,
            "backoff_factor": 0.5,
            "status_forcelist": [500, 502, 503, 504]
        }
    )
```

### Environment Variables

```bash
# API Configuration
export API_BASE_URL="https://api.example.com"
export API_TIMEOUT=30
export API_KEY="your_api_key"

# Authentication
export AUTH_TOKEN="your_auth_token"
export OAUTH_CLIENT_ID="client_id"
export OAUTH_CLIENT_SECRET="client_secret"
```

### Pytest Markers

Markers defined in `pytest.ini`:

```ini
[pytest]
markers =
    api: API endpoint tests
    contract: Contract testing tests
    authentication: Authentication flow tests
    schema: Schema validation tests
```

## Test Coverage

### API Endpoints Tested

| Endpoint | Method | Tests | Coverage |
|----------|--------|-------|----------|
| /api/products | GET | 5 | 100% |
| /api/products | POST | 4 | 100% |
| /api/products/{id} | GET | 3 | 100% |
| /api/products/{id} | PUT | 3 | 100% |
| /api/products/{id} | DELETE | 2 | 100% |
| /api/auth/login | POST | 6 | 100% |
| /api/auth/logout | POST | 2 | 100% |

### Test Categories

- **Positive Tests**: Valid requests with expected responses
- **Negative Tests**: Invalid requests, error handling
- **Edge Cases**: Boundary values, special characters
- **Performance**: Response time validation
- **Security**: Authentication, authorization, input validation

## Maintenance

### Adding New API Tests

1. **Create test file** in `tests/api/`:

```python
# tests/api/test_new_endpoint.py

import pytest
from utils.api.api_client import APIClient
from utils.api.response_validator import ResponseValidator

@pytest.mark.api
class TestNewEndpoint:
    """Tests for new API endpoint"""

    def test_get_resource_API_NEW_001(self, api_client):
        """Test GET /api/resource"""
        response = api_client.get("/api/resource")
        assert response.status_code == 200
```

2. **Add schema** for the endpoint in `tests/api/schemas/`:

```python
# tests/api/schemas/resource_schema.py

RESOURCE_SCHEMA = {
    "type": "object",
    "required": ["id", "name"],
    "properties": {
        "id": {"type": "integer"},
        "name": {"type": "string"}
    }
}
```

3. **Run tests**:
```bash
pytest tests/api/test_new_endpoint.py -v
```

### Updating API Client

To add new HTTP methods or features:

1. Modify `utils/api/api_client.py`
2. Add corresponding tests in `tests/test_utils/test_api_client.py`
3. Update documentation
4. Run full test suite:
```bash
pytest -m api -v
```

### Handling API Changes

When API changes occur:

1. **Update schemas** in `tests/api/schemas/`
2. **Modify tests** to match new behavior
3. **Update validation logic** if needed
4. **Run regression tests**:
```bash
pytest -m api -v --tb=short
```

## Best Practices

### 1. Use Descriptive Test Names

```python
# Good
def test_get_products_returns_list_of_products_API_001():
    """Test that GET /api/products returns a list of product objects"""

# Bad
def test_api_1():
    """Test API"""
```

### 2. Validate Comprehensively

```python
def test_create_product_API_002(self, api_client):
    """Test product creation with full validation"""
    response = api_client.post("/api/products", json=payload)

    # Validate status
    assert response.status_code == 201

    # Validate headers
    assert response.headers["Content-Type"] == "application/json"

    # Validate body
    data = response.json()
    assert data["id"] is not None
    assert data["name"] == payload["name"]

    # Validate response time
    assert response.elapsed.total_seconds() < 2.0
```

### 3. Use Fixtures for Common Setup

```python
@pytest.fixture
def authenticated_client(api_client):
    """API client with authentication"""
    token = get_auth_token()
    api_client.set_header("Authorization", f"Bearer {token}")
    return api_client
```

### 4. Test Error Scenarios

```python
def test_create_product_with_invalid_data_API_003(self, api_client):
    """Test error handling for invalid product data"""
    invalid_payload = {"name": ""}  # Empty name

    response = api_client.post("/api/products", json=invalid_payload)

    # Expect 400 Bad Request
    assert response.status_code == 400

    # Validate error message
    error = response.json()
    assert "name" in error["errors"]
```

### 5. Mock External Dependencies

```python
import responses

@responses.activate
def test_external_api_call_API_004():
    """Test with mocked external API"""
    # Mock external API
    responses.add(
        responses.GET,
        "https://external-api.com/data",
        json={"result": "success"},
        status=200
    )

    # Test code that calls external API
    client = APIClient(base_url="https://external-api.com")
    response = client.get("/data")
    assert response.status_code == 200
```

## Common Issues and Solutions

### Issue: SSL Certificate Verification Errors

**Problem:** SSL certificate verification fails in development/test environments.

**Solution:**
```python
# Disable SSL verification for testing (NOT for production)
client = APIClient(base_url="https://api.example.com", verify_ssl=False)
```

### Issue: Flaky Tests Due to Network Issues

**Problem:** Tests fail intermittently due to network timeouts.

**Solution:**
```python
# Configure retries
client = APIClient(
    base_url="https://api.example.com",
    retry_config={
        "max_retries": 3,
        "backoff_factor": 1.0
    }
)
```

### Issue: Rate Limiting

**Problem:** API rate limits cause test failures.

**Solution:**
```python
import time

def test_with_rate_limiting(api_client):
    """Test with rate limit handling"""
    for i in range(10):
        response = api_client.get(f"/api/products/{i}")

        if response.status_code == 429:  # Too Many Requests
            retry_after = int(response.headers.get("Retry-After", 1))
            time.sleep(retry_after)
            response = api_client.get(f"/api/products/{i}")

        assert response.status_code == 200
```

## Performance Considerations

- **Response time benchmarks**: < 2 seconds for GET, < 3 seconds for POST
- **Parallel execution**: Supported with pytest-xdist
- **Connection pooling**: Enabled by default in APIClient
- **Request timeout**: Configurable (default: 30 seconds)

**Optimize test performance:**
```bash
pytest -m api -n auto --dist loadscope
```

## Security Considerations

1. **Never commit API keys or tokens** to version control
2. **Use environment variables** for sensitive data
3. **Validate all inputs** before sending to API
4. **Test authentication flows** thoroughly
5. **Check for sensitive data leakage** in responses

## Future Enhancements

1. **GraphQL API testing support**
2. **WebSocket testing**
3. **gRPC API testing**
4. **Automatic contract generation**
5. **Performance benchmarking integration**

## References

- [REST API Best Practices](https://restfulapi.net/)
- [JSON Schema Specification](https://json-schema.org/)
- [HTTP Status Codes](https://httpstatuses.com/)
- [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749)

## Support

For issues or questions:
- Review test failures in `results/api/`
- Check API documentation
- Consult backend development team

## License

Internal testing module - follows project license.

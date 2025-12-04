# Database Testing Guide

Complete guide for database testing with multi-database support.

## Overview

The Database Testing Module provides professional tools for testing databases:

- **DatabaseConnection** - Multi-database connection manager (MySQL, PostgreSQL, SQLite, SQL Server)
- **QueryExecutor** - High-level query execution with test helpers
- **QueryValidator** - Comprehensive result validation

## Quick Start

```python
from utils.database.connection_manager import DatabaseConfig, DatabaseConnection, DatabaseType
from utils.database.query_executor import QueryExecutor
from utils.database.query_validator import QueryValidator

# Create connection
config = DatabaseConfig(
    db_type=DatabaseType.SQLITE,
    db_file="test.db"
)

with DatabaseConnection(config) as conn:
    executor = QueryExecutor(conn)

    # Insert data
    executor.insert("users", {"id": 1, "name": "John"})

    # Query data
    user = executor.select_one("users", {"id": 1})

    # Validate
    QueryValidator.validate_field_value(user, "name", "John")
```

## Supported Databases

- MySQL/MariaDB
- PostgreSQL
- SQLite
- SQL Server

## DatabaseConnection

### MySQL Example

```python
config = DatabaseConfig(
    db_type=DatabaseType.MYSQL,
    host="localhost",
    port=3306,
    database="test_db",
    username="user",
    password="pass"
)

with DatabaseConnection(config) as conn:
    results = conn.execute_query("SELECT * FROM users")
```

### PostgreSQL Example

```python
config = DatabaseConfig(
    db_type=DatabaseType.POSTGRESQL,
    host="localhost",
    port=5432,
    database="test_db",
    username="user",
    password="pass"
)
```

### SQLite Example

```python
config = DatabaseConfig(
    db_type=DatabaseType.SQLITE,
    db_file="test.db"
)
```

## QueryExecutor

### Common Operations

```python
executor = QueryExecutor(connection)

# INSERT
executor.insert("users", {"id": 1, "name": "John", "email": "john@example.com"})

# SELECT
user = executor.select_one("users", {"id": 1})
all_users = executor.select_all("users")

# UPDATE
executor.update("users", {"email": "new@example.com"}, {"id": 1})

# DELETE
executor.delete("users", {"id": 1})

# COUNT
count = executor.count("users")
active_count = executor.count("users", {"status": "active"})

# EXISTS
exists = executor.exists("users", {"email": "john@example.com"})
```

## QueryValidator

### Validation Methods

```python
results = executor.select_all("users")

# Row existence
QueryValidator.validate_row_exists(results)
QueryValidator.validate_row_not_exists(results)

# Row count
QueryValidator.validate_row_count(results, 5)

# Field validation
user = results[0]
QueryValidator.validate_field_value(user, "name", "John")
QueryValidator.validate_field_not_null(user, "email")
QueryValidator.validate_field_type(user, "id", int)

# All rows match
QueryValidator.validate_all_rows_match(results, "status", "active")
```

## Complete Example

```python
import pytest
from utils.database.connection_manager import DatabaseConfig, DatabaseConnection, DatabaseType
from utils.database.query_executor import QueryExecutor
from utils.database.query_validator import QueryValidator

@pytest.fixture
def db_connection():
    config = DatabaseConfig(
        db_type=DatabaseType.SQLITE,
        db_file=":memory:"  # In-memory database
    )

    with DatabaseConnection(config) as conn:
        # Setup schema
        conn.execute_script("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                email TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        yield conn

def test_user_creation(db_connection):
    executor = QueryExecutor(db_connection)

    # Insert user
    executor.insert("users", {
        "id": 1,
        "username": "john_doe",
        "email": "john@example.com"
    })

    # Verify
    user = executor.select_one("users", {"id": 1})
    QueryValidator.validate_field_value(user, "username", "john_doe")
    QueryValidator.validate_field_not_null(user, "created_at")
```

## Best Practices

1. Use fixtures for database connections
2. Use in-memory SQLite for unit tests
3. Clean up test data after tests
4. Use transactions for test isolation
5. Validate data after operations

## Running Database Tests

```bash
pytest tests/database/ -v
pytest -m database
```

## Requirements

```bash
pip install pymysql  # MySQL
pip install psycopg2-binary  # PostgreSQL
pip install pyodbc  # SQL Server
# SQLite included with Python
```

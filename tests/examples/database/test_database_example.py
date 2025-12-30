"""
Database Testing Examples
Demonstrates database testing with QueryExecutor and validators.

Author: Marc Arévalo
Version: 1.0
"""

import pytest

from utils.database.connection_manager import (
    DatabaseConfig,
    DatabaseConnection,
    DatabaseType,
)
from utils.database.query_executor import QueryExecutor
from utils.database.query_validator import QueryValidator


@pytest.fixture
def sqlite_db(tmp_path):
    """Create SQLite database for testing."""
    db_file = tmp_path / "test.db"

    config = DatabaseConfig(db_type=DatabaseType.SQLITE, db_file=str(db_file))

    with DatabaseConnection(config) as conn:
        # Create test table
        conn.execute_script(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                email TEXT NOT NULL,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE orders (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                amount REAL,
                status TEXT DEFAULT 'pending',
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            """
        )

        yield conn


@pytest.fixture
def query_executor(sqlite_db):
    """Create query executor."""
    return QueryExecutor(sqlite_db)


@pytest.mark.database
@pytest.mark.smoke
def test_insert_and_select(query_executor):
    """TC-DB-001: Test INSERT and SELECT operations."""
    # Insert user
    affected = query_executor.insert(
        "users", {"id": 1, "username": "john_doe", "email": "john@example.com"}
    )

    assert affected == 1, "Insert should affect 1 row"

    # Select user
    user = query_executor.select_one("users", {"id": 1})

    assert user is not None
    assert user["username"] == "john_doe"
    assert user["email"] == "john@example.com"


@pytest.mark.database
def test_update_operation(query_executor):
    """TC-DB-002: Test UPDATE operation."""
    # Insert user
    query_executor.insert(
        "users", {"id": 1, "username": "john_doe", "email": "john@example.com"}
    )

    # Update user
    affected = query_executor.update(
        "users", {"email": "john.doe@example.com"}, {"id": 1}
    )

    assert affected == 1

    # Verify update
    user = query_executor.select_one("users", {"id": 1})
    assert user["email"] == "john.doe@example.com"


@pytest.mark.database
def test_delete_operation(query_executor):
    """TC-DB-003: Test DELETE operation."""
    # Insert user
    query_executor.insert(
        "users", {"id": 1, "username": "john_doe", "email": "john@example.com"}
    )

    # Delete user
    affected = query_executor.delete("users", {"id": 1})

    assert affected == 1

    # Verify deletion
    user = query_executor.select_one("users", {"id": 1})
    assert user is None


@pytest.mark.database
def test_count_operation(query_executor):
    """TC-DB-004: Test COUNT operation."""
    # Insert multiple users
    for i in range(5):
        query_executor.insert(
            "users",
            {
                "id": i + 1,
                "username": f"user{i}",
                "email": f"user{i}@example.com",
            },
        )

    # Count all users
    count = query_executor.count("users")
    assert count == 5

    # Count with condition
    count_active = query_executor.count("users", {"status": "active"})
    assert count_active == 5


@pytest.mark.database
def test_exists_operation(query_executor):
    """TC-DB-005: Test EXISTS check."""
    # User doesn't exist yet
    exists = query_executor.exists("users", {"username": "john_doe"})
    assert not exists

    # Insert user
    query_executor.insert(
        "users", {"id": 1, "username": "john_doe", "email": "john@example.com"}
    )

    # User now exists
    exists = query_executor.exists("users", {"username": "john_doe"})
    assert exists


@pytest.mark.database
def test_query_validator_row_exists(query_executor):
    """TC-DB-006: Test QueryValidator row existence."""
    # Insert user
    query_executor.insert(
        "users", {"id": 1, "username": "john_doe", "email": "john@example.com"}
    )

    # Query users
    results = query_executor.select_all("users")

    # Validate row exists
    QueryValidator.validate_row_exists(results)
    QueryValidator.validate_row_exists(results, {"username": "john_doe"})


@pytest.mark.database
def test_query_validator_row_count(query_executor):
    """TC-DB-007: Test QueryValidator row count."""
    # Insert users
    for i in range(3):
        query_executor.insert(
            "users",
            {
                "id": i + 1,
                "username": f"user{i}",
                "email": f"user{i}@example.com",
            },
        )

    results = query_executor.select_all("users")

    # Validate count
    QueryValidator.validate_row_count(results, 3)


@pytest.mark.database
def test_query_validator_field_value(query_executor):
    """TC-DB-008: Test QueryValidator field validation."""
    # Insert user
    query_executor.insert(
        "users",
        {
            "id": 1,
            "username": "john_doe",
            "email": "john@example.com",
            "status": "active",
        },
    )

    user = query_executor.select_one("users", {"id": 1})

    # Validate fields
    QueryValidator.validate_field_value(user, "username", "john_doe")
    QueryValidator.validate_field_value(user, "status", "active")
    QueryValidator.validate_field_not_null(user, "email")


@pytest.mark.database
def test_foreign_key_relationship(query_executor):
    """TC-DB-009: Test foreign key relationships."""
    # Insert user
    query_executor.insert(
        "users", {"id": 1, "username": "john_doe", "email": "john@example.com"}
    )

    # Insert orders for user
    query_executor.insert("orders", {"id": 1, "user_id": 1, "amount": 99.99})
    query_executor.insert("orders", {"id": 2, "user_id": 1, "amount": 149.99})

    # Query orders for user
    orders = query_executor.select_all("orders", {"user_id": 1})

    # Validate
    QueryValidator.validate_row_count(orders, 2)
    QueryValidator.validate_all_rows_match(orders, "user_id", 1)


@pytest.mark.database
def test_select_all_no_results(query_executor):
    """TC-DB-010: Test SELECT with no results."""
    results = query_executor.select_all("users", {"username": "nonexistent"})

    QueryValidator.validate_row_not_exists(results)


# Example with MySQL (requires actual MySQL server)
@pytest.mark.database
@pytest.mark.mysql
@pytest.mark.skip(reason="Requires MySQL server")
def test_mysql_connection():
    """TC-DB-011: Test MySQL connection."""
    config = DatabaseConfig(
        db_type=DatabaseType.MYSQL,
        host="localhost",
        port=3306,
        database="test_db",
        username="test_user",
        password="test_pass",
    )

    with DatabaseConnection(config) as conn:
        executor = QueryExecutor(conn)
        results = executor.execute_raw("SELECT VERSION()")
        assert len(results) > 0


# Example with PostgreSQL
@pytest.mark.database
@pytest.mark.postgresql
@pytest.mark.skip(reason="Requires PostgreSQL server")
def test_postgresql_connection():
    """TC-DB-012: Test PostgreSQL connection."""
    config = DatabaseConfig(
        db_type=DatabaseType.POSTGRESQL,
        host="localhost",
        port=5432,
        database="test_db",
        username="test_user",
        password="test_pass",
    )

    with DatabaseConnection(config) as conn:
        executor = QueryExecutor(conn)
        results = executor.execute_raw("SELECT version()")
        assert len(results) > 0

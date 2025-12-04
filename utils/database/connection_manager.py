"""
Database Connection Manager
Manages database connections with support for multiple database types.

Author: Marc Arévalo
Version: 1.0
"""

import logging
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class DatabaseType(Enum):
    """Supported database types."""

    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    SQLITE = "sqlite"
    SQLSERVER = "sqlserver"


@dataclass
class DatabaseConfig:
    """Database configuration."""

    db_type: DatabaseType
    host: Optional[str] = None
    port: Optional[int] = None
    database: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    # SQLite specific
    db_file: Optional[str] = None
    # Additional options
    charset: str = "utf8mb4"
    connect_timeout: int = 30


class DatabaseConnection:
    """
    Database connection wrapper with multi-database support.

    Supports:
    - MySQL/MariaDB
    - PostgreSQL
    - SQLite
    - SQL Server
    """

    def __init__(self, config: DatabaseConfig):
        """
        Initialize database connection.

        Args:
            config: Database configuration
        """
        self.config = config
        self.connection = None
        self._connect()

    def _connect(self) -> None:
        """Establish database connection."""
        try:
            if self.config.db_type == DatabaseType.MYSQL:
                self._connect_mysql()
            elif self.config.db_type == DatabaseType.POSTGRESQL:
                self._connect_postgresql()
            elif self.config.db_type == DatabaseType.SQLITE:
                self._connect_sqlite()
            elif self.config.db_type == DatabaseType.SQLSERVER:
                self._connect_sqlserver()
            else:
                raise ValueError(
                    f"Unsupported database type: {self.config.db_type}"
                )

            logger.info(f"Connected to {self.config.db_type.value} database")

        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            raise

    def _connect_mysql(self) -> None:
        """Connect to MySQL/MariaDB."""
        try:
            import pymysql

            self.connection = pymysql.connect(
                host=self.config.host,
                port=self.config.port or 3306,
                user=self.config.username,
                password=self.config.password,
                database=self.config.database,
                charset=self.config.charset,
                connect_timeout=self.config.connect_timeout,
                cursorclass=pymysql.cursors.DictCursor,
            )
        except ImportError:
            raise ImportError(
                "PyMySQL is required for MySQL. Install with: pip install pymysql"
            )

    def _connect_postgresql(self) -> None:
        """Connect to PostgreSQL."""
        try:
            import psycopg2
            import psycopg2.extras

            self.connection = psycopg2.connect(
                host=self.config.host,
                port=self.config.port or 5432,
                user=self.config.username,
                password=self.config.password,
                dbname=self.config.database,
                connect_timeout=self.config.connect_timeout,
            )
            # Use DictCursor for dict results
            self.connection.cursor_factory = psycopg2.extras.RealDictCursor
        except ImportError:
            raise ImportError(
                "psycopg2 is required for PostgreSQL. Install with: pip install psycopg2-binary"
            )

    def _connect_sqlite(self) -> None:
        """Connect to SQLite."""
        import sqlite3

        if not self.config.db_file:
            raise ValueError("db_file is required for SQLite")

        self.connection = sqlite3.connect(self.config.db_file)
        # Return rows as dictionaries
        self.connection.row_factory = sqlite3.Row

    def _connect_sqlserver(self) -> None:
        """Connect to SQL Server."""
        try:
            import pyodbc

            connection_string = (
                f"DRIVER={{ODBC Driver 17 for SQL Server}};"
                f"SERVER={self.config.host},{self.config.port or 1433};"
                f"DATABASE={self.config.database};"
                f"UID={self.config.username};"
                f"PWD={self.config.password};"
                f"Timeout={self.config.connect_timeout};"
            )

            self.connection = pyodbc.connect(connection_string)
        except ImportError:
            raise ImportError(
                "pyodbc is required for SQL Server. Install with: pip install pyodbc"
            )

    def execute_query(
        self, query: str, params: Optional[tuple] = None
    ) -> list:
        """
        Execute SELECT query and return results.

        Args:
            query: SQL query
            params: Query parameters (optional)

        Returns:
            List of result rows as dictionaries
        """
        if not self.connection:
            raise RuntimeError("Database connection not established")

        cursor = self.connection.cursor()

        try:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)

            # Fetch results
            results = cursor.fetchall()

            # Convert to list of dicts
            if self.config.db_type == DatabaseType.SQLITE:
                results = [dict(row) for row in results]
            elif self.config.db_type == DatabaseType.SQLSERVER:
                columns = [column[0] for column in cursor.description]
                results = [dict(zip(columns, row)) for row in results]

            logger.debug(f"Query executed: {query[:100]}...")
            logger.debug(f"Returned {len(results)} rows")

            return results

        except Exception as e:
            logger.error(f"Query execution failed: {e}")
            logger.error(f"Query: {query}")
            raise

        finally:
            cursor.close()

    def execute_update(
        self, query: str, params: Optional[tuple] = None
    ) -> int:
        """
        Execute INSERT/UPDATE/DELETE query.

        Args:
            query: SQL query
            params: Query parameters (optional)

        Returns:
            Number of affected rows
        """
        if not self.connection:
            raise RuntimeError("Database connection not established")

        cursor = self.connection.cursor()

        try:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)

            self.connection.commit()
            affected_rows = cursor.rowcount

            logger.debug(f"Update executed: {query[:100]}...")
            logger.debug(f"Affected {affected_rows} rows")

            return affected_rows

        except Exception as e:
            self.connection.rollback()
            logger.error(f"Update execution failed: {e}")
            logger.error(f"Query: {query}")
            raise

        finally:
            cursor.close()

    def execute_script(self, script: str) -> None:
        """
        Execute SQL script (multiple statements).

        Args:
            script: SQL script
        """
        if not self.connection:
            raise RuntimeError("Database connection not established")

        cursor = self.connection.cursor()

        try:
            if self.config.db_type == DatabaseType.SQLITE:
                cursor.executescript(script)
            else:
                # Split and execute statements
                statements = [
                    s.strip() for s in script.split(";") if s.strip()
                ]
                for statement in statements:
                    cursor.execute(statement)

            self.connection.commit()
            logger.debug(f"Script executed: {len(statements)} statements")

        except Exception as e:
            self.connection.rollback()
            logger.error(f"Script execution failed: {e}")
            raise

        finally:
            cursor.close()

    def close(self) -> None:
        """Close database connection."""
        if self.connection:
            self.connection.close()
            logger.info(f"Database connection closed")
            self.connection = None

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


class DatabaseConnectionManager:
    """
    Manages multiple database connections.

    Provides convenient access to different databases.
    """

    def __init__(self):
        """Initialize connection manager."""
        self.connections: Dict[str, DatabaseConnection] = {}

    def add_connection(
        self, name: str, config: DatabaseConfig
    ) -> DatabaseConnection:
        """
        Add database connection.

        Args:
            name: Connection name
            config: Database configuration

        Returns:
            Database connection
        """
        connection = DatabaseConnection(config)
        self.connections[name] = connection
        logger.info(f"Added database connection: {name}")
        return connection

    def get_connection(self, name: str) -> DatabaseConnection:
        """
        Get database connection by name.

        Args:
            name: Connection name

        Returns:
            Database connection

        Raises:
            KeyError: If connection doesn't exist
        """
        if name not in self.connections:
            raise KeyError(f"Database connection '{name}' not found")

        return self.connections[name]

    def close_all(self) -> None:
        """Close all database connections."""
        for name, connection in self.connections.items():
            connection.close()
            logger.info(f"Closed connection: {name}")

        self.connections.clear()

    @contextmanager
    def connection(self, name: str):
        """
        Context manager for database connection.

        Args:
            name: Connection name

        Yields:
            Database connection
        """
        conn = self.get_connection(name)
        try:
            yield conn
        finally:
            # Connection remains open for reuse
            pass

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close_all()

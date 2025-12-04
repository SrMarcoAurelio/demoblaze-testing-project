"""
Query Executor
High-level query execution with testing-focused helpers.

Author: Marc Arévalo
Version: 1.0
"""

import logging
from typing import Any, Dict, List, Optional

from .connection_manager import DatabaseConnection

logger = logging.getLogger(__name__)


class QueryExecutor:
    """
    High-level query executor with testing helpers.

    Provides convenient methods for common database operations in tests.
    """

    def __init__(self, connection: DatabaseConnection):
        """
        Initialize query executor.

        Args:
            connection: Database connection
        """
        self.connection = connection

    def select_one(
        self, table: str, where: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Select single row from table.

        Args:
            table: Table name
            where: WHERE conditions as dict

        Returns:
            Row as dictionary or None
        """
        where_clause = " AND ".join([f"{k} = %s" for k in where.keys()])
        query = f"SELECT * FROM {table} WHERE {where_clause} LIMIT 1"
        params = tuple(where.values())

        results = self.connection.execute_query(query, params)
        return results[0] if results else None

    def select_all(
        self, table: str, where: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Select all rows from table.

        Args:
            table: Table name
            where: WHERE conditions (optional)

        Returns:
            List of rows
        """
        if where:
            where_clause = " AND ".join([f"{k} = %s" for k in where.keys()])
            query = f"SELECT * FROM {table} WHERE {where_clause}"
            params = tuple(where.values())
            return self.connection.execute_query(query, params)
        else:
            query = f"SELECT * FROM {table}"
            return self.connection.execute_query(query)

    def count(self, table: str, where: Optional[Dict[str, Any]] = None) -> int:
        """
        Count rows in table.

        Args:
            table: Table name
            where: WHERE conditions (optional)

        Returns:
            Row count
        """
        if where:
            where_clause = " AND ".join([f"{k} = %s" for k in where.keys()])
            query = (
                f"SELECT COUNT(*) as count FROM {table} WHERE {where_clause}"
            )
            params = tuple(where.values())
            result = self.connection.execute_query(query, params)
        else:
            query = f"SELECT COUNT(*) as count FROM {table}"
            result = self.connection.execute_query(query)

        return result[0]["count"]

    def insert(self, table: str, data: Dict[str, Any]) -> int:
        """
        Insert row into table.

        Args:
            table: Table name
            data: Column-value pairs

        Returns:
            Number of affected rows
        """
        columns = ", ".join(data.keys())
        placeholders = ", ".join(["%s"] * len(data))
        query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
        params = tuple(data.values())

        return self.connection.execute_update(query, params)

    def update(
        self, table: str, data: Dict[str, Any], where: Dict[str, Any]
    ) -> int:
        """
        Update rows in table.

        Args:
            table: Table name
            data: Column-value pairs to update
            where: WHERE conditions

        Returns:
            Number of affected rows
        """
        set_clause = ", ".join([f"{k} = %s" for k in data.keys()])
        where_clause = " AND ".join([f"{k} = %s" for k in where.keys()])
        query = f"UPDATE {table} SET {set_clause} WHERE {where_clause}"
        params = tuple(list(data.values()) + list(where.values()))

        return self.connection.execute_update(query, params)

    def delete(self, table: str, where: Dict[str, Any]) -> int:
        """
        Delete rows from table.

        Args:
            table: Table name
            where: WHERE conditions

        Returns:
            Number of affected rows
        """
        where_clause = " AND ".join([f"{k} = %s" for k in where.keys()])
        query = f"DELETE FROM {table} WHERE {where_clause}"
        params = tuple(where.values())

        return self.connection.execute_update(query, params)

    def exists(self, table: str, where: Dict[str, Any]) -> bool:
        """
        Check if row exists in table.

        Args:
            table: Table name
            where: WHERE conditions

        Returns:
            True if exists
        """
        return self.count(table, where) > 0

    def truncate(self, table: str) -> None:
        """
        Truncate table (delete all rows).

        Args:
            table: Table name
        """
        query = f"TRUNCATE TABLE {table}"
        self.connection.execute_update(query)
        logger.info(f"Truncated table: {table}")

    def execute_raw(
        self, query: str, params: Optional[tuple] = None
    ) -> List[Dict]:
        """
        Execute raw SQL query.

        Args:
            query: SQL query
            params: Query parameters (optional)

        Returns:
            Query results
        """
        return self.connection.execute_query(query, params)

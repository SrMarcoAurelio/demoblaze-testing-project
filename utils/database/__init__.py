"""
Database Testing Module
Comprehensive database testing utilities with multi-database support.

Author: Marc Arévalo
Version: 1.0

Supports:
- MySQL/MariaDB
- PostgreSQL
- SQLite
- SQL Server
"""

from .connection_manager import DatabaseConnection, DatabaseConnectionManager
from .query_executor import QueryExecutor
from .query_validator import QueryValidator

__all__ = [
    "DatabaseConnection",
    "DatabaseConnectionManager",
    "QueryExecutor",
    "QueryValidator",
]
